"""Panel backup & restore.

A backup is a single .tar.gz of everything needed to bring the panel back exactly as it was:
the SQLite database (a *consistent* snapshot via the sqlite backup API, safe while the panel
is running), config.json, and the two encryption keys (secret_key + cred_key) — without those
keys a restored DB's stored SSH credentials couldn't be decrypted.

Backups live in data/backups/ (dir 0700, files 0600). They contain secrets, so every route
that touches them is superadmin-only, and names are strictly validated to prevent path
traversal. Restore is destructive, so it first takes an automatic pre-restore safety backup,
then swaps the files and restarts the panel from a detached unit that survives the restart.
"""
import base64
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import pathlib as _pathlib
import tarfile
import tempfile

# Imported for the restore's privileged step only. system_ops does not import
# backup, so this direction is safe.
from panel.ops.system_ops import _helper_present, _run_verb
import time

from panel.core.config import (DATA_DIR, DB_PATH, CONFIG_FILE, SECRET_FILE, CRED_KEY_FILE,
                    load_config, update_config, encrypt_secret, decrypt_secret)

_log = logging.getLogger("panel.backup")

BACKUP_DIR = DATA_DIR / "backups"
# panel-backup-<YYYYMMDD-HHMMSS>-<kind>.tar.gz — plus an optional .enc for an encrypted one.
_NAME_RE = re.compile(r"^panel-backup-\d{8}-\d{6}-[a-z]+\.tar\.gz(\.enc)?\Z")
_GLOB = "panel-backup-*.tar.gz*"
ENC_SUFFIX = ".enc"
_MEMBERS = ("panel.db", "config.json", "secret_key", "cred_key")

# ── Backup encryption ────────────────────────────────────────────────────────────────────────
# An unencrypted backup is a skeleton key: it holds panel.db AND secret_key AND cred_key, so one
# copied tarball undoes every encrypted column at once. On disk that is covered (0600 in a 0700
# dir, superadmin-only download, audit-logged), but a backup is the artefact most likely to leave
# the machine — cloud sync, a copy onto a laptop, an off-box rsync. Encrypting it means the file
# alone is worthless.
#
# Layout: b"LGSMBK1\n" | one-line JSON header (KDF params + salt) | b"\n" | Fernet token.
# The header is plaintext BY DESIGN — restore needs the salt before it can derive anything, and
# scrypt params must be readable so a future cost increase can still open today's archives.
_ENC_MAGIC = b"LGSMBK1\n"
# ~32MB, ~0.1s. A backup passphrase is typed rarely, so this can be far costlier than a login hash.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 15, 8, 1


def _derive_key(passphrase, salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P):
    """scrypt(passphrase) -> a urlsafe-b64 Fernet key. Memory-hard, so a stolen archive cannot be
    brute-forced at GPU speed the way a plain SHA-based KDF would allow."""
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    raw = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _is_readable_tar(path):
    """True if `path` opens as a gzip tar. Used to ASSERT the opposite of an encrypted archive —
    "it has a header" is not the same claim as "its contents are unreadable"."""
    try:
        with tarfile.open(str(path), "r:gz"):
            return True
    except Exception:
        return False


def is_encrypted_backup(name):
    return str(name or "").endswith(ENC_SUFFIX)


def _encrypt_archive(plain_path, dest_path, passphrase):
    """Encrypt the tar.gz at `plain_path` to `dest_path`. Whole-file, so the archive is held in
    memory once — fine for a panel DB (metrics are pruned; these run to single-digit MB)."""
    from cryptography.fernet import Fernet
    salt = os.urandom(16)
    key = _derive_key(passphrase, salt)
    with open(plain_path, "rb") as f:
        blob = f.read()
    header = json.dumps({"kdf": "scrypt", "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P,
                         "salt": base64.b64encode(salt).decode()},
                        separators=(",", ":"), sort_keys=True).encode("utf-8")
    with open(dest_path, "wb") as f:
        f.write(_ENC_MAGIC)
        f.write(header)
        f.write(b"\n")
        f.write(Fernet(key).encrypt(blob))
    os.chmod(dest_path, 0o600)


def _decrypt_archive(src_path, dest_path, passphrase):
    """Decrypt to `dest_path`. Returns (ok, message). A wrong passphrase is reported as such and
    never raises — Fernet authenticates, so a tampered archive fails here too rather than being
    unpacked over the live install."""
    from cryptography.fernet import Fernet, InvalidToken
    try:
        with open(src_path, "rb") as f:
            body = f.read()
    except OSError:
        return False, "Could not read the backup archive."
    if not body.startswith(_ENC_MAGIC):
        return False, "That file is not an encrypted panel backup."
    rest = body[len(_ENC_MAGIC):]
    nl = rest.find(b"\n")
    if nl < 0:
        return False, "The encrypted backup's header is damaged."
    try:
        head = json.loads(rest[:nl].decode("utf-8"))
        salt = base64.b64decode(head["salt"])
        n, r, p = int(head["n"]), int(head["r"]), int(head["p"])
    except Exception:
        return False, "The encrypted backup's header is damaged."
    # The header is part of the FILE, so these are only as trustworthy as the archive. Nothing can
    # upload one today — every archive here was written by this panel — but scrypt's `n` is a
    # memory parameter, and n=2**30 asks for a gigabyte before it fails. Bound them now, while the
    # only cost is three lines, rather than the day a "restore from a file you upload" feature
    # makes the header attacker-supplied.
    if not (2 ** 12 <= n <= 2 ** 20) or not (1 <= r <= 32) or not (1 <= p <= 16) or len(salt) > 64:
        return False, "The encrypted backup's header asks for parameters this panel will not use."
    if head.get("kdf") != "scrypt":
        return False, "This backup uses an encryption scheme this panel does not know."
    if not passphrase:
        return False, "This backup is encrypted — a passphrase is required."
    try:
        key = _derive_key(passphrase, salt, n=n, r=r, p=p)
        plain = Fernet(key).decrypt(rest[nl + 1:])
    except InvalidToken:
        # Fernet authenticates, so a wrong key and a modified archive raise the same thing and
        # genuinely cannot be told apart without the key. Say both rather than guess.
        return False, "Wrong passphrase, or the backup has been altered — it could not be opened."
    except Exception:
        _log.exception("backup decrypt failed")
        return False, "The backup could not be decrypted."
    try:
        with open(dest_path, "wb") as f:
            f.write(plain)
        os.chmod(dest_path, 0o600)
    except OSError:
        return False, "Could not write the decrypted archive."
    return True, ""


class PassphraseUnreadable(Exception):
    """A backup passphrase IS configured, but this host cannot decrypt it.

    Its own exception because the only safe response is to REFUSE: writing the archive would
    produce a plaintext copy of every secret the panel holds, named as though it were encrypted.
    """


def get_passphrase():
    """The configured backup passphrase, or "" when backups are unencrypted.

    Stored ENCRYPTED in config.json (under cred_key), which matters for the case this whole
    feature is about: config.json travels inside the archive, so a leaked archive would otherwise
    carry its own passphrase in the clear. It cannot be decrypted without cred_key, which lives
    only on the panel host."""
    try:
        stored = load_config().get("backup_passphrase") or ""
    except Exception:
        _log.debug("could not read the panel config", exc_info=True)
        raise PassphraseUnreadable("the panel config could not be read")
    if not stored:
        return ""                     # genuinely not configured: unencrypted backups are the ask
    value = decrypt_secret(stored)
    if not value:
        # Configured, and this host cannot decrypt it — a rotated, restored or replaced cred_key.
        # decrypt_secret answers "" for that, the same answer it gives for "nothing configured",
        # and create_backup read that as "backups are unencrypted": it wrote the archive in the
        # CLEAR, without the .enc suffix that would have shown it, on the daily schedule, with
        # nobody watching. The archive carries panel.db, config.json, secret_key AND cred_key —
        # so the failure hands over the whole key set. Proven by execution with a real Fernet
        # token encrypted under a different key: is_encrypted -> True, decrypt_secret -> "".
        raise PassphraseUnreadable(
            "a backup passphrase is configured but cannot be decrypted on this host")
    return value


MIN_PASSPHRASE_LEN = 12


def set_passphrase(passphrase):
    """Set (or clear, with "") the backup passphrase. Existing archives are NOT re-encrypted —
    they keep whatever they were written with, which is why restore accepts an explicit one.

    Raises ValueError below MIN_PASSPHRASE_LEN. The route checks this too and returns a friendly
    message, but the rule lives HERE as well: this is the only thing standing between a leaked
    archive and every secret in it, and a second caller — a manage.py subcommand, a setup step —
    would otherwise set a two-character passphrase with nothing objecting."""
    if passphrase and len(passphrase) < MIN_PASSPHRASE_LEN:
        raise ValueError("Backup passphrase must be at least %d characters." % MIN_PASSPHRASE_LEN)
    value = encrypt_secret(passphrase) if passphrase else ""

    def _mut(cfg):
        cfg["backup_passphrase"] = value

    update_config(_mut)
    return bool(passphrase)

DEFAULT_KEEP_DAYS = 14

# How many panel backups may be retained, in days. Named rather than inlined into the clamp because
# the UI now lets the number be TYPED rather than picked from a list, so the browser needs the same
# bound the server enforces — /api/panel/backups hands these out (see keep_limits).
MIN_KEEP_DAYS, MAX_KEEP_DAYS = 1, 365
# Game-server backups are whole game directories — gigabytes each — so the ceiling is far lower
# than the panel's own. This was already the effective maximum: it is what the clamp used, and the
# dropdown it replaces stopped at 30.
MIN_FULL_KEEP, MAX_FULL_KEEP = 1, 30
# The backup INTERVAL shares the panel bound; 0 means "off" so it has no floor of its own.
MAX_INTERVAL_DAYS = 365


def keep_limits():
    """The bounds the UI must not let a typed value exceed, so the number field and the clamp below
    cannot disagree. A dropdown could not be wrong; a text box can, so it is told."""
    return {"keep_days": {"min": MIN_KEEP_DAYS, "max": MAX_KEEP_DAYS},
            "full_keep": {"min": MIN_FULL_KEEP, "max": MAX_FULL_KEEP}}


def _ensure_dir():
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(BACKUP_DIR, 0o700)
    except OSError:
        _log.debug("could not chmod backups dir", exc_info=True)


def _safe_path(name):
    """Return the backup file named `name` from BACKUP_DIR, or None. The returned path is taken
    from the directory LISTING — never built from the request — and `name` must basename-match
    one of our strictly-named backups, so nothing outside data/backups can ever be reached."""
    name = os.path.basename(name or "")
    if not _NAME_RE.match(name):
        return None
    for p in BACKUP_DIR.glob(_GLOB):
        if p.name == name and p.is_file():
            return p
    return None


def _snapshot_db(dest):
    """Write a CONSISTENT copy of panel.db to `dest` using SQLite's online-backup API — safe
    even while the panel is mid-write (WAL), unlike a plain file copy."""
    if not os.path.exists(DB_PATH):
        return
    src = sqlite3.connect(str(DB_PATH))
    try:
        dst = sqlite3.connect(str(dest))
        try:
            with dst:
                src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def create_backup(kind="manual", encrypt=True):
    """Create a new backup archive. `kind` is a short lowercase tag (manual/daily/pre-restore).
    Returns (True, name) or (False, message).

    `encrypt=False` writes it in the clear even when a passphrase is configured, for the ONE
    caller that must be able to open the result afterwards: the pre-restore safety copy. Its
    passphrase comes from config.json decrypted under cred_key, and the very next step of a
    restore overwrites BOTH of those from the archive being restored — so an archive written
    under a different passphrase (one from before a set_passphrase, or carried from another
    install, which is the case restore's own docstring calls out) left the safety net locked by a
    key that no longer existed, at exactly the moment it was needed. It stays inside BACKUP_DIR,
    which is 0700, and the file itself is 0600."""
    kind = re.sub(r"[^a-z]", "", (kind or "manual").lower()) or "manual"
    _ensure_dir()
    try:
        passphrase = get_passphrase() if encrypt else ""
    except PassphraseUnreadable as exc:
        # Refuse. The alternative is a plaintext archive of panel.db, config.json, secret_key and
        # cred_key that looks like a successful encrypted backup.
        _log.error("backup refused: %s", exc)
        return False, ("Backup refused: a passphrase is configured but could not be decrypted on "
                       "this host, and writing the archive would leave it unencrypted. Check "
                       "data/cred_key, or clear the backup passphrase to take plain backups "
                       "deliberately.")
    name = "panel-backup-%s-%s.tar.gz" % (time.strftime("%Y%m%d-%H%M%S"), kind)
    if passphrase:
        name += ENC_SUFFIX
    dest = BACKUP_DIR / name
    tmp = tempfile.mkdtemp(prefix="lgsm-bk-")
    try:
        _snapshot_db(os.path.join(tmp, "panel.db"))
        for src, member in ((CONFIG_FILE, "config.json"), (SECRET_FILE, "secret_key"),
                            (CRED_KEY_FILE, "cred_key")):
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(tmp, member))
        # Built inside the temp dir when encrypting, so a plaintext archive never exists in
        # data/backups even briefly — a crash mid-encrypt must not leave an unencrypted skeleton
        # key sitting in the directory the user thinks is encrypted.
        staged = os.path.join(tmp, "archive.tar.gz") if passphrase else str(dest)
        with tarfile.open(staged, "w:gz") as tar:
            for member in _MEMBERS:
                fp = os.path.join(tmp, member)
                if os.path.exists(fp):
                    tar.add(fp, arcname=member)
        if passphrase:
            _encrypt_archive(staged, str(dest), passphrase)
        else:
            os.chmod(dest, 0o600)
        return True, name
    except Exception:
        _log.exception("backup creation failed")
        try:
            os.remove(dest)
        except OSError:
            _log.debug("could not remove partial backup", exc_info=True)
        return False, "Backup failed — see panel logs."
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def list_backups():
    """All backups, newest first: [{name, size, created(epoch), kind}]."""
    _ensure_dir()
    out = []
    for p in BACKUP_DIR.glob(_GLOB):
        if not _NAME_RE.match(p.name):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        enc = is_encrypted_backup(p.name)
        tail = p.name.rsplit("-", 1)[-1]
        kind = tail[:-len(".tar.gz" + (ENC_SUFFIX if enc else ""))]
        out.append({"name": p.name, "size": st.st_size, "created": int(st.st_mtime),
                    "kind": kind, "encrypted": enc})
    out.sort(key=lambda b: b["created"], reverse=True)
    return out


def delete_backup(name):
    p = _safe_path(name)
    if not p:
        return False, "No such backup."
    try:
        p.unlink()
        return True, "Backup deleted."
    except OSError:
        _log.exception("backup delete failed")
        return False, "Could not delete the backup."


def prune_backups(keep_days=None):
    """Remove daily backups older than keep_days (manual/pre-restore backups are kept — the
    user made those deliberately). Returns the number removed."""
    if keep_days is None:
        try:
            keep_days = int(load_config().get("backup_keep_days", DEFAULT_KEEP_DAYS))
        except (TypeError, ValueError):
            keep_days = DEFAULT_KEEP_DAYS
    cutoff = time.time() - max(1, keep_days) * 86400
    removed = 0
    for b in list_backups():
        if b["kind"] == "daily" and b["created"] < cutoff:
            ok, _ = delete_backup(b["name"])
            removed += 1 if ok else 0
    return removed


def daily_backup_tick():
    """Called periodically by the panel's background thread: if daily backups are enabled and
    the newest daily one is >~24h old (or none exists), make one and prune old dailies. Cheap
    no-op otherwise. Returns True if a backup was taken."""
    cfg = load_config()
    if not cfg.get("backup_enabled", True):
        return False
    dailies = [b for b in list_backups() if b["kind"] == "daily"]
    newest = dailies[0]["created"] if dailies else 0
    if time.time() - newest < 23 * 3600:      # ~daily, with slack so a slightly-early tick is fine
        return False
    ok, _ = create_backup("daily")
    if ok:
        prune_backups()
    return ok


def _service_restart_launcher(script_path):
    """systemd-run argv that runs `script_path` DETACHED (survives the panel stop/restart the
    script performs). Mirrors system_ops' service-model detection: per-user vs system unit."""
    user_unit = os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")
    system_unit = "/etc/systemd/system/linuxgsm-panel.service"
    if os.path.exists(user_unit) or not os.path.exists(system_unit):
        return ["systemd-run", "--user", "--collect", "/bin/bash", script_path]
    return ["sudo", "systemd-run", "--collect", "/bin/bash", script_path]


def restore_backup(name, passphrase=None, skip_safety_backup=False):
    """Restore a backup: take an automatic pre-restore safety backup, then swap the DB/config/
    keys into place and restart the panel — all from a DETACHED unit so it survives the panel
    stopping. Destructive; returns (ok, message). The panel goes down for a few seconds.

    `passphrase` is for an encrypted archive; when omitted the configured one is used. Restoring
    onto a FRESH install is the case that needs it passed explicitly — that panel has no
    config.json yet, and the passphrase it would need is inside the archive it cannot open.

    `skip_safety_backup` is the operator's answer to "the safety copy could not be written, go
    ahead anyway" — see _restore_validated. It is not a default because the thing being
    overwritten includes cred_key, without which every stored SSH credential is unreadable."""
    src = _safe_path(name)
    if not src:
        return False, "No such backup."

    # Decrypt FIRST, into a temp file, and only then validate. Nothing about the live install is
    # touched — not even the pre-restore safety backup — until the archive has been opened and
    # checked, so a wrong passphrase or a tampered file costs nothing.
    _dec_tmp = None
    if is_encrypted_backup(src.name):
        _dec_tmp = tempfile.mkdtemp(prefix="lgsm-bk-dec-")
        plain = os.path.join(_dec_tmp, "archive.tar.gz")
        try:
            # An operator-supplied passphrase wins; only fall back to the stored one. If THAT is
            # unreadable, say so plainly — the alternative is an "incorrect passphrase" error that
            # sends someone hunting for a typo when the real problem is cred_key.
            _pp = passphrase if passphrase else get_passphrase()
        except PassphraseUnreadable as exc:
            shutil.rmtree(_dec_tmp, ignore_errors=True)
            return False, ("Cannot decrypt this backup: %s. Enter the passphrase explicitly, or "
                           "restore data/cred_key first." % exc)
        ok, msg = _decrypt_archive(str(src), plain, _pp)
        if not ok:
            shutil.rmtree(_dec_tmp, ignore_errors=True)
            return False, msg
        src = _pathlib.Path(plain)

    try:
        # Validate the archive up front (members only, no path escapes) before we touch anything.
        try:
            with tarfile.open(src, "r:gz") as tar:
                names = tar.getnames()
            if not names or any(n not in _MEMBERS for n in names):
                return False, "Backup archive looks invalid."
        except Exception:
            _log.exception("backup archive unreadable")
            return False, "Could not read the backup archive."

        # The ORIGINAL name, not src: for an encrypted archive src is now a temp file, and the
        # user-facing message must still say which backup they restored.
        return _restore_validated(src, os.path.basename(str(name)),
                                  skip_safety_backup=skip_safety_backup)
    finally:
        if _dec_tmp:
            shutil.rmtree(_dec_tmp, ignore_errors=True)


def _restore_validated(src, name, skip_safety_backup=False):
    """The destructive half, on an archive already decrypted and checked. `name` is only for the
    message shown to the user — `src` is what actually gets unpacked."""
    # The safety net, and its result is CHECKED. create_backup swallows every exception and
    # answers (False, "Backup failed — see panel logs.") — a full disk, a BACKUP_DIR whose mode
    # changed, a _snapshot_db failure on a database that is already damaged. Both results were
    # discarded, so execution fell straight through to the destructive verb and the UI still said
    # "the panel will restart in a few seconds" while there was no recovery point at all. Losing
    # cred_key that way means every stored SSH credential is undecryptable.
    #
    # Written UNENCRYPTED (see create_backup): the passphrase this one would use is about to be
    # overwritten by the archive being restored.
    safety = ""
    if not skip_safety_backup:
        ok, safety = create_backup("prerestore", encrypt=False)
        if not ok:
            return False, ("The pre-restore safety copy could not be written (%s). Restoring "
                           "would overwrite panel.db, config.json, secret_key and cred_key with "
                           "no way back — without cred_key every stored SSH credential becomes "
                           "unreadable. Confirm again to restore without one." % safety)

    # A FIXED staging directory inside data/, not a fresh mkdtemp. The helper's restore verb takes
    # no path argument — root copying "whatever is in the directory you name" over the panel's keys
    # would let a caller stage a directory it cannot read and have root hand its contents back — so
    # both sides agree on this one location instead.
    stage = os.path.join(str(DATA_DIR), ".restore-stage")
    shutil.rmtree(stage, ignore_errors=True)
    os.makedirs(stage, mode=0o700, exist_ok=True)
    try:
        with tarfile.open(src, "r:gz") as tar:
            for m in tar.getmembers():
                if m.name in _MEMBERS and m.isfile():
                    tar.extract(m, stage)   # names already whitelisted above
    except Exception:
        _log.exception("backup extract failed")
        shutil.rmtree(stage, ignore_errors=True)
        return False, "Could not extract the backup."

    # STOP the panel first (releases the SQLite file), swap the files, clear the WAL/SHM
    # sidecars (the restored DB is authoritative), then START it again. No `set -e`: even if a
    # copy fails, we must always try to bring the panel back up rather than leave it stopped.
    # The swap itself — stop, copy the four members over the live files, drop the stale WAL/SHM
    # pair, start again, wipe the staging directory. It has to outlive the panel process, so it
    # runs detached.
    #
    # This used to be a bash script the panel WROTE into its own data dir and then handed to
    # `sudo systemd-run`: root executing a file the panel user had just created, out of a directory
    # the panel user owns. Narrowing the sudoers grant would not have touched that. The helper now
    # performs the sequence itself, in root-owned code, reading only the fixed staging path.
    try:
        if _helper_present():
            out, err, rc = _run_verb("panel-restore", [], timeout=20)
            if rc == 0:
                return True, _restore_started_msg(name, safety)
            _log.error("restore verb failed: rc=%s %s", rc, (err or out or "")[:200])
            shutil.rmtree(stage, ignore_errors=True)
            return False, "Could not start the restore."
        # Pre-helper fallback, unchanged in shape: a host that has not re-run install.sh as root
        # still needs to be able to restore.
        return _legacy_restore_dispatch(stage, name, safety)
    except Exception:
        _log.exception("restore dispatch failed")
        # Nothing will run the cleanup, so don't leave the keys staged either.
        shutil.rmtree(stage, ignore_errors=True)
        return False, "Could not start the restore."


def _restore_started_msg(name, safety):
    """What the operator is told. It names the safety copy, because that archive IS their way back
    and it is the only place its name appears — the panel is about to restart."""
    if safety:
        return ("Restoring from %s — the panel will restart in a few seconds. Your previous data "
                "was saved as %s." % (name, safety))
    return ("Restoring from %s — the panel will restart in a few seconds. NO pre-restore safety "
            "copy was made." % name)


def _legacy_restore_dispatch(stage, name, safety=""):
    """The pre-helper restore: write a script and run it under `sudo systemd-run`.

    Kept ONLY for a host that has the new code but has not had install.sh re-run as root, which is
    also the reason the sudoers grant cannot narrow yet — see the escalation census in the tests."""
    ufl = "--user " if os.path.exists(os.path.expanduser("~/.config/systemd/user/linuxgsm-panel.service")) else ""
    lines = ["#!/bin/bash", "sleep 1",
             "systemctl %sstop linuxgsm-panel.service || true" % ufl, "sleep 1"]
    for member, target in (("panel.db", DB_PATH), ("config.json", CONFIG_FILE),
                           ("secret_key", SECRET_FILE), ("cred_key", CRED_KEY_FILE)):
        srcf = os.path.join(stage, member)
        if os.path.exists(srcf):
            lines.append('cp -f %s %s || true' % (_sh(srcf), _sh(str(target))))
    lines += [
        'rm -f %s %s' % (_sh(str(DB_PATH) + "-wal"), _sh(str(DB_PATH) + "-shm")),
        "systemctl %sstart linuxgsm-panel.service || true" % ufl,
        'rm -rf %s' % _sh(stage),
    ]
    script = os.path.join(str(DATA_DIR), "restore.sh")
    with open(script, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(script, 0o700)
    # argv names a fixed script path under DATA_DIR, written at 0700 immediately above, and
    # there is no shell here. The script's CONTENT is composed — every value interpolated into
    # it goes through _sh() (shlex.quote), which is where the scrutiny belongs and is not what
    # this rule inspects.
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    subprocess.Popen(_service_restart_launcher(script),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy())
    return True, _restore_started_msg(name, safety)


def _sh(s):
    """Minimal single-quote shell escaping for a filesystem path in the restore script."""
    return "'" + str(s).replace("'", "'\\''") + "'"


def get_settings():
    cfg = load_config()
    try:
        keep = int(cfg.get("backup_keep_days", DEFAULT_KEEP_DAYS))
    except (TypeError, ValueError):
        keep = DEFAULT_KEEP_DAYS
    return {"enabled": bool(cfg.get("backup_enabled", True)),
            "keep_days": max(MIN_KEEP_DAYS, min(MAX_KEEP_DAYS, keep)),
            # Whether one is set — NEVER the passphrase itself. It is the only thing standing
            # between a leaked archive and every secret in it, so it does not travel to a browser.
            "encrypt": bool(cfg.get("backup_passphrase"))}


def set_settings(enabled=None, keep_days=None):
    def _mut(cfg):   # update_config: race-safe read-modify-write under the config lock
        if enabled is not None:
            cfg["backup_enabled"] = bool(enabled)
        if keep_days is not None:
            try:
                cfg["backup_keep_days"] = max(MIN_KEEP_DAYS, min(MAX_KEEP_DAYS, int(keep_days)))
            except (TypeError, ValueError):
                _log.debug("ignored invalid keep_days", exc_info=True)
    update_config(_mut)
    return get_settings()


# ── Full backups (game server files, via LinuxGSM's own backup) ──────────────
# Space-heavy, so they run on their own (longer) interval and keep only a few per server.
DEFAULT_FULL_INTERVAL = 7   # days; 0 = off
DEFAULT_FULL_KEEP = 2       # LinuxGSM backups kept per game server


def get_full_settings():
    cfg = load_config()

    def _int(k, d):
        try:
            return int(cfg.get(k, d))
        except (TypeError, ValueError):
            return d
    return {
        "interval_days": max(0, min(MAX_INTERVAL_DAYS,
                                    _int("full_backup_interval_days", DEFAULT_FULL_INTERVAL))),
        "keep": max(MIN_FULL_KEEP, min(MAX_FULL_KEEP, _int("full_backup_keep", DEFAULT_FULL_KEEP))),
        "last": _int("full_backup_last", 0),
        "summary": cfg.get("full_backup_summary", ""),
    }


def set_full_settings(interval_days=None, keep=None):
    def _mut(cfg):
        if interval_days is not None:
            try:
                cfg["full_backup_interval_days"] = max(0, min(MAX_INTERVAL_DAYS, int(interval_days)))
            except (TypeError, ValueError):
                _log.debug("ignored invalid full interval", exc_info=True)
        if keep is not None:
            try:
                cfg["full_backup_keep"] = max(MIN_FULL_KEEP, min(MAX_FULL_KEEP, int(keep)))
            except (TypeError, ValueError):
                _log.debug("ignored invalid full keep", exc_info=True)
    update_config(_mut)
    return get_full_settings()


def record_full_backup(summary):
    """Persist the time + one-line summary of the most recent full backup."""
    ts, note = int(time.time()), str(summary)[:300]   # runs in the backup thread → update_config
    update_config(lambda cfg: cfg.update({"full_backup_last": ts, "full_backup_summary": note}))


def full_backup_due():
    """True if scheduled full backups are on and one is due (interval elapsed since the last)."""
    s = get_full_settings()
    if s["interval_days"] <= 0:
        return False
    return time.time() - s["last"] >= s["interval_days"] * 86400


# ── Per-server schedules ─────────────────────────────────────────────────────
# Each game server can override the global default (interval + keep), or inherit it. Overrides
# live in cfg["game_schedules"] keyed by server id; a server's own last-run is tracked there too,
# so scheduled backups are decided (and staggered) per server.
def get_game_schedule(sid):
    """Effective schedule for one server: its override where set, else the global default.
    Returns {interval_days, keep, last, overridden}."""
    cfg = load_config()
    entry = _game_schedules(cfg).get(str(sid))
    if not isinstance(entry, dict):   # tolerate a corrupted config — treat as no override
        entry = {}
    d = get_full_settings()
    has_iv, has_keep = "interval_days" in entry, "keep" in entry

    def _clamp(v, lo, hi, dflt):
        try:
            return max(lo, min(hi, int(v)))
        except (TypeError, ValueError):
            return dflt
    return {
        "interval_days": (_clamp(entry["interval_days"], 0, MAX_INTERVAL_DAYS, d["interval_days"])
                          if has_iv else d["interval_days"]),
        "keep": (_clamp(entry["keep"], MIN_FULL_KEEP, MAX_FULL_KEEP, d["keep"])
                 if has_keep else d["keep"]),
        "last": _clamp(entry.get("last", 0), 0, 2 ** 63, 0),
        "overridden": has_iv or has_keep,
        "interval_set": has_iv,   # True → this server overrides the interval (else inherits default)
        "keep_set": has_keep,     # True → this server overrides keep
    }


def _game_schedules(cfg):
    """The game_schedules map from config, tolerant of corruption (returns {} if it isn't a dict)."""
    gs = cfg.get("game_schedules")
    return gs if isinstance(gs, dict) else {}


def set_game_schedule(sid, interval_days, keep):
    """Set/clear a server's schedule override. For each of interval_days/keep: a number sets an
    override, None clears it (inherit the global default). The server's last-run is preserved."""
    def _mut(cfg):
        sched = _game_schedules(cfg)
        cfg["game_schedules"] = sched   # normalise a corrupted value back to a dict
        entry = sched.get(str(sid))
        if not isinstance(entry, dict):
            entry = {}
        if interval_days is None:
            entry.pop("interval_days", None)
        else:
            entry["interval_days"] = max(0, min(MAX_INTERVAL_DAYS, int(interval_days)))
        if keep is None:
            entry.pop("keep", None)
        else:
            entry["keep"] = max(MIN_FULL_KEEP, min(MAX_FULL_KEEP, int(keep)))
        if entry:
            sched[str(sid)] = entry
        else:
            sched.pop(str(sid), None)
    update_config(_mut)
    return get_game_schedule(sid)


def remove_game_schedule(sid):
    """Drop a server's schedule entry entirely — used when it's uninstalled, so no stale override
    or last-run lingers in config (and can't be inherited if SQLite later reuses the row id)."""
    def _mut(cfg):
        gs = cfg.get("game_schedules")
        if isinstance(gs, dict):
            gs.pop(str(sid), None)
    update_config(_mut)


def record_game_backup(sid):
    """Mark a server's scheduled backup as just done (updates only that server's last-run)."""
    def _mut(cfg):   # runs after a scheduled backup (background) → update_config
        sched = _game_schedules(cfg)
        cfg["game_schedules"] = sched
        entry = sched.get(str(sid))
        if not isinstance(entry, dict):
            entry = {}
        entry["last"] = int(time.time())
        sched[str(sid)] = entry
    update_config(_mut)


def game_backup_due(sid):
    """True if this server's schedule is enabled (interval > 0) and a backup is due."""
    s = get_game_schedule(sid)
    if s["interval_days"] <= 0:
        return False
    return time.time() - s["last"] >= s["interval_days"] * 86400
