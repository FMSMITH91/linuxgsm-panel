"""Part 52 of the unit suite: fixes from the 2026-10-11 review (game files, debug report, helper, routes).

* GMod content: the install flow mounts only the games that are on disk (the remote grant's
  exit status is held to the helper's rule in part05).
* LinuxGSM configs: the secrets files linuxgsm.sh sources (secrets-common.cfg after common.cfg,
  secrets-<instance>.cfg LAST) are read for every merged value, and a change to a key the instance
  secrets file also sets is refused instead of "Saved" and shadowed.
* The game list's one-minute "nothing yet" stays a minute after a second failed fetch.
* Upload conflicts are found in a folder reached through a symlink; a folder that links OUTSIDE
  the home says so instead of "Invalid path".
* The batched player poll cuts the map in jq, as its docstring says.
* Debug report: sudo lines with GROUP=/TSID=/ENV= fields are counted, a REFUSED line keeps no
  argv; an EMPTY cred_key is missing at every decrypt gate; an unreadable config.json prints no
  retention values; commits compare by prefix; JSON-quoted secret keys are redacted; a multi-word
  Tailscale name is mapped by its leading words too.
* Helper: sudoers.d names sudo ignores, a rule for another host, a negated user list and a later
  overriding rule do not make the caller root-capable; the restore's -wal/-shm unlink never follows
  a link at data/.
* Routes: the console window drops the log's unfinished last line when it has a place; the cron
  GET's tracking upgrade (a crontab write) asks the write refusal; `details` with a Status block is
  installed even when it also says "No such file".

HOW IT RUNS. On part12's Flask app and stubs, as part49 does: every host command runs in a REAL
bash over a throwaway home (/home/<account> rewritten to it); nothing reaches a transport.
"""
import io
import os
import shutil as _shutil52
import subprocess as _sp52  # nosec B404 - runs bash on the commands this part's code builds
import tempfile as _tf52
import time as _time52
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part05 import _helper
from unit.part12 import (_P9_TRIPPED, _p9, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sf, _p9_sh, _p9_sm, _p9_so, _p9_trip)
from panel.core import config as _cfg52
from panel.db.models import GameServer, RemoteServer, User, db
from panel.ops import system_ops as _so52
from panel.ops.debug_report import _base as _base52
from panel.ops.debug_report import _src_db as _srcdb52
from panel.ops.debug_report import data as _data52
from panel.ops.debug_report import header as _hdr52
from panel.ops.debug_report import hosts as _hosts52
from panel.ops.debug_report import logs as _logs52
from panel.ops.debug_report import privacy as _pv52
from panel.ops.ssh_manager import cron as _cron52
from panel.ops.ssh_manager import files as _files52
from panel.security import auth as _auth52
from panel.services import lgsm_data as _lgd52

_TRIP52_START = len(_P9_TRIPPED)
_USER52 = "r11b52"
_SELF52 = "csgoserver"
_HOME52 = os.path.realpath(_tf52.mkdtemp(prefix="lgsm-unit-p52-home-"))
_OUT52 = os.path.realpath(_tf52.mkdtemp(prefix="lgsm-unit-p52-out-"))
_CFGDIR52 = "lgsm/config-lgsm/%s" % _SELF52
_mine52 = {"hosts": [], "servers": [], "users": []}


def _bash52(server, user, sh, timeout=30, selfname=None, scope=False):
    """shell_as_game_user, in a real bash, with /home/<account> pointing at the throwaway home."""
    p = _sp52.run(["bash", "-c", sh.replace("/home/" + _USER52, _HOME52)],  # nosec B603 B607 - bash on this part's own command
                  capture_output=True, text=True, timeout=60, check=False)
    return p.stdout, p.stderr, p.returncode


def _write52(rel, text):
    path = os.path.join(_HOME52, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _reset52():
    for root in (_HOME52, _OUT52):
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if os.path.islink(p) or not os.path.isdir(p):
                os.unlink(p)
            else:
                _shutil52.rmtree(p)
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()


def _arm52():
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part52's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash52)
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})


def _setup52():
    with _p9.app_context():
        r = RemoteServer(name="p52-host", host="192.0.2.152", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p52-" + _USER52, short_name=_USER52, game_type="csgo",
                        port=27520, installed=True, status="offline")
        admin = User(username="p52_admin", password_hash=_auth52.hash_password("Str0ng!passw0rd-p52"),
                     display_name="p52 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine52["hosts"].append(r.id)
        _mine52["servers"].append(gs.id)
        _mine52["users"].append(admin.id)
        return gs.id, admin.id


def _cleanup52():
    with _p9.app_context():
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine52[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()
    _shutil52.rmtree(_HOME52, ignore_errors=True)
    _shutil52.rmtree(_OUT52, ignore_errors=True)


# ── A04/A07: the install flow mounts only the content that is on disk ───────────────────────────
def _gmod_install52():
    mounted = []
    _p9_patch(_p9_ms, "ensure_content_user", lambda remote: {"user": "cu", "present": {"cstrike": 1}})
    # TF2's download failed (out of disk): install_gmod_content reports nothing newly installed.
    _p9_patch(_p9_ms, "install_gmod_content",
              lambda remote, cu, games, on_progress=None: (False, [], "tf: download failed"))
    _p9_patch(_p9_ms, "gmod_mount_setup",
              lambda remote, short, cu, games: (mounted.append(list(games)), (True, "ok"))[1])
    job = NS(short_name="gm52", game_type="gmod", content_games=["cstrike", "tf"],
             p=lambda *a, **k: None)
    step = _p9_ms._install_gmod_content(job, NS(name="p52-host", id=-52))
    check("gmod install: the mount is written for the games on disk only (a failed TF2 download is "
          "not mounted; the CS:S already there is)",
          mounted == [["cstrike"]] and step == 9, repr((mounted, step)))


# ── A04: the secrets files linuxgsm.sh sources ──────────────────────────────────────────────────
def _secrets52():
    _reset52()
    _write52("lgsm/config-lgsm/%s/_default.cfg" % _SELF52, 'discordwebhook=""\nmaxplayers="8"\n')
    _write52(_CFGDIR52 + "/common.cfg", 'maxplayers="10"\n')
    _write52(_CFGDIR52 + "/secrets-common.cfg", 'maxplayers="12"\n')
    _write52(_CFGDIR52 + "/%s.cfg" % _SELF52, 'discordwebhook="https://old"\nport="27015"\n')
    _write52(_CFGDIR52 + "/secrets-%s.cfg" % _SELF52, 'discordwebhook="https://real"\n')
    vals = _files52.lgsm_get_values(NS(), _USER52, _SELF52, ["discordwebhook", "maxplayers", "port"])
    check("lgsm_get_values: a key secrets-<instance>.cfg sets reads from there (linuxgsm.sh "
          "sources it last), secrets-common.cfg over common.cfg",
          vals == {"discordwebhook": "https://real", "maxplayers": "12", "port": "27015"}, repr(vals))
    rc = _files52.lgsm_read_config(NS(), _USER52, _SELF52)
    merged = {g["key"]: g["value"] for grp in rc.get("groups") or [] for g in grp["settings"]}
    check("lgsm_read_config: the settings form shows the values the server runs with (both "
          "secrets files merged), while Raw is still the instance cfg alone",
          merged.get("discordwebhook") == "https://real" and merged.get("maxplayers") == "12"
          and rc.get("raw") == 'discordwebhook="https://old"\nport="27015"\n' and not rc.get("error"),
          repr((merged, rc.get("raw"), rc.get("error"))))
    _secrets52_writes()


def _secrets52_writes():
    """lgsm_write_config against the secrets files _secrets52 wrote, then with none at all."""
    written = []
    _p9_patch(_files52, "_write_file_as_user",
              lambda s, u, p, b: (written.append((p, b.decode())), (True, ""))[1])
    ok, msg = _files52.lgsm_write_config(NS(), _USER52, _SELF52, {"discordwebhook": "https://new"})
    check("lgsm_write_config: changing a key secrets-<instance>.cfg also sets is refused, naming "
          "that file, and nothing is written",
          ok is False and "secrets-%s.cfg" % _SELF52 in msg and not written, repr((ok, msg, written)))
    ok, msg = _files52.lgsm_write_config(NS(), _USER52, _SELF52,
                                         {"discordwebhook": "https://real", "port": "27016"})
    check("lgsm_write_config: ...while the same value posted back (the Alerts form saves every "
          "field) and a key the secrets file does not set still save (control)",
          ok is True and len(written) == 1 and 'port="27016"' in written[0][1], repr((ok, msg, written)))
    _reset52()
    _write52(_CFGDIR52 + "/%s.cfg" % _SELF52, 'port="27015"\n')
    del written[:]
    ok, _msg = _files52.lgsm_write_config(NS(), _USER52, _SELF52, {"port": "27017"})
    check("lgsm_write_config: with no secrets file at all the write goes ahead (control)",
          ok is True and len(written) == 1, repr((ok, written)))


# ── A04: the game list's empty memo ──────────────────────────────────────────────────────────────
def _lgd_memo52():
    key = "p52-serverlist"
    try:
        with _lgd52._lock:
            first = _lgd52._memo_store(key, None, [], None, True)
            exp1 = _lgd52._mem[key][0] - _time52.time()
            # A minute on, the fetch fails again: the hit is the empty one this stored itself, and
            # EXPIRED — as _memoised hands it over. Passed the live first store instead, a memo
            # that was never re-stored still read about a minute from now and passed.
            _lgd52._mem[key] = (_time52.time() - 1, [])
            second = _lgd52._memo_store(key, _lgd52._mem[key], [], None, True)
            exp2 = _lgd52._mem[key][0] - _time52.time()
    finally:
        with _lgd52._lock:
            _lgd52._mem.pop(key, None)
    check("lgsm_data: an empty read after an empty read is remembered for a minute again, not the "
          "hour a failed refetch of a real list waits",
          first == [] and second == [] and 55 <= exp1 <= 61 and 55 <= exp2 <= 61, repr((exp1, exp2)))


# ── A04: uploads into, and browsing of, a symlinked folder ───────────────────────────────────────
def _links52(client, sid):
    _reset52()
    _write52("lgsm/log/server/x.cfg", "old\n")
    os.symlink("lgsm/log/server", os.path.join(_HOME52, "serverlog"))
    try:
        got = _files52.stat_upload_targets(NS(), _USER52, "serverlog", ["x.cfg", "new.cfg"])
    except Exception as exc:  # noqa: BLE001 - a crash fails the check by name
        got = repr(exc)
    check("upload check: a file that exists in a folder reached through a symlink is found (the "
          "Replace dialog appears)",
          isinstance(got, list) and [e.get("name") for e in got] == ["x.cfg"], repr(got))
    os.makedirs(os.path.join(_OUT52, "bigdisk"))
    os.symlink(os.path.join(_OUT52, "bigdisk"), os.path.join(_HOME52, "moved"))
    r = client.get("/api/server/%d/browse?path=moved" % sid)
    body = _p9_json(r)
    check("browse: a folder that links outside the home is refused saying so, not 'Invalid path'",
          r.status_code == 400 and "outside the account's home" in (body.get("error") or ""),
          repr((r.status_code, body)))
    r = client.get("/api/server/%d/browse?path=serverlog" % sid)
    body = _p9_json(r)
    check("browse: ...while a symlinked folder inside the home still lists (control)",
          r.status_code == 200 and [e["name"] for e in body.get("entries") or []] == ["x.cfg"],
          repr((r.status_code, body)))


# ── A04 lead: the batched poll cuts the map ──────────────────────────────────────────────────────
def _batch_map52():
    if not _shutil52.which("jq"):
        skip("player batch: a long map name is cut in jq", "no jq on this machine")
        return
    reply = '{"name":"n","map":"%s","players":[],"maxplayers":4}' % ("m" * 5000)
    flt = _cron52._batch_target_filter(7)
    p = _sp52.run(["jq", "-c", flt], input=reply, capture_output=True, text=True, timeout=30)  # nosec B603 B607 - jq on a fixed filter
    out = p.stdout.strip()
    d = _cron52._batch_reply(out)
    check("player batch: a game-supplied map of 5000 chars is cut in jq, so the reply stays one "
          "short line (under PIPE_BUF)",
          d is not None and d.get("p") == "m" * 120 and len(out) < 512, repr(out[:200]))
    p = _sp52.run(["jq", "-c", flt], input='{"map":5,"players":[]}', capture_output=True, text=True,
                  timeout=30)  # nosec B603 B607 - jq on a fixed filter
    d = _cron52._batch_reply(p.stdout.strip())
    check("player batch: ...and a map that is not text is still no map (_map_text), not one made "
          "up by tostring", d is not None and _cron52._map_text(d.get("p")) is None, repr(d))


# ── A06: sudo lines in the debug report ─────────────────────────────────────────────────────────
def _sudo_lines52():
    pre = "Oct 11 10:00:00 h sudo[1]: lgsmpanel : "
    refused = [pre + "3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/x ; USER=root ; "
                     "COMMAND=/usr/bin/mysql -u root -pS3cretPass",
               pre + "a password is required ; TTY=pts/0 ; PWD=/home/x ; USER=root ; "
                     "ENV=DB_PASS=hunter2 ; COMMAND=/usr/bin/htpasswd -b /etc/nginx/.htpasswd bob hunter2"]
    kept, verbs, _s = _logs52._split_priv(refused)
    text = "\n".join(kept)
    check("debug report: a REFUSED sudo line stays in the log but keeps no argv or ENV= value",
          len(kept) == 2 and not any(t in text for t in ("S3cretPass", "hunter2", "htpasswd", "mysql"))
          and "incorrect password attempts" in text and "COMMAND=(other program as root)" in text,
          repr(kept))
    ok = [pre + "TTY=pts/0 ; PWD=/home/x ; USER=root ; GROUP=docker ; COMMAND=/usr/bin/docker ps -q",
          pre + "TTY=pts/0 ; PWD=/home/x ; USER=root ; TSID=000001 ; ENV=DB_PASS=hunter2 ; "
                "COMMAND=/usr/bin/env secretarg",
          pre + "PWD=/home/x ; USER=root ; COMMAND=/usr/bin/true"]
    kept, verbs, _s = _logs52._split_priv(ok)
    check("debug report: successful sudo lines with GROUP=, TSID= or ENV= are counted, never "
          "printed (the plain line still is counted too)",
          kept == [] and verbs == {"other program as root": 1, "env as root": 1, "true as root": 1},
          repr((kept, verbs)))


# ── A06: an EMPTY cred_key is a missing one at every decrypt gate ───────────────────────────────
def _cred_key52():
    tmp = _tf52.mkdtemp(prefix="lgsm-unit-p52-key-")
    empty = _cfg52.CRED_KEY_FILE.__class__(os.path.join(tmp, "cred_key"))
    empty.write_bytes(b"")
    full = _cfg52.CRED_KEY_FILE.__class__(os.path.join(tmp, "cred_key_full"))
    full.write_bytes(b"k" * 44)
    decrypts = []
    orig = _cfg52.CRED_KEY_FILE
    try:
        # The control: a key file WITH a key is present, so "not present" below is the emptiness.
        _p9_patch(_cfg52, "CRED_KEY_FILE", full)
        check("debug report hosts: a cred_key with a key in it is a key present (control)",
              _hosts52.key_present() is True, "")
        _p9_patch(_cfg52, "CRED_KEY_FILE", empty)
        check("debug report hosts: an empty cred_key is not a key present (a decrypt would mint one)",
              _hosts52.key_present() is False, "")
        from panel.ops import backup as _bk52
        _p9_patch(_bk52, "get_settings", lambda: {"encrypt": True})
        _p9_patch(_bk52, "get_passphrase", lambda: decrypts.append("passphrase") or "x")
        lvl, words = _data52._passphrase_state()
        check("debug report database: with an empty cred_key the passphrase is said unreadable, "
              "and never decrypted", lvl == "fail" and "missing" in words and not decrypts,
              repr((lvl, words, decrypts)))
        st = _pv52._State()
        _p9_patch(_pv52, "_in_app", lambda ctx, fn: None)
        _pv52._names_db(None, st)
        check("debug report privacy: an empty cred_key is reported missing (no decrypting name read)",
              st.cred_key_missing is True, repr(st.source_errors))
        seen = []
        _p9_patch(_so52, "_read_host_fields", lambda: ([], []))   # (host rows, session values)
        _tally = {"ok": 0, "bad": 0, "plain": 0, "session_bad": 0}
        _p9_patch(_so52, "_cred_tally", lambda hosts, sv, key: (seen.append(key), (_tally, []))[1])
        _so52._diag_host_credentials()
        check("diagnostics: the host-credentials check does not decrypt under an empty cred_key",
              seen == [False], repr(seen))
        check("debug report: ...and none of it wrote a key over the empty file",
              empty.read_bytes() == b"", repr(empty.read_bytes()[:8]))
    finally:
        # Back to the run's own path now, not at part52's final restore: until then any section
        # whose route decrypted a field reached _cred_fernet in the directory removed below.
        _p9_patch(_cfg52, "CRED_KEY_FILE", orig)
        _shutil52.rmtree(tmp, ignore_errors=True)


# ── A06: an unreadable config.json prints no retention values ───────────────────────────────────
def _retention52():
    _p9_patch(_cfg52, "load_config", lambda *a, **k: _cfg52.UnreadableConfig({}))
    try:
        _data52._retention_conf()
        raised = False
    except ValueError:
        raised = True
    check("debug report database: retention is not read out of an unreadable config.json",
          raised, "")
    _p9_patch(_srcdb52, "run_ro", lambda queries, timeout=None: {
        "audit_log": [(5, None)], "metric_sample": [(0, None)], "host_sample": [(0, None)]})
    res = _data52.section_database(_base52.Ctx(app=None, deadline_s=5.0))
    line = [ln for ln in res.lines if "**audit_log**" in ln]
    check("debug report database: ...and the audit_log line says it is not known rather than "
          "printing the defaults as the operator's settings",
          len(line) == 1 and "config.json unreadable" in line[0] and "keep forever" not in line[0]
          and "90 d" not in line[0], repr(line))


# ── A06 leads: commits by prefix, JSON-quoted secrets, multi-word Tailscale names ───────────────
def _report_leads52():
    res = _base52.Result()
    _p9_patch(_hdr52, "_process_start", lambda: None)
    _p9_patch(_hdr52, "_branch", lambda: "main")
    ctx = NS(app=NS(config={"PANEL_COMMIT": "4045c74"}), memo=lambda k, fn: "4045c747")
    _hdr52._commit_lines(ctx, res)
    check("debug report header: a short commit that git now abbreviates longer is the same commit, "
          "not RESTART PENDING",
          not any("RESTART PENDING" in ln for ln in res.lines) and ", same" in res.lines[0],
          repr(res.lines))
    res = _base52.Result()
    ctx = NS(app=NS(config={"PANEL_COMMIT": "4045c74"}), memo=lambda k, fn: "3f89779a")
    _hdr52._commit_lines(ctx, res)
    check("debug report header: ...while a different commit still is (control)",
          any("RESTART PENDING" in ln for ln in res.lines), repr(res.lines))
    red = _so52._redact('{"password": "hunter2", "api_key": \'k9\'} {\'token\': \'tok55\'}')
    check("redaction: a JSON- or repr-quoted secret key is redacted too",
          not any(v in red for v in ("hunter2", "k9", "tok55")), red)
    st = _pv52._State()
    _pv52._names_tailscale({"User": {"1": {"DisplayName": "Jane Quinn Doe"}}}, st)
    check("debug report privacy: a Tailscale name of several words is mapped by its leading words "
          "too (a cut between them left 'Jane …' unmapped)",
          "jane" in st.names and "jane quinn" in st.names and "jane quinn doe" in st.names,
          repr(sorted(st.names)))


# ── A07: who reaches root, as the helper reads sudoers ──────────────────────────────────────────
def _reach52():
    tmp = _tf52.mkdtemp(prefix="lgsm-unit-p52-sudo-")
    import pwd as _pwd52
    caller = _pwd52.getpwuid(os.getuid()).pw_name
    saved = (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of)
    try:
        main = os.path.join(tmp, "sudoers")
        ddir = os.path.join(tmp, "sudoers.d")
        os.makedirs(ddir)
        _helper.SUDOERS_FILE, _helper.SUDOERS_DIR = main, ddir
        _helper._groups_of = lambda _n: set()

        def reach(main_text, files):
            with open(main, "w", encoding="utf-8") as fh:
                # sudoers.d is read through the main file's includedir, as sudo reads it.
                fh.write(main_text + "@includedir %s\n" % ddir)
            for n in os.listdir(ddir):
                os.unlink(os.path.join(ddir, n))
            for n, t in files.items():
                with open(os.path.join(ddir, n), "w", encoding="utf-8") as fh:
                    fh.write(t)
            with _redirect52():
                return _helper._caller_reaches_root(caller)

        grant = "%s ALL=(ALL) NOPASSWD: ALL\n" % caller
        got = {"disabled": reach("", {"lgsmpanel-full.disabled": grant}),
               "tilde": reach("", {"lgsmpanel-full~": grant}),
               "live": reach("", {"lgsmpanel-full": grant})}
        check("helper: a sudoers.d file sudo ignores ('.' in the name, or ending '~') does not make "
              "the caller root-capable; the same rule in a live name does (control)",
              got == {"disabled": False, "tilde": False, "live": True}, repr(got))
        got = {"other host": reach("%s otherhost=(ALL) NOPASSWD: ALL\n" % caller, {}),
               "negated": reach("ALL, !%s ALL=(ALL) NOPASSWD: ALL\n" % caller, {}),
               "later": reach(grant + "%s ALL=(ALL) ALL\n" % caller, {}),
               "netgroup": reach("+admins ALL=(ALL) NOPASSWD: ALL\n", {}),
               "plain": reach(grant, {})}
        check("helper: a rule for another host, a user list that negates the caller, a later rule "
              "that asks a password for everything, a netgroup it cannot evaluate — none is root; "
              "the plain grant is (control)",
              got == {"other host": False, "negated": False, "later": False, "netgroup": False,
                      "plain": True}, repr(got))
    finally:
        (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of) = saved
        _shutil52.rmtree(tmp, ignore_errors=True)


class _redirect52(object):
    """Swallow the helper's stderr notes for the length of a with-block."""

    def __enter__(self):
        import contextlib
        self._cm = contextlib.redirect_stderr(io.StringIO())
        return self._cm.__enter__()

    def __exit__(self, *exc):
        return self._cm.__exit__(*exc)


def _sidecars52():
    tmp = _tf52.mkdtemp(prefix="lgsm-unit-p52-restore-")
    try:
        other, real = os.path.join(tmp, "other"), os.path.join(tmp, "real")
        os.makedirs(other)
        os.makedirs(real)
        for d in (other, real):
            for side in ("-wal", "-shm"):
                with open(os.path.join(d, "panel.db" + side), "w") as fh:
                    fh.write("x")
        os.symlink(other, os.path.join(tmp, "data"))
        # The restore itself, driven: systemctl and the member copy stood in for, so what is left
        # is the sidecar drop and the stage wipe as _restore_run does them.
        saved = (_helper.resolve, _helper.subprocess, _helper.restore_copy_members)
        try:
            _helper.resolve = lambda name: "/bin/true"
            _helper.subprocess = NS(run=lambda *a, **k: NS(returncode=0))
            _helper.restore_copy_members = lambda stage, data_dir: []
            _helper._restore_run(os.path.join(tmp, "data"))
            _helper._restore_run(real)
        finally:
            (_helper.resolve, _helper.subprocess, _helper.restore_copy_members) = saved
        check("helper restore: the -wal/-shm drop does not follow a data/ swapped for a link, and "
              "still removes them from the real directory (control)",
              sorted(os.listdir(other)) == ["panel.db-shm", "panel.db-wal"] and os.listdir(real) == [],
              repr((os.listdir(other), os.listdir(real))))
    finally:
        _shutil52.rmtree(tmp, ignore_errors=True)


# ── A08: the console window, the cron GET, `details` ────────────────────────────────────────────
def _console52():
    log = os.path.join(_OUT52, "console.log")
    gs = NS(console_log=log, short_name=_USER52, lgsm_name=_SELF52)

    def read(remote, user, cmd, timeout=15, selfname=None):
        p = _sp52.run(["bash", "-c", cmd], capture_output=True, text=True, timeout=30, check=False)  # nosec B603 B607 - bash on this part's own command
        return p.stdout, p.stderr, p.returncode

    _p9_patch(_p9_sm, "read_as_game_user", read)
    rows = {}
    for name, text in (("partial", "line1\nline2\nline3\npartial"), ("whole", "line1\nline2\nline3\n")):
        with open(log, "w", encoding="utf-8") as fh:
            fh.write(text)
        ok, lines, at = _p9_sf._read_console_window(NS(), gs, 50, None)
        rows[name] = (ok, [r.get("line") for r in lines], at)
    check("console window: a log that ends mid-line primes WITHOUT the fragment (the catch-up from "
          "`at`, the file's end, brings that line whole), and `at` is still the end",
          rows["partial"][0] and rows["partial"][1] == ["line1", "line2", "line3"]
          and rows["partial"][2] is not None and rows["partial"][2][2] == len("line1\nline2\nline3\npartial"),
          repr(rows["partial"]))
    check("console window: ...while a log ending in a newline keeps its last line (control)",
          rows["whole"][1] == ["line1", "line2", "line3"], repr(rows["whole"]))


def _cron_get52(client, sid):
    upgrades = []
    _p9_patch(_p9_sm, "upgrade_managed_cron_tracking",
              lambda *a, **k: upgrades.append(a[1]))
    _p9_patch(_p9_sm, "list_cron_jobs", lambda remote, user, lgsm: [])
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {u: "is in the sudo group" for u in users})
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()
    r = client.get("/api/server/%d/cron" % sid)
    # 409 since review 1012a: a root-capable account's crontab is not even listed (_cron_listing).
    check("cron GET: the tracking upgrade (a crontab REWRITE) is not run as a root-capable account",
          r.status_code == 409 and upgrades == [], repr((r.status_code, upgrades)))
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()
    r = client.get("/api/server/%d/cron" % sid)
    check("cron GET: ...and still runs for a plain game account (control)",
          r.status_code == 200 and upgrades == [_USER52], repr((r.status_code, upgrades)))


def _looks_installed52():
    outs = {}
    for name, text in (("both", "Status: STOPPED\ncat: server.cfg: No such file or directory\n"),
                       ("missing", "cat: x: No such file or directory\n"),
                       ("not", "Server is not installed\nStatus: ")):
        _p9_patch(_p9_sm, "shell_as_game_user", lambda *a, _t=text, **k: (_t, "", 0))
        _p9_patch(_p9_sh, "_serverfiles_verdict", lambda remote, user: None)
        outs[name] = _p9_sh._looks_installed(_p9, NS(), _USER52, _SELF52)
    check("install reconcile: `details` that printed its Status block is installed even when it "
          "also says 'No such file'; that line alone, or 'not installed', is not (controls)",
          outs == {"both": True, "missing": False, "not": False}, repr(outs))


try:
    _arm52()
    _S52, _ADMIN52 = _setup52()
    _A52 = _p9_client(_ADMIN52)
    _gmod_install52()
    _secrets52()
    _lgd_memo52()
    _links52(_A52, _S52)
    _batch_map52()
    _sudo_lines52()
    _cred_key52()
    _retention52()
    _report_leads52()
    _reach52()
    _sidecars52()
    _console52()
    _cron_get52(_A52, _S52)
    _looks_installed52()
finally:
    _p9_restore_all()
    _cleanup52()

check("part52: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP52_START, repr(_P9_TRIPPED[_TRIP52_START:][:6]))
