"""Part 247 of the unit suite: security fixes around restarts, step-up, 2FA, keys and the installer.

* The HTTPS certificate's paste, Let's Encrypt and remove routes, and the daily Let's Encrypt
  refresh, restart the panel only when host_reboot.panel_host_busy() allows it: refused (nothing
  written, no restart) while a game-server restore or the panel host's reboot runs.
* Turning 2FA off with a password under 15 characters is refused before any code is spent; an
  admin's 2FA reset also issues a new password the account must change.
* Settings' audit row names "Require 2FA" and session binding changes.
* The helper's tls-le-copy copies only a certificate panel.conf's tls_le_names lists (the installer
  records it from PANEL_TLS_LE_NAMES, never from a run the panel started); the route says how.
* A name under a self-hosted control server's suffix is taken as tailnet by the lock-out guards only
  when it resolves to tailnet addresses.
* The re-encryption pass reads only ciphertext columns, and the prune keeps a key panel.db.backup
  still uses; a failed legacy encryption at start is logged (part13 checks that through create_app).
* The update rollback keeps the breached-password list; sign-release saves a release's name only
  once its GitHub release exists.
* The debug report does not call every `&&` game-account body LinuxGSM work; the world reset does
  not read a config line that can set the key by arithmetic as one that only names it.

Every route runs on part12's app with its transport tripwire armed; nothing reaches a host or data/.
"""
import ast as _ast247
import io as _io247
import os
import pathlib as _pl247
import shlex as _shlex247
import shutil as _sh247
import subprocess as _sp247  # nosec B404 - bash and git over this part's own scratch files
import sys
import tempfile as _tf247
from importlib import machinery as _mach247, util as _ilu247
from types import SimpleNamespace as _NS247

import pyotp as _pyotp247
from cryptography.fernet import Fernet as _Fernet247
from flask import Flask as _Flask247

from unit.part01 import check, eq, skip
from unit.part05 import _helper_path, _root
from unit.part142 import _ENV142, _run142
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_flashes, _p9_json, _p9_patch,
                         _p9_restore_all)
from panel.core import config as _cfg247
from panel.db import at_rest as _ar247
from panel.db.models import AuditLog as _AL247, User as _U247, db as _db247
from panel.ops import system_ops as _so247, tailscale_integration as _ts247
from panel.ops.debug_report import logs as _lg247
from panel.ops.ssh_manager import _core as _core247, firewall as _fw247, hosts as _hosts247
from panel.routes import tls_cert as _route247
from panel.security import account_guard as _ag247, auth as _auth247
from panel.services import certs as _certs247, host_reboot as _hr247, tls_own as _own247, world_reset as _wr247

_trips247 = len(_P9_TRIPPED)
_TMP247 = _tf247.mkdtemp(prefix="lgsm-unit-247-")
_CFG247 = {}
_RESTARTS247 = []
_BUSY247 = "A game server is being restored (part247): the panel does not restart until it ends."
_LONG247 = "harbour lantern quietly"       # 23 characters: the fixtures' long password
_SHORT247 = "harbour9x"                    # 9 characters: allowed only with 2FA on
_IDS247 = []
_CODES247 = {}
_XHR247 = {"X-Requested-With": "XMLHttpRequest"}
_REAL_FETCH247 = _own247.fetch_letsencrypt


def _audit247(action, since=0):
    with _p9.app_context():
        return [(r.detail, r.success) for r in
                _AL247.query.filter(_AL247.action == action, _AL247.id > since).order_by(_AL247.id).all()]


def _last_id247():
    with _p9.app_context():
        r = _AL247.query.order_by(_AL247.id.desc()).first()
        return r.id if r else 0


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The certificate routes and the daily refresh ask panel_host_busy before a restart
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _arm_tls247(busy):
    _p9_arm(who="part247")
    for mod in (_own247, _route247):
        _p9_patch(mod, "load_config", lambda: dict(_CFG247))
        _p9_patch(mod, "update_config", lambda mutate: mutate(_CFG247))
    _p9_patch(_certs247, "load_config", lambda: dict(_CFG247))
    _p9_patch(_certs247, "DATA_DIR", _pl247.Path(_TMP247) / "data")
    _p9_patch(_so247, "restart_panel", lambda delay_seconds=2: (_RESTARTS247.append(delay_seconds), (True, "ok"))[1])
    _p9_patch(_hr247, "panel_host_busy", lambda: busy)
    _p9_patch(_own247, "fetch_letsencrypt", lambda name: (_RESTARTS247.append("fetch:" + name), (b"", b"", "p247"))[1])
    _p9_patch(_own247, "install", lambda *a, **k: _RESTARTS247.append("install"))
    _p9_patch(_own247, "remove", lambda: _RESTARTS247.append("remove"))


def _tls_posts247():
    """(status, first flash) of the three routes, and what reached the restart/fetch/install recorder."""
    out = []
    for url, data in (("/settings/tls/paste", {"cert_pem": "x", "key_pem": "y"}),
                      ("/settings/tls/letsencrypt", {"le_name": "panel.example.com"}),
                      ("/settings/tls/remove", {"confirm": "on"})):
        with _p9_client(P9_ADMIN) as c:
            r = c.post(url, data=data)
            with c.session_transaction() as sess:
                said = [m for _c, m in sess.get("_flashes", [])]
        out.append((r.status_code, said[:1]))
    return out


def _s247_tls_routes():
    _CFG247.clear()
    _CFG247.update({"tls_cert_source": "own"})
    _RESTARTS247.clear()
    try:
        _arm_tls247(_BUSY247)
        busy = _tls_posts247()
        busy_calls = list(_RESTARTS247)
        busy_cfg = dict(_CFG247)
        _p9_patch(_hr247, "panel_host_busy", lambda: None)
        free = _tls_posts247()
    finally:
        _p9_restore_all()
    eq("tls restart: paste, Let's Encrypt and remove are each refused with panel_host_busy's sentence while the "
       "panel must not restart", busy, [(302, [_BUSY247])] * 3)
    eq("tls restart: ...nothing was fetched, installed, removed or restarted, and auto-renew was not written",
       (busy_calls, busy_cfg), ([], {"tls_cert_source": "own"}))
    eq("tls restart: when the panel may restart, the same posts reach the fetch and the remove (control)",
       ([s for s, _m in free], [c for c in _RESTARTS247 if c in ("fetch:panel.example.com", "remove")]),
       ([302] * 3, ["fetch:panel.example.com", "remove"]))


def _s247_tls_renew():
    _CFG247.clear()
    _CFG247.update({"tls_cert_source": "letsencrypt", "tls_le_name": "panel.example.com"})
    _RESTARTS247.clear()
    try:
        _arm_tls247(_BUSY247)
        _own247._RENEW["at"] = 0.0
        busy = _own247.maybe_renew({"BOOT_TLS": True}, now=10 * 86400.0)
        busy_at, busy_calls = _own247._RENEW["at"], list(_RESTARTS247)
        _p9_patch(_hr247, "panel_host_busy", lambda: None)
        free = _own247.maybe_renew({"BOOT_TLS": True}, now=10 * 86400.0)
    finally:
        _p9_restore_all()
        _own247._RENEW["at"] = 0.0
    eq("tls renew: the daily refresh answers 'busy' while the panel must not restart, fetches nothing, and is "
       "not marked as done (the next tick tries again)", (busy, busy_at, busy_calls), ("busy", 0.0, []))
    eq("tls renew: ...and runs once the panel may restart (control: it reaches the fetch)",
       (free, _RESTARTS247), ("failed", ["fetch:panel.example.com"]))
    from panel.routes import os_updates as _osu247
    seen = []

    class _Ctx247:
        def __enter__(self):
            seen.append("in")

        def __exit__(self, *exc):
            seen.append("out")
            return False
    fake = type("FakeApp247", (), {"config": {"BOOT_TLS": True}, "app_context": lambda self: _Ctx247()})()
    try:
        _p9_patch(_own247, "maybe_renew", lambda boot=None, now=None: seen.append("renew"))
        _osu247._renew_tls(fake)
    finally:
        _p9_restore_all()
    eq("tls renew: the update-check ticker's refresh runs inside an app context (its busy check reads the host "
       "rows)", seen, ["in", "renew", "out"])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. 2FA off keeps no password under 15 characters
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _user247(name, secret_word, totp=None, superadmin=False):
    with _p9.app_context():
        u = _U247(username=name, password_hash=_auth247.hash_password(secret_word), display_name=name,
                  is_superadmin=superadmin, is_active=True)
        if totp:
            from panel.core.config import encrypt_secret
            u.totp_secret, u.totp_enabled = encrypt_secret(totp), True
            _CODES247[name] = _auth247.generate_backup_codes(n=2)
            u.set_backup_codes(_CODES247[name])
        _db247.session.add(u)
        _db247.session.commit()
        _IDS247.append(u.id)
        return u.id


def _two_fa247(uid):
    with _p9.app_context():
        u = _db247.session.get(_U247, uid)
        return (bool(u.totp_enabled), u.backup_codes_remaining, bool(u.must_change_password),
                _auth247.check_password(_SHORT247, u.password_hash))


def _s247_disable_short():
    seed = _pyotp247.random_base32()
    short_id = _user247("p247-short", _SHORT247, totp=seed)
    long_id = _user247("p247-long", _LONG247, totp=seed)
    since = _last_id247()
    _ag247.reset_throttle()
    c = _p9_client(short_id)
    r = c.post("/account/2fa/disable", data={"password": _SHORT247, "totp_code": _CODES247["p247-short"][0]})
    said = _p9_flashes(c)
    eq("2fa off: a password under 15 characters is refused, 2FA stays on and the backup code is not spent",
       (r.status_code, _two_fa247(short_id)[:2], [m for m in said if "shorter than 15" in m][:1] != []),
       (302, (True, 2), True))
    eq("2fa off: ...and the refusal is audited", _audit247("2fa_disabled", since),
       [("refused: password shorter than 15 characters", False)])
    ok = _p9_client(long_id).post("/account/2fa/disable", data={"password": _LONG247,
                                                                     "totp_code": _CODES247["p247-long"][0]})
    with _p9.app_context():
        long_on = bool(_db247.session.get(_U247, long_id).totp_enabled)
    eq("2fa off: a 15+ character password with a backup code turns it off (control)", (ok.status_code, long_on),
       (302, False))
    _ag247.reset_throttle()


def _s247_admin_reset():
    target = _user247("p247-reset", _SHORT247, totp=_pyotp247.random_base32())
    r = _p9_client(P9_ADMIN).post("/users/%d/edit" % target, headers=_XHR247,
                                  data={"username": "p247-reset", "display_name": "p247-reset", "is_active": "on",
                                        "reset_2fa": "on"})
    j = _p9_json(r)
    state = _two_fa247(target)
    eq("2fa reset: an admin's 2FA reset also issues a new password (shown once) the account must change, so "
       "the short one allowed with 2FA no longer signs in", (r.status_code, bool((j.get("credential") or {})),
                                                             state[0], state[2], state[3]),
       (200, True, False, True, False))
    plain = _user247("p247-plain", _LONG247)
    r2 = _p9_client(P9_ADMIN).post("/users/%d/edit" % plain, headers=_XHR247,
                                   data={"username": "p247-plain", "display_name": "p247-plain", "is_active": "on",
                                         "reset_2fa": "on"})
    with _p9.app_context():
        u = _db247.session.get(_U247, plain)
        kept = (bool(u.must_change_password), _auth247.check_password(_LONG247, u.password_hash))
    eq("2fa reset: ticked for an account with no 2FA, nothing is reset (control)",
       (r2.status_code, bool(_p9_json(r2).get("credential")), kept), (200, False, (False, True)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The settings audit row names the 2FA requirement and session binding
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s247_settings_audit():
    saved = {"require_2fa": True, "session_protection": "strong"}
    keys = ("PERMANENT_SESSION_LIFETIME", "SESSION_ABSOLUTE_SECONDS", "REMEMBER_COOKIE_DURATION",
            "STEP_UP_MINUTES", "SESSION_PROTECTION", "REQUIRE_2FA")
    live = {k: _p9.config.get(k) for k in keys}
    form = {"session_idle_minutes": "30", "session_absolute_hours": "8", "remember_days": "3"}
    since = _last_id247()
    try:
        import panel.routes.admin_notifications as _an247
        _p9_patch(_an247, "update_config", lambda mutate: mutate(saved))
        _p9_patch(_an247, "load_config", lambda: dict(saved))
        _p9_client(P9_ADMIN).post("/settings/save", data=dict(form, session_protection="basic"))
        _p9.config.update(REQUIRE_2FA=False, SESSION_PROTECTION=live["SESSION_PROTECTION"])
        _p9_client(P9_ADMIN).post("/settings/save", data=dict(form, session_protection="basic", require_2fa="on"))
        _p9.config.update(REQUIRE_2FA=False, SESSION_PROTECTION=live["SESSION_PROTECTION"])
    finally:
        _p9.config.update(live)
        _p9_restore_all()
    details = [d for d, _s in _audit247("settings_update", since)]
    eq("settings audit: turning Require 2FA off and session binding strong -> basic are named; turning 2FA on "
       "again is named, and an unchanged binding is not", [[p for p in d.split("; ") if "2FA" in p or "protection"
                                                            in p] for d in details],
       [["require 2FA on -> off", "session protection strong -> basic"], ["require 2FA off -> on"]])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. tls-le-copy copies only a certificate the operator opened at install
# ════════════════════════════════════════════════════════════════════════════════════════════════
_spec247 = _ilu247.spec_from_loader("ph_tls247", _mach247.SourceFileLoader("ph_tls247", _helper_path))
_ph247 = _ilu247.module_from_spec(_spec247)
_spec247.loader.exec_module(_ph247)
_LE247 = os.path.join(_TMP247, "letsencrypt")
_PEM_CERT247 = b"-----BEGIN CERTIFICATE-----\nUDI0Nw==\n-----END CERTIFICATE-----\n"
_PEM_KEY247 = b"-----BEGIN PRIVATE KEY-----\nUDI0Nw==\n-----END PRIVATE KEY-----\n"


def _le_tree247(name):
    for sub in ("archive", "live"):
        os.makedirs(os.path.join(_LE247, sub, name), exist_ok=True)
    for fname, data in (("fullchain", _PEM_CERT247), ("privkey", _PEM_KEY247)):
        with open(os.path.join(_LE247, "archive", name, fname + "1.pem"), "wb") as fh:
            fh.write(data)
        link = os.path.join(_LE247, "live", name, fname + ".pem")
        if not os.path.lexists(link):
            os.symlink("../../archive/%s/%s1.pem" % (name, fname), link)


def _helper247(verb, args, timeout=30, merge_stderr=True):
    """system_ops._run_verb as the helper answers it, in this process."""
    saved = (sys.stdout, sys.stderr, sys.stdin)
    sys.stdout, sys.stderr, sys.stdin = _io247.StringIO(), _io247.StringIO(), _io247.StringIO("")
    try:
        rc = _ph247.main(["panel-helper", verb] + list(args))
        return sys.stdout.getvalue(), sys.stderr.getvalue(), rc
    finally:
        sys.stdout, sys.stderr, sys.stdin = saved


def _staged247():
    ssl = os.path.join(_TMP247, "data", "ssl")
    return sorted(os.listdir(ssl)) if os.path.isdir(ssl) else []


def _s247_le_names():
    _RESTARTS247.clear()
    for name in ("panel.example.com", "mail.example.org"):
        _le_tree247(name)
    os.makedirs(os.path.join(_TMP247, "data", "ssl"), mode=0o700, exist_ok=True)
    conf = {"data_dir": os.path.join(_TMP247, "data"), "tls_le_names": "other.example.net, panel.example.com"}
    try:
        _arm_tls247(None)
        _p9_patch(_ph247, "TLS_LE_ROOT", _LE247)
        _p9_patch(_ph247, "TLS_LE_OWNER", os.getuid())
        _p9_patch(_ph247, "panel_conf", lambda: dict(conf))
        refused = _helper247("tls-le-copy", ["mail.example.org"])
        refused_files = _staged247()
        copied = _helper247("tls-le-copy", ["panel.example.com"])
        copied_files = _staged247()
        for left in copied_files:
            os.unlink(os.path.join(_TMP247, "data", "ssl", left))
        conf.pop("tls_le_names")
        unrecorded = _helper247("tls-le-copy", ["panel.example.com"])[1:]
        conf["tls_le_names"] = "panel.example.com"
        _p9_patch(_own247, "fetch_letsencrypt", _REAL_FETCH247)
        _p9_patch(_so247, "_run_verb", _helper247)
        with _p9_client(P9_ADMIN) as c:
            r = c.post("/settings/tls/letsencrypt", data={"le_name": "mail.example.org"})
            said = _p9_flashes(c)
    finally:
        _p9_restore_all()
    eq("le names: the helper refuses a certificate panel.conf does not list, copying nothing; a listed one is copied",
       (refused[1:], refused_files, copied[0], copied_files),
       (("tls-le-copy: certificate not opened to the panel at install\n", 1), [], "COPIED",
        ["le-fullchain.pem", "le-privkey.pem"]))
    eq("le names: with no tls_le_names recorded at all, nothing is copied",
       unrecorded, ("tls-le-copy: certificate not opened to the panel at install\n", 1))
    eq("le names: through the route, the refusal says how to open it with the installer, and nothing restarts",
       (r.status_code, said[:1], _RESTARTS247),
       (302, [_own247.LE_NOT_OPENED.replace("{name}", "mail.example.org")], []))


def _s247_le_installer():
    with open(os.path.join(_root, "install.sh"), encoding="utf-8") as fh:
        ins = fh.read()
    i = ins.find("\n_b1_tls_le_names_choice() {")
    fn = ins[i + 1:ins.index("\n}\n", i) + 3] if i >= 0 else "_b1_tls_le_names_choice() { echo missing; }\n"
    conf = os.path.join(_TMP247, "b1-panel.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write("root_cron=no\ntls_le_names=a.example.com,b.example.org\n")
    script = fn + 'set -euo pipefail\n_b1_tls_le_names_choice "$1"\n'
    runs = []
    for extra in ({}, {"PANEL_TLS_LE_NAMES": "x.example.com, *,bad_name,x.example.com,y.example.net"},
                  {"PANEL_TLS_LE_NAMES": "none"}, {"PANEL_SELF_UPDATE": "1", "PANEL_TLS_LE_NAMES": "z.example.com"}):
        env = {k: v for k, v in os.environ.items() if k not in ("PANEL_TLS_LE_NAMES", "PANEL_SELF_UPDATE")}
        env.update(extra)
        r = _sp247.run(["bash", "-c", script, "b1", conf], capture_output=True, text=True, env=env, cwd=_TMP247)  # nosec B603 B607
        runs.append(r.stdout.strip())
    eq("le names installer: an unset PANEL_TLS_LE_NAMES keeps the record; a list is validated (no glob, no bad "
       "name, no repeat); none clears it; a run the panel started never takes it from the environment",
       runs, ["a.example.com,b.example.org", "x.example.com,y.example.net", "", "a.example.com,b.example.org"])
    check("le names installer: panel.conf is written with the tls_le_names= line the helper reads",
          "\\nroot_cron=%s\\ntls_le_names=%s\\n" in ins and '"${ROOT_CRON_CHOICE}" "${TLS_LE_NAMES}"' in ins
          and _ph247.TLS_LE_CONF_KEY == "tls_le_names")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A self-hosted control server's suffix is resolved by the lock-out guards
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s247_headscale():
    answers = {"vps.example.net": ["203.0.113.47"], "node.example.net": ["100.101.102.103"]}

    def _gai(host, *a, **k):
        if host not in answers:
            raise OSError("p247: no such name")
        return [(2, 1, 6, "", (ip, 0)) for ip in answers[host]]
    server = _NS247(host="vps.example.net", port=22, auth_method="key", is_local=False, username="root")
    try:
        _p9_patch(_ts247, "tailnet_suffix", lambda info=None: "example.net")
        _p9_patch(_ts247, "socket", _NS247(getaddrinfo=_gai, IPPROTO_TCP=6))
        _p9_patch(_hosts247, "_r28b_resolve", lambda h: sorted(answers.get(h, [])))
        got = {"host public": _hosts247._r28b_host_on_tailnet("vps.example.net"),
               "host tailnet": _hosts247._r28b_host_on_tailnet("node.example.net"),
               "host unresolved": _hosts247._r28b_host_on_tailnet("gone.example.net"),
               "host ts.net": _hosts247._r28b_host_on_tailnet("box.tail1234.ts.net"),
               "fw public": _fw247._fwa_is_tailnet_host("vps.example.net"),
               "fw tailnet": _fw247._fwa_is_tailnet_host("node.example.net"),
               "fw unresolved": _fw247._fwa_is_tailnet_host("gone.example.net"),
               "display name": _ts247.is_tailnet_name("vps.example.net")}
        refusal = _hosts247._r28b_panel_way_in_refusal(server)
    finally:
        _p9_restore_all()
    eq("headscale: a name under the self-hosted suffix is tailnet for the lock-out guards only when it resolves to "
       "tailnet addresses; unresolved is public; ts.net is still taken from the name; the display check is unchanged",
       got, {"host public": False, "host tailnet": True, "host unresolved": False, "host ts.net": True,
             "fw public": False, "fw tailnet": True, "fw unresolved": False, "display name": True})
    check("headscale: removing public SSH from a host the panel dials at that public name is refused",
          refusal is not None and "connects to this host at" in str(refusal), repr(refusal))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The re-encryption pass: ciphertext columns only, and the backup's keys kept
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _v1_247(fkey, text):
    return "enc:v1:" + _Fernet247(fkey).encrypt(text.encode()).decode()


def _rig247(tag):
    """A fresh key file, config.json and database under the temp dir: (app, Fernet key, db file)."""
    folder = _pl247.Path(_TMP247) / tag
    folder.mkdir()
    _p9_patch(_cfg247, "CRED_KEY_FILE", folder / "cred_key")
    _p9_patch(_cfg247, "CONFIG_FILE", folder / "config.json")
    _cfg247._cfg_cache["key"] = None
    fkey = _Fernet247.generate_key()
    (folder / "cred_key").write_bytes(fkey)
    (folder / "config.json").write_text("{}")
    app = _Flask247("p247" + tag)
    dbf = str(folder / "p.db")
    app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///" + dbf, SQLALCHEMY_TRACK_MODIFICATIONS=False)
    _db247.init_app(app)
    with app.app_context():
        _db247.create_all()
    return app, fkey, dbf


def _exec247(app, sql, **params):
    with app.app_context():
        _db247.session.execute(_db247.text(sql), params)
        _db247.session.commit()


def _passes247(app, n=2):
    out = []
    for _i in range(n):
        with app.app_context():
            out.append(_ar247.reencrypt_pass(prune=True))
    return out


def _s247_scan_columns():
    try:
        app, _fkey, _dbf = _rig247("cols")
        with app.app_context():
            _db247.session.add(_U247(username="p247cols", password_hash="x", display_name="plain"))
            _db247.session.commit()
        # A display name anyone may type, shaped like a Fernet value no key opens.
        _exec247(app, "UPDATE user SET display_name = :d", d=_v1_247(_Fernet247.generate_key(), "p247"))
        tallies = _passes247(app)
        ring = _cfg247._cred_keyring()
        cols = set((t, c) for t, _pk, c in _ar247._text_columns())
    finally:
        _p9_restore_all()
        _cfg247._cfg_cache["key"] = None
    eq("at rest: a display name shaped like ciphertext is not read as a stored secret: nothing unreadable, and the "
       "Fernet key is pruned after two passes", ([t.unreadable for t in tallies], ring.fernet), ([0, 0], []))
    eq("at rest: the scan reads the named secret columns and the EncryptedString ones, not typed text",
       [(t, c) in cols for t, c in (("user", "email"), ("user", "totp_secret"), ("remote_server", "auth_credential"),
                                    ("remote_server", "host"), ("user_session", "ip"), ("user", "display_name"),
                                    ("audit_log", "username"))], [True] * 5 + [False] * 2)


def _encrypt_targets247():
    """Every attribute or keyword a panel module assigns encrypt_secret(...) to: {(file, name)}."""
    found = set()
    base = os.path.join(_root, "panel")
    for folder, _dirs, files in os.walk(base):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(folder, f)
            with open(path, encoding="utf-8") as fh:
                tree = _ast247.parse(fh.read())
            found |= {(os.path.relpath(path, base), n) for n in _targets_in247(tree)}
    return found


def _calls_encrypt247(node):
    return any(isinstance(n, _ast247.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "encrypt_secret"
               for n in _ast247.walk(node))


def _assign_targets247(node):
    """The attribute names an Assign gives an encrypt_secret(...) value (tuple assignments matched up)."""
    out = set()
    for tgt in node.targets:
        pairs = (list(zip(tgt.elts, node.value.elts)) if isinstance(tgt, _ast247.Tuple)
                 and isinstance(node.value, _ast247.Tuple) else [(tgt, node.value)])
        out |= {t.attr for t, v in pairs if isinstance(t, _ast247.Attribute) and _calls_encrypt247(v)}
    return out


def _targets_in247(tree):
    out = set()
    for node in _ast247.walk(tree):
        if isinstance(node, _ast247.Assign):
            out |= _assign_targets247(node)
        elif isinstance(node, _ast247.Call) and getattr(node.func, "id", "") != "dict":
            out |= {k.arg for k in node.keywords if k.arg and _calls_encrypt247(k.value)}
    return out


def _s247_secret_columns_listed():
    named = {c for cols in _ar247.SECRET_COLUMNS.values() for c in cols}
    targets = _encrypt_targets247()
    with _p9.app_context():
        tables = {t.name: {c.name for c in t.columns} for t in _db247.metadata.sorted_tables}
    eq("at rest: every column the panel writes with encrypt_secret is in SECRET_COLUMNS (the scan reads it)",
       sorted((f, n) for f, n in targets if n not in named), [])
    eq("at rest: every SECRET_COLUMNS entry is a real column", sorted((t, c) for t, cols in _ar247.SECRET_COLUMNS.items()
                                                                   for c in cols if c not in tables.get(t, ())), [])
    check("at rest: the AST scan finds the known writers (control)",
          {("routes/remotes.py", "auth_credential"), ("routes/databases.py", "admin_secret")} <= targets,
          repr(sorted(targets)[:12]))


def _s247_backup_keeps_key():
    try:
        app, fkey, dbf = _rig247("bkp")
        with app.app_context():
            _db247.session.add(_U247(username="p247bkp", password_hash="x"))
            _db247.session.commit()
        _exec247(app, "UPDATE user SET email = :e", e=_v1_247(fkey, "p247@example.invalid"))
        _sh247.copyfile(dbf, dbf + ".backup")       # the rolling copy, taken before the re-encryption
        kept = _passes247(app, 3)
        held = _cfg247._cred_keyring().fernet
        with open(dbf + ".backup", "wb") as fh:
            fh.write(b"not a database at all")
        _passes247(app, 2)
        unreadable = _cfg247._cred_keyring().fernet
        os.unlink(dbf + ".backup")
        _passes247(app, 2)
        gone = _cfg247._cred_keyring().fernet
    finally:
        _p9_restore_all()
        _cfg247._cfg_cache["key"] = None
    eq("at rest: the prune keeps a key panel.db.backup still uses, and one an unreadable backup might; with no "
       "backup it goes (two passes)", ([t.rewritten for t in kept], held == [fkey.decode()],
                                       unreadable == [fkey.decode()], gone), ([1, 0, 0], True, True, []))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The update rollback keeps the breached-password list
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s247_rollback_list():
    with open(os.path.join(_root, "install.sh"), encoding="utf-8") as fh:
        ins = fh.read()
    block = ins[ins.find("    # ── Health check FAILED"):]
    line = next((ln for ln in block.split("\n") if 'find "${PANEL_DIR}/data"' in ln), "false")
    tree = os.path.join(_TMP247, "rb")
    os.makedirs(os.path.join(tree, "data", ".backups"))
    for name in ("panel.db", "common-passwords-100k.txt", "config.json"):
        with open(os.path.join(tree, "data", name), "w", encoding="utf-8") as fh:
            fh.write("p247")
    _sp247.run(["bash", "-c", line.strip(), "b1"], env=dict(os.environ, PANEL_DIR=tree), check=False)  # nosec B603 B607
    eq("rollback: wiping data/ before the snapshot is unpacked keeps .backups and the breached-password list (the "
       "snapshot leaves the list out)", sorted(os.listdir(os.path.join(tree, "data"))),
       [".backups", "common-passwords-100k.txt"])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. sign-release saves a release's name only once its GitHub release exists
# ════════════════════════════════════════════════════════════════════════════════════════════════
_FAKEGH247 = r"""
printf '%s\n' "$*" >> "$FAKEGH_LOG"
if [ "$1" = release ] && [ "$2" = view ]; then exit 1; fi
if [ "$1" = release ] && [ "$2" = create ]; then
    [ "${FAKEGH_CREATE_RC:-0}" = 0 ] || exit "$FAKEGH_CREATE_RC"
    git --git-dir "$FAKEGH_BARE" tag "$3" "$5"
fi
exit 0
"""


def _git247(*a, **k):
    return _run142(["git", *a], **k).stdout.strip()


def _sign_repo247():
    sb = os.path.join(_TMP247, "sign")
    os.makedirs(sb)
    key = os.path.join(sb, "relkey")
    _run142(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key])
    with open(key + ".pub", encoding="utf-8") as fh:
        pub = "release " + " ".join(fh.read().split()[:2]) + "\n"
    bare, dev = os.path.join(sb, "rel.git"), os.path.join(sb, "dev")
    _git247("init", "-q", "--bare", "-b", "main", bare)
    _git247("clone", "-q", bare, dev)
    os.makedirs(os.path.join(dev, "panel", "install"))
    os.makedirs(os.path.join(dev, "docs"))
    with open(os.path.join(dev, "panel", "install", "release-signers"), "w", encoding="utf-8") as fh:
        fh.write(pub)
    with open(os.path.join(dev, "docs", "CHANGELOG.md"), "w", encoding="utf-8") as fh:
        fh.write("# Changelog\n")
    _git247("-C", dev, "config", "gpg.format", "ssh")
    _git247("-C", dev, "config", "user.signingkey", key + ".pub")
    gh = os.path.join(sb, "fakegh.sh")
    with open(gh, "w", encoding="utf-8") as fh:
        fh.write(_FAKEGH247)
    return sb, key, bare, dev, gh


def _commit247(dev, n):
    with open(os.path.join(dev, "panel", "x%d.py" % n), "w", encoding="utf-8") as fh:
        fh.write("X = %d\n" % n)
    _git247("-C", dev, "add", ".")
    _git247("-C", dev, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "c%d" % n)
    _git247("-C", dev, "push", "-q", "origin", "main")
    return _git247("-C", dev, "rev-parse", "HEAD")


def _sign247(rig, sha, **extra):
    sb, key, _bare, dev, gh = rig
    env = dict(_ENV142, SIGN_RELEASE_KEY=key, FAKEGH_LOG=os.path.join(sb, "gh.log"), FAKEGH_BARE=rig[2],
               SIGN_RELEASE_GH="bash %s" % _shlex247.quote(gh), **extra)
    return _run142(["bash", os.path.join(_root, "tools", "sign-release.sh"), "--yes", sha], cwd=dev, env=env,
                   input="")


def _named247(rig, sha):
    """(signature on release-signatures, the saved name) for `sha`."""
    bare = rig[2]
    sig = _run142(["git", "--git-dir", bare, "cat-file", "-e", "release-signatures:main/%s.sig" % sha]).returncode == 0
    name = _run142(["git", "--git-dir", bare, "show", "release-signatures:main/%s.name" % sha])
    return sig, (name.stdout.strip() if name.returncode == 0 else None)


def _s247_sign_release():
    if not (_sh247.which("ssh-keygen") and _sh247.which("git")):
        skip("sign-release: the release name", "git or ssh-keygen is not installed")
        return
    rig = _sign_repo247()
    a = _commit247(rig[3], 1)
    r_a = _sign247(rig, a, SIGN_RELEASE_NO_RELEASE="1")
    b = _commit247(rig[3], 2)
    r_b = _sign247(rig, b, FAKEGH_CREATE_RC="1")
    b_failed = _named247(rig, b)
    r_b2 = _sign247(rig, b)
    eq("sign-release: no release (SIGN_RELEASE_NO_RELEASE, or a create that failed) saves no name beside the "
       "signature", [r_a.returncode, _named247(rig, a), r_b.returncode, b_failed], [0, (True, None), 0, (True, None)])
    b_named = _named247(rig, b)
    check("sign-release: a re-run that publishes the release adds its name, the tag it was published under",
          r_b2.returncode == 0 and b_named[0] and bool(b_named[1]) and "named (%s)" % b_named[1] in r_b2.stdout,
          "%s | %s | %s" % (b_named, r_b2.stdout[-300:], r_b2.stderr[-300:]))
    c = _commit247(rig[3], 3)
    r_c = _sign247(rig, c)
    c_named = _named247(rig, c)
    check("sign-release: a release published on the first run is named in the same signature commit, the next "
          "free name of that day (.2 after the release above)",
          r_c.returncode == 0 and c_named[0] and bool(b_named[1]) and c_named[1] == b_named[1] + ".2",
          "%s %s | %s" % (b_named, c_named, r_c.stderr[-300:]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. The debug report's game-account labels and the world reset's names-only lines
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _s247_debug_labels():
    bodies = {"cron runner": "mkdir -p /home/s/.p && chmod 700 /home/s/.p",
              "lgsm action": "cd /home/s && ./mcserver start",
              "backup prune": "find -H /home/s/lgsm/backup -name x | xargs -0 -r rm -f --"}
    labels = {}
    for k, b in bodies.items():
        sh = _core247.GAME_SHELL_CWD + b
        line = ("Oct 03 05:01:01 box7731 sudo[2301]:   ubuntu : PWD=/home/ubuntu ; USER=mcsrv7731 ; "
                "COMMAND=/usr/bin/bash -c %s" % sh)
        _kept, verbs, _s = _lg247._split_priv([line])
        labels[k] = sorted((verbs.get(_lg247.GAME_ACCOUNT) or {}).keys())
    eq("debug report: with the shell's own `cd / || exit;` lead, a body with `&&` and no cd of its own is 'other', "
       "a LinuxGSM action still is one, and the backup prune keeps its label",
       labels, {"cron runner": ["other"], "lgsm action": ["LinuxGSM action"], "backup prune": ["backup prune"]})


def _s247_world_reset_lines():
    texts = ['executabledir="/srv/a"\nother="%s"\n' % v for v in
             ("${y:executabledir=2:1}", "$[executabledir=2]", "${A[executabledir=1]}", "executabledir=2",
              "-executabledir ${executabledir}", "$executabledir/x")]
    got = [_wr247.cfg_values([t], ["executabledir"])[0] for t in texts]
    eq("world reset: a line that can set the key by arithmetic (an offset, $[ ], a subscript) or holds `key=` text "
       "is refused; one that only names or expands it is read (control)", got,
       [None, None, None, None, {"executabledir": "/srv/a"}, {"executabledir": "/srv/a"}])


def _cleanup247():
    with _p9.app_context():
        for uid in _IDS247:
            u = _db247.session.get(_U247, uid)
            if u is not None:
                _db247.session.delete(u)
        _db247.session.commit()


try:
    _s247_tls_routes()
    _s247_tls_renew()
    _s247_disable_short()
    _s247_admin_reset()
    _s247_settings_audit()
    _s247_le_names()
    _s247_le_installer()
    _s247_headscale()
    _s247_scan_columns()
    _s247_secret_columns_listed()
    _s247_backup_keeps_key()
    _s247_rollback_list()
    _s247_sign_release()
    _s247_debug_labels()
    _s247_world_reset_lines()
finally:
    _p9_restore_all()
    _cleanup247()
    _sh247.rmtree(_TMP247, ignore_errors=True)
check("part247: nothing in this part reached a real transport (part12's tripwire)", len(_P9_TRIPPED) == _trips247)
