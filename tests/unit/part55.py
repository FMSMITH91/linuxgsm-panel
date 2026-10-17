"""Part 55 of the unit suite: the second 2026-10-11 review's fixes (builder B).

Game files, the debug report, the privileged helper and routes:

* LinuxGSM configs: a value posted unchanged from secrets-<instance>.cfg is not copied into the
  plaintext instance cfg, and the Alerts card posts only the fields the user changed (run in node).
* GMod content: the install flow mounts content already on the host as well as content it fetched,
  and takes the one-content-job-per-host claim every Content-card job takes.
* Debug report: a sudo line of sudo's shape that nothing parsed is cut, not printed whole (an
  unknown refusal reason, `;` inside a value, HOST=/CWD= fields, a line split before COMMAND=,
  sudo's JSON format); an unreadable config.json is said in the Backups section, not its defaults;
  a quoted secret value is redacted whole.
* Helper: a later rule for another Runas does not take a root grant back; a negated host, a
  withdrawal through a Cmnd_Alias, a trailing PASSWD tag and a sudoers.d file no includedir names
  do not make the caller root-capable.
* Routes: the Alerts save and the log-timestamps switch ask the write refusal the settings form
  asks; a file named like the guard's sentinel does not make a folder "outside the home".

HOW IT RUNS. On part12's Flask app and stubs, as part52 does: every host command runs in a REAL
bash over a throwaway home (/home/<account> rewritten to it); nothing reaches a transport.
"""
import contextlib as _ctx55
import io as _io55
import os
import pwd as _pwd55
import shutil as _shutil55
import subprocess as _sp55  # nosec B404 - runs bash on the commands this part's code builds
import tempfile as _tf55
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part05 import _helper, _root
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sf, _p9_sh, _p9_so, _p9_trip)
from unit.part47 import _cut47, _node47
from panel.core import config as _cfg55
from panel.db.models import GameServer, RemoteServer, User, db
from panel.ops import backup as _bk55
from panel.ops.debug_report import _base as _base55
from panel.ops.debug_report import data as _data55
from panel.ops.debug_report import logs as _logs55
from panel.ops.ssh_manager import files as _files55
from panel.ops.ssh_manager import gmod as _gmod55
from panel.security import auth as _auth55

_TRIP55_START = len(_P9_TRIPPED)
_USER55 = "r12b55"
_SELF55 = "csgoserver"
_HOME55 = os.path.realpath(_tf55.mkdtemp(prefix="lgsm-unit-p55-home-"))
_CFGDIR55 = "lgsm/config-lgsm/%s" % _SELF55
_mine55 = {"hosts": [], "servers": [], "users": []}


def _bash55(server, user, sh, timeout=30, selfname=None, scope=False):
    """shell_as_game_user, in a real bash, with /home/<account> pointing at the throwaway home."""
    p = _sp55.run(["bash", "-c", sh.replace("/home/" + _USER55, _HOME55)],  # nosec B603 B607 - bash on this part's own command
                  capture_output=True, text=True, timeout=60, check=False)
    return p.stdout, p.stderr, p.returncode


def _write55(rel, text):
    path = os.path.join(_HOME55, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _reset55():
    for name in os.listdir(_HOME55):
        p = os.path.join(_HOME55, name)
        if os.path.islink(p) or not os.path.isdir(p):
            os.unlink(p)
        else:
            _shutil55.rmtree(p)
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()


def _arm55():
    _p9_arm(who="part55")
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash55)
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})


def _setup55():
    with _p9.app_context():
        r = RemoteServer(name="p55-host", host="192.0.2.155", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p55-" + _USER55, short_name=_USER55, game_type="csgo",
                        port=27555, installed=True, status="offline")
        admin = User(username="p55_admin", password_hash=_auth55.hash_password("Str0ng!passw0rd-p55"),
                     display_name="p55 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gs, admin])
        db.session.commit()
        _mine55["hosts"].append(r.id)
        _mine55["servers"].append(gs.id)
        _mine55["users"].append(admin.id)
        return gs.id, admin.id


def _cleanup55():
    with _p9.app_context():
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine55[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()
    _shutil55.rmtree(_HOME55, ignore_errors=True)


# ── A04: secrets stay in the secrets files ──────────────────────────────────────────────────────
def _secrets_copy55():
    _reset55()
    _write55(_CFGDIR55 + "/%s.cfg" % _SELF55, 'port="27015"\n')
    _write55(_CFGDIR55 + "/secrets-%s.cfg" % _SELF55, 'discordwebhook="https://real"\n')
    written = []
    _p9_patch(_files55, "_write_file_as_user",
              lambda s, u, p, b, selfname=None: (written.append(b.decode()), (True, ""))[1])
    ok, _msg = _files55.lgsm_write_config(NS(), _USER55, _SELF55,
                                          {"discordwebhook": "https://real", "emailalert": "on"})
    check("lgsm_write_config: a value posted unchanged from secrets-<instance>.cfg is not copied "
          "into the plaintext instance cfg (the other key is still written)",
          ok is True and len(written) == 1 and "https://real" not in written[0]
          and 'emailalert="on"' in written[0], repr((ok, written)))
    del written[:]
    ok, _msg = _files55.lgsm_write_config(NS(), _USER55, _SELF55, {"discordwebhook": "https://real"})
    check("lgsm_write_config: ...and a save of nothing but that value writes nothing at all",
          ok is True and written == [], repr((ok, written)))


def _save_alerts55():
    with open(os.path.join(_root, "static", "js", "server_files.js"), encoding="utf-8") as fh:
        src = fh.read()
    prog = (
        "global.MOUNT = ''; global.serverId = 1;\n"
        "function el(a, extra){ return Object.assign({getAttribute: k => (k in a ? a[k] : null),"
        " hasAttribute: k => k in a, setAttribute: (k, v) => { a[k] = v; }}, extra); }\n"
        "const toggles = [el({'data-alert-toggle': 'discordalert', 'data-orig': 'on'}, {checked: true}),"
        " el({'data-alert-toggle': 'emailalert', 'data-orig': 'off'}, {checked: true})];\n"
        "const keys = [el({'data-alert-key': 'discordwebhook', 'data-orig': 'https://secret'},"
        " {value: 'https://secret'}), el({'data-alert-key': 'emailaddress', 'data-orig': ''},"
        " {value: ' a@b.c '})];\n"
        "global.document = {getElementById: () => null, querySelectorAll: s =>"
        " s === '[data-alert-toggle]' ? toggles : s === '[data-alert-key]' ? keys : toggles.concat(keys)};\n"
        "const posted = [];\n"
        "global.fetch = (u, o) => { posted.push(JSON.parse(o.body).values);"
        " return Promise.resolve({json: () => Promise.resolve({success: true})}); };\n"
        + _cut47(src, "function alertsMsg(") + "\n" + _cut47(src, "function saveAlerts(") + "\n"
        "(async () => { saveAlerts(null); for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));"
        " saveAlerts(null); for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));"
        " console.log(JSON.stringify(posted)); })();\n")
    out = _node47(prog)
    if out is None:
        skip("alerts card: Save posts only the fields the user changed", "node is not installed here")
        return
    check("alerts card: Save posts only the fields the user changed (an unchanged webhook read "
          "from a secrets file is not posted back), and a second Save posts nothing",
          out == [{"emailalert": "on", "emailaddress": "a@b.c"}], repr(out))


# ── A04/A08: the install's GMod content step ────────────────────────────────────────────────────
def _gmod_install55():
    mounted, held = [], []
    outcomes = {"cstrike": "already", "tf": "unchecked"}
    _p9_patch(_gmod55, "_install_content_game", lambda server, cu, g, on_progress: (
        held.append(_p9_sf._claim_gmod_content_host(-55)), outcomes[g])[1])
    _p9_patch(_gmod55, "ensure_content_update_cron", lambda server, cu: True)
    # The content scan came back empty, so ensure_content_user fell back with `present: {}`.
    _p9_patch(_p9_ms, "ensure_content_user", lambda remote: {"user": "gmodcontent", "present": {}})
    _p9_patch(_p9_ms, "gmod_mount_setup",
              lambda remote, short, cu, games: (mounted.append(list(games)), (True, "ok"))[1])
    job = NS(short_name="gm55", game_type="gmod", content_games=["cstrike", "tf"],
             p=lambda *a, **k: None)
    with _p9.app_context():     # the install job runs its steps inside one (the owner lookup reads the DB)
        step = _p9_ms._install_gmod_content(job, NS(name="p55-host", id=-55))
    check("gmod install: a game the content step found already on the host is mounted (the scan "
          "came back empty); one it could not check is not",
          mounted == [["cstrike"]] and step == 9, repr((mounted, step)))
    check("gmod install: the content step holds the host's content claim while it runs, and lets "
          "it go after", held and not any(held) and _p9_sf._claim_gmod_content_host(-55),
          repr(held))
    _p9_sf._release_gmod_content_host(-55)
    del mounted[:]
    _p9_sf._claim_gmod_content_host(-55)          # a Content-card job is running on this host
    try:
        with _p9.app_context():
            step = _p9_ms._install_gmod_content(job, NS(name="p55-host", id=-55))
    finally:
        _p9_sf._release_gmod_content_host(-55)
    check("gmod install: with another content job running on the host, the step downloads and "
          "mounts nothing (it is best-effort) and the install goes on",
          mounted == [] and step == 9, repr((mounted, step)))


# ── A06: sudo lines that nothing parsed ─────────────────────────────────────────────────────────
def _sudo_fail_closed55():
    pre = "Oct 11 10:00:00 h sudo[1]: bob : "
    leaks = [pre + "user NOT authorized on host ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
                   "COMMAND=/usr/bin/mysql -u root -pS3cretPass",
             pre + "setid command rejected in intercept mode ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
                   "COMMAND=/usr/bin/x secretA",
             pre + "a reason of the operator's own ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
                   "COMMAND=/usr/bin/x secretB",
             pre + "TTY=pts/0 ; PWD=/home/bob ; USER=root ; ENV=DB_PASS=a;secretC ; COMMAND=/usr/bin/x",
             pre + "3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
                   "ENV=DB_PASS=secretD" + "x" * 1100,
             pre + "TTY=pts/0 ; PWD=/home/bob ; USER=root ; ENV=DB_PASS=secretE" + "y" * 3000
                 + " ; COMMAND=/usr/bin/x",
             "Oct 11 10:00:00 h sudo[1]: @cee:{\"sudo\":{\"accept\":{\"command\":\"/usr/bin/x\","
             "\"runargv\":[\"x\",\"secretF\"]}}}"]
    kept, _verbs, _s = _logs55._split_priv(leaks)
    text = "\n".join(kept)
    check("debug report: a sudo line of sudo's shape that the parser does not account for keeps no "
          "argv or ENV= value (an unknown refusal, `;` in ENV=, a line split before COMMAND=, JSON)",
          len(kept) == len(leaks) and not any(t in text for t in (
              "S3cretPass", "secretA", "secretB", "secretC", "secretD", "secretE", "secretF")),
          repr([k[-90:] for k in kept]))
    ok = [pre + "HOST=box ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/true",
          pre + "TTY=pts/0 ; CWD=/srv ; USER=root ; COMMAND=/usr/bin/true"]
    kept, verbs, _s = _logs55._split_priv(ok)
    check("debug report: a successful sudo line with a HOST= or CWD= field is counted, not printed",
          kept == [] and verbs == {"true as root": 2}, repr((kept, verbs)))
    plain = ["Oct 11 10:00:00 h app[1]: WARNING something failed ; USER=nobody here"]
    kept, _verbs, _s = _logs55._split_priv(plain)
    check("debug report: ...while a line that is not sudo's is kept whole (control)",
          kept == plain, repr(kept))


# ── A06: the Backups section on an unreadable config.json ───────────────────────────────────────
def _backups_unreadable55():
    _p9_patch(_bk55, "load_config", lambda *a, **k: _cfg55.UnreadableConfig({}))
    res = _base55.Result()
    _data55._settings_line(res)
    _data55._r12b_manual_line(res)
    text = "\n".join(res.lines)
    fails = [f for f in res.findings if "fail" in repr(f)]
    check("debug report backups: an unreadable config.json is said, with backups refused, not "
          "printed as 'enabled · encryption off' (and the manual run is not 'never run')",
          "could not be read" in text and "encryption off" not in text and "never run" not in text
          and len(fails) == 1, repr((res.lines, res.findings)))


def _redact_quoted55():
    red = _p9_so._redact('{"password": "correct horse battery", "user": "bob"} '
                         "{'token': 'zz9 yy8'} password=plain next")
    check("redaction: a quoted secret value is redacted whole, not to its first blank",
          not any(v in red for v in ("correct", "horse", "battery", "zz9", "yy8", "plain"))
          and '"user": "bob"' in red and "next" in red, red)


# ── A07: who reaches root, as the helper reads sudoers ──────────────────────────────────────────
def _reach55():
    tmp = _tf55.mkdtemp(prefix="lgsm-unit-p55-sudo-")
    caller = _pwd55.getpwuid(os.getuid()).pw_name
    saved = (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of)
    try:
        main = os.path.join(tmp, "sudoers")
        ddir = os.path.join(tmp, "sudoers.d")
        os.makedirs(ddir)
        _helper.SUDOERS_FILE, _helper.SUDOERS_DIR = main, ddir
        _helper._groups_of = lambda _n: set()

        def reach(main_text, files, include=True):
            with open(main, "w", encoding="utf-8") as fh:
                fh.write(main_text + ("@includedir %s\n" % ddir if include else ""))
            for n in os.listdir(ddir):
                os.unlink(os.path.join(ddir, n))
            for n, t in files.items():
                with open(os.path.join(ddir, n), "w", encoding="utf-8") as fh:
                    fh.write(t)
            with _ctx55.redirect_stderr(_io55.StringIO()):
                return _helper._caller_reaches_root(caller)

        grant = "%s ALL=(ALL) NOPASSWD: ALL\n" % caller
        got = {"install.sh layout": reach("", {"90-cloud": grant, "linuxgsm-panel":
                                               "%s ALL=(%%lgsmpanel-games) NOPASSWD: ALL\n" % caller}),
               "later root rule": reach("", {"90-cloud": grant, "linuxgsm-panel":
                                             "%s ALL=(root) ALL\n" % caller})}
        check("helper: install.sh's own `(%lgsmpanel-games) NOPASSWD: ALL` line after a real root "
              "grant does not take the grant back; a later rule as root still does (control)",
              got == {"install.sh layout": True, "later root rule": False}, repr(got))
        got = {"negated host": reach("%s ALL,!%s=(ALL) NOPASSWD: ALL\n" % (caller, _helper.socket.gethostname()), {}),
               "alias withdrawal": reach(grant + "Cmnd_Alias EVERY = ALL\n%s ALL=(ALL) PASSWD: EVERY\n"
                                         % caller, {}),
               "PASSWD last": reach("%s ALL=(ALL) NOPASSWD: PASSWD: ALL\n" % caller, {}),
               "no includedir": reach("", {"lgsmpanel-full": grant}, include=False),
               "plain": reach(grant, {})}
        check("helper: a grant whose host list negates a host, a later PASSWD through a Cmnd_Alias, "
              "a trailing PASSWD tag, a sudoers.d file no includedir reads — none is root; the "
              "plain grant is (control)",
              got == {"negated host": False, "alias withdrawal": False, "PASSWD last": False,
                      "no includedir": False, "plain": True}, repr(got))
    finally:
        (_helper.SUDOERS_FILE, _helper.SUDOERS_DIR, _helper._groups_of) = saved
        _shutil55.rmtree(tmp, ignore_errors=True)


# ── A08: writes that ask the refusal, and the guard's sentinel ──────────────────────────────────
def _write_refusals55(client, sid):
    writes = []
    _p9_patch(_p9_sf, "lgsm_write_config", lambda *a, **k: (writes.append(a[3]), (True, ""))[1])
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {u: "is in the sudo group" for u in users})
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()
    ra = client.post("/api/server/%d/alerts" % sid, json={"values": {"emailalert": "on"}})
    rt = client.post("/api/server/%d/log-timestamps" % sid, json={"enabled": False})
    check("alerts / log timestamps: a write to the instance cfg as a root-capable account is refused, "
          "as the settings form's is",
          ra.status_code == 409 and rt.status_code == 409 and writes == []
          and (_p9_json(rt).get("error") or ""), repr((ra.status_code, rt.status_code, writes)))
    _p9_patch(_p9_sh, "privileged_accounts", lambda remote, users: {})
    with _p9_sh._ACCOUNT_VERDICTS_LOCK:
        _p9_sh._ACCOUNT_VERDICTS.clear()
    ra = client.post("/api/server/%d/alerts" % sid, json={"values": {"emailalert": "on"}})
    rt = client.post("/api/server/%d/log-timestamps" % sid, json={"enabled": False})
    check("alerts / log timestamps: ...and both still save for a plain game account (control)",
          ra.status_code == 200 and rt.status_code == 200
          and writes == [{"emailalert": "on"}, {"logtimestamp": "off"}],
          repr((ra.status_code, rt.status_code, writes)))


def _sentinel_name55():
    _reset55()
    _write55("cfgs/__OUTSIDE_HOME__", "x\n")
    _write55("cfgs/a.cfg", "y\n")
    got = _files55.browse_dir(NS(), _USER55, "cfgs", _SELF55)
    names = sorted(e.get("name") for e in (got or {}).get("entries") or [])
    check("browse: a folder holding a file named like the guard's sentinel still lists",
          not (got or {}).get("outside_home") and names == ["__OUTSIDE_HOME__", "a.cfg"], repr(got))
    os.symlink("/", os.path.join(_HOME55, "root"))
    got = _files55.browse_dir(NS(), _USER55, "root", _SELF55)
    check("browse: ...while a folder that links outside the home is still refused (control)",
          bool((got or {}).get("outside_home")), repr(got)[:200])


try:
    _arm55()
    _S55, _ADMIN55 = _setup55()
    _A55 = _p9_client(_ADMIN55)
    _secrets_copy55()
    _save_alerts55()
    _gmod_install55()
    _sudo_fail_closed55()
    _backups_unreadable55()
    _redact_quoted55()
    _reach55()
    _write_refusals55(_A55, _S55)
    _sentinel_name55()
finally:
    _p9_restore_all()
    _cleanup55()

check("part55: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP55_START, repr(_P9_TRIPPED[_TRIP55_START:][:6]))
