"""Part 239 of the unit suite: Settings -> Schedules, and the panel owner's root cron page.

1. Root's crontab grammar: privileged.py and the helper accept and refuse the same lines; a job's
   schedule is cron's own five fields or an @keyword, with no control character in any line.
2. The two verbs: the helper refuses both unless panel.conf records root_cron=yes; its write
   refuses a bad line (rc 2) and a crontab changed since it was read (rc 3), and installs the rest
   through `crontab -u root -`; the remote shell forms, run under bash with a stand-in crontab,
   print what the helper prints and write only while the digest matches.
3. The routes: the page, a change and the switch are the panel owner's only (another superadmin
   gets 403 and an access_denied row); off by default; every change needs the password in the
   request; a change is written with the page's digest and audited old -> new; a stale line, a bad
   schedule or a host not opened at install writes nothing.
4. Schedules: the backup time, the OS check's time and switch, and the update interval are parsed
   from the viewer's zone, stored in UTC and audited; the backup tick and the OS check follow them.
5. Text: every new sentence in Spanish and French; install.sh records the choice under the key the
   helper reads.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a recorder.
The helper runs in-process with stand-ins, and the shell forms run under bash in a throwaway
directory with a stand-in `crontab` on PATH. Nothing reaches a host, root's crontab or data/.
"""
import atexit as _atexit239
import base64 as _b64239
import hashlib as _hl239
import io as _io239
import json as _json239
import os
import shutil as _shutil239
import subprocess as _sp239  # nosec B404 - bash over the panel's own shell forms, in a throwaway dir
import sys
import tempfile as _tf239
import time as _time239

from unit.part01 import check, eq
from unit.part05 import _helper as _h239, _root
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_patch, _p9_restore_all)
from panel.core import config as _cfg239
from panel.db.models import User as _U239, db as _db239
from panel.ops import backup as _bk239
from panel.ops.ssh_manager import _core as _core239
from panel.ops.ssh_manager import cron as _cron239
from panel.routes import account_security as _as239
from panel.routes import os_updates as _osu239
from panel.security import privileged as _pv239
from panel.services import root_cron as _rc239
from panel.services import schedules as _sc239

_trips239 = len(_P9_TRIPPED)
_TMP239 = _tf239.mkdtemp(prefix="p239-")
_atexit239.register(_shutil239.rmtree, _TMP239, True)
_GOOD239 = "p239-" + "right-one"
_BAD239 = "p239-" + "wrong-one"


# ── 1. the grammar, in both copies ────────────────────────────────────────────────────────────────
_LINES239 = {
    "": True, "   ": True, "# a comment": True, "MAILTO=root": True, "PATH = /usr/bin:/bin": True,
    "*/5 * * * * /usr/bin/true": True, "0 3 * * sun /x": True, "1-10/2,30 0-23 1 jan 7 echo \\%": True,
    "@reboot /usr/local/bin/x": True, "@daily  x": True, "\t0\t0\t*\t*\t*\tx": True,
    "@reboot": False, "@foo x": False, "@REBOOT x": False, "60 * * * * x": False, "* 24 * * * x": False,
    "5/10 * * * * x": False, "* * * * *": False, "* * 0 * * x": False, "* * * jan-feb * x": False,
    "* * * * * x\x1b": False, "*/0 * * * * x": False, "10-5 * * * * x": False, "* * * * * x\r": False,
    "* * * * 8 x": False, "1 2 3": False, "x" * 4097: False,
}


def _grammar239():
    got = {line: (bool(_pv239.root_cron_line_kind(line)), bool(_h239.root_cron_line_kind(line)))
           for line in _LINES239}
    eq("root cron grammar: each line is read as expected by privileged.py and by the helper alike",
       {k[:30]: v for k, v in got.items() if v != (_LINES239[k], _LINES239[k])}, {})
    files = ("", "* * * * * x\n", "* * * * * x", "MAILTO=a\n0 0 * * * y\n", "ok\n", "# c\n" * 1001,
             "#" * 70000 + "\n", "@hourly z\n\n# end\n")
    eq("root cron grammar: whole files are refused for the same reasons by both copies (no trailing "
       "newline, a bad line by number, too many lines, too long)",
       [(_pv239.root_crontab_problem(t), _h239.root_crontab_problem(t)) for t in files],
       [(w, w) for w in ("", "", "the last line has no newline", "",
                         "line 1 is not a job, a variable, a comment or blank", "too many lines", "too long", "")])
    eq("root cron grammar: the limits and keywords are the same numbers in both copies",
       [getattr(_pv239, n) for n in ("ROOT_CRON_MAX_BYTES", "ROOT_CRON_MAX_LINES", "ROOT_CRON_LINE_MAX",
                                     "ROOT_CRON_SPECIALS", "ROOT_CRON_FIELDS", "ROOT_CRON_TEXT_RE",
                                     "ROOT_CRON_ENV_RE", "ROOT_CRON_ITEM_RE", "ROOT_CRON_CONF_KEY", "ROOT_CRON_DIR",
                                     "ROOT_CRON_DIR_FILE_RE", "ROOT_CRON_DIR_MAX_FILES", "ROOT_CRON_DIR_FILE_MAX")],
       [getattr(_h239, n) for n in ("ROOT_CRON_MAX_BYTES", "ROOT_CRON_MAX_LINES", "ROOT_CRON_LINE_MAX",
                                    "ROOT_CRON_SPECIALS", "ROOT_CRON_FIELDS", "ROOT_CRON_TEXT_RE",
                                    "ROOT_CRON_ENV_RE", "ROOT_CRON_ITEM_RE", "ROOT_CRON_CONF_KEY", "ROOT_CRON_DIR",
                                    "ROOT_CRON_DIR_FILE_RE", "ROOT_CRON_DIR_MAX_FILES", "ROOT_CRON_DIR_FILE_MAX")])
    eq("root cron job lines: a % is stored escaped and shown as typed; a bad schedule or a two-line command "
       "is refused",
       (_rc239.job_line("30 4 * * *", "date +%F > /x"), _rc239.rows("30 4 * * * date +\\%F\n")[0]["command"],
        _rc239.job_line("30 4 * *", "x")[0], _rc239.job_line("@daily", "a\nb")[0], _rc239.job_line("@weekly", " ")[0]),
       (("30 4 * * * date +\\%F > /x", ""), "date +%F", None, None, None))


# ── 2. the verbs: the helper and the remote shell forms ───────────────────────────────────────────
class _Cron239:
    """subprocess for the helper: `crontab -u root -l` answers `current`; `-` records what it installs."""

    TimeoutExpired = _sp239.TimeoutExpired
    DEVNULL = _sp239.DEVNULL

    def __init__(self, current):
        self.current, self.installed = current, []

    def run(self, argv, **kw):
        if argv[1:] == ["-u", "root", "-l"]:
            if self.current is None:
                return _sp239.CompletedProcess(argv, 1, b"", b"no crontab for root\n")
            return _sp239.CompletedProcess(argv, 0, self.current.encode(), b"")
        if argv[1:] == ["-u", "root", "-"]:
            self.installed.append(kw.get("input", b"").decode())
            return _sp239.CompletedProcess(argv, 0, b"", b"")
        return _sp239.CompletedProcess(argv, 99, b"", b"unexpected")


def _helper239(conf, argv, current, stdin="", crond=None):
    """(rc, stdout, stderr, what was installed) of the helper's main(argv)."""
    fake = _Cron239(current)
    saved = (_h239.subprocess, _h239.resolve, _h239.panel_conf, _h239.ROOT_CRON_DIR, sys.stdin, sys.stdout, sys.stderr)
    _h239.subprocess, _h239.resolve, _h239.panel_conf = fake, (lambda n: "/usr/bin/" + n), (lambda: dict(conf))
    _h239.ROOT_CRON_DIR = crond or os.path.join(_TMP239, "no-such-dir")
    sys.stdin, sys.stdout, sys.stderr = _io239.StringIO(stdin), _io239.StringIO(), _io239.StringIO()
    try:
        rc = _h239.main(["panel-helper"] + list(argv))
        return rc, sys.stdout.getvalue(), sys.stderr.getvalue(), fake.installed
    finally:
        (_h239.subprocess, _h239.resolve, _h239.panel_conf, _h239.ROOT_CRON_DIR, sys.stdin, sys.stdout,
         sys.stderr) = saved


def _sha239(text):
    return _hl239.sha256(text.encode()).hexdigest()


def _crond239():
    d = _tf239.mkdtemp(dir=_TMP239)
    for name, body in (("lgsm-node-tools", "0 4 * * 0 root /x\n"), ("e2scrub_all", "10 3 * * 0 root y\n"),
                       ("bad.name", "z\n")):
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    os.symlink(os.path.join(d, "e2scrub_all"), os.path.join(d, "a-link"))
    return d


def _helper_verbs239():
    cur = "MAILTO=root\n0 1 * * * /old\n"
    yes = {"root_cron": "yes"}
    shut = [(_helper239(c, ["root-crontab-read"], cur)[0], _helper239(c, ["root-crontab-write", _sha239(cur)], cur,
                                                                       "@daily x\n")[0:4:3])
            for c in ({}, {"root_cron": "no"}, {"root_cron": "YES"})]
    eq("panel-helper: without root_cron=yes in panel.conf both verbs are refused (rc 1) and nothing is installed",
       shut, [(1, (1, []))] * 3)
    refusal = _helper239({}, ["root-crontab-read"], cur)[2]
    check("panel-helper: the refusal names the installer setting that opens it",
          "PANEL_ROOT_CRON=1" in refusal, refusal)
    crond = _crond239()
    rc, out, _e, _i = _helper239(yes, ["root-crontab-read"], cur, crond=crond)
    got = _rc239.parse_read(out)
    eq("panel-helper: root-crontab-read prints root's crontab and the /etc/cron.d files cron reads (no link, "
       "no dotted name), the panel's own marked",
       (rc, got["state"], got["text"], [(f["name"], f["text"], f["panel"]) for f in got["crond"]]),
       (0, "ok", cur, [("e2scrub_all", "10 3 * * 0 root y\n", False), ("lgsm-node-tools", "0 4 * * 0 root /x\n", True)]))
    eq("panel-helper: with no crontab for root, the read says none",
       _rc239.parse_read(_helper239(yes, ["root-crontab-read"], None)[1])["state"], "none")
    new = cur + "@daily /new\n"
    ok = _helper239(yes, ["root-crontab-write", _sha239(cur)], cur, new)
    stale = _helper239(yes, ["root-crontab-write", _sha239("other\n")], cur, new)
    bad = _helper239(yes, ["root-crontab-write", _sha239(cur)], cur, cur + "* * * * *\n")
    first = _helper239(yes, ["root-crontab-write", _sha239("")], None, "@hourly x\n")
    eq("panel-helper: root-crontab-write installs the stdin content only while root's crontab hashes to the "
       "digest given (rc 3 when it changed), refuses a bad line (rc 2), and writes a first crontab",
       [(r[0], r[3]) for r in (ok, stale, bad, first)], [(0, [new]), (3, []), (2, []), (0, ["@hourly x\n"])])
    eq("panel-helper: the write takes its content on stdin, and the read is a read",
       ("root-crontab-write" in _h239.STDIN_VERBS, "root-crontab-read" in _h239.READ_VERBS,
        "root-crontab-write" in _h239.READ_VERBS), (True, True, False))


def _bash239(script, path_dir):
    env = {"PATH": path_dir + ":/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp239.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, env=env, check=False)  # nosec B603 B607
    return r.returncode, r.stdout


def _fake_crontab239(d, current):
    """A stand-in `crontab` in `d`: -l prints `current` (or fails with none), - saves stdin to installed."""
    store = os.path.join(d, "current")
    if current is not None:
        with open(store, "w", encoding="utf-8") as fh:
            fh.write(current)
    script = ("#!/bin/bash\nif [ \"$3\" = -l ]; then [ -f %(s)s ] || { echo 'no crontab for root' >&2; exit 1; }; "
              "cat %(s)s; exit 0; fi\nif [ \"$3\" = - ]; then cat > %(d)s/installed; exit 0; fi\nexit 9\n"
              % {"s": store, "d": d})
    path = os.path.join(d, "crontab")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in bash runs
    os.chmod(path, 0o700)  # nosec B103
    return path


def _remote_forms239():
    cur = "MAILTO=root\n0 1 * * * /old %\n"
    d = _tf239.mkdtemp(dir=_TMP239)
    _fake_crontab239(d, cur)
    crond = _crond239()
    script = _pv239.remote_command("root-crontab-read", []).replace(_pv239.ROOT_CRON_DIR, crond)
    rc, out = _bash239(script, d)
    helper_out = _helper239({"root_cron": "yes"}, ["root-crontab-read"], cur, crond=crond)[1]
    eq("remote root-crontab-read: the shell form prints exactly what the helper prints for the same host",
       (rc, out), (0, helper_out))
    d2 = _tf239.mkdtemp(dir=_TMP239)
    _fake_crontab239(d2, None)
    eq("remote root-crontab-read: no crontab for root reads as none",
       _rc239.parse_read(_bash239(_pv239.remote_command("root-crontab-read", []).replace(
           _pv239.ROOT_CRON_DIR, crond), d2)[1])["state"], "none")
    new = cur + "@daily /new\n"
    stale_rc, stale_out = _bash239(_pv239.remote_root_crontab_write_command(new, _sha239("x")), d)
    stale_written = os.path.exists(os.path.join(d, "installed"))
    ok_rc, _o = _bash239(_pv239.remote_root_crontab_write_command(new, _sha239(cur)), d)
    with open(os.path.join(d, "installed"), encoding="utf-8") as fh:
        written = fh.read()
    eq("remote root-crontab-write: exits 3 and writes nothing when root's crontab no longer hashes to the "
       "digest; otherwise installs the content byte for byte",
       (stale_rc, "changed since it was read" in stale_out, stale_written, ok_rc, written), (3, True, False, 0, new))
    refused = []
    for text in ("* * * * *\n", "x"):
        try:
            _pv239.remote_root_crontab_write_command(text, _sha239(cur))
        except _pv239.VerbError:
            refused.append(text)
    eq("remote root-crontab-write: a bad file is refused before any command is built", len(refused), 2)
    eq("privileged.py: the write is two-sided (local helper, remote builder), the read has a remote form",
       ("root-crontab-write" in _pv239.LOCAL_ONLY_VERBS, "root-crontab-read" in _pv239._REMOTE_ACTIONS,
        _pv239.helper_argv("root-crontab-write", ["a" * 64])[-2:]), (True, True, ["root-crontab-write", "a" * 64]))


# ── 3. the routes ─────────────────────────────────────────────────────────────────────────────────
def _other_super239():
    with _p9.app_context():
        u = _U239.query.filter_by(username="p239_super").first()
        if u is None:
            u = _U239(username="p239_super", password_hash="x", display_name="S", is_superadmin=True,
                      is_owner=False, is_active=True)
            _db239.session.add(u)
            _db239.session.commit()
        return u.id


def _drop_other239():
    with _p9.app_context():
        u = _U239.query.filter_by(username="p239_super").first()
        if u is not None:
            _db239.session.delete(u)
            _db239.session.commit()


def _stubs239(current, opened=True, writes=None):
    """Answer the read with `current` (None: no crontab), record writes in `writes`, and the password."""
    state = {"current": current}

    def _rp(server, verb, args=(), **_kw):
        if verb != "root-crontab-read":
            return "", "unexpected verb", 9
        if state["current"] is None:
            return "root-crontab none\n", "", 0
        return "root-crontab ok %s\n" % _b64239.b64encode(state["current"].encode()).decode(), "", 0

    def _wr(server, content, expected, timeout=30):
        writes.append((server.id, content, expected))
        return "", "", 0
    _p9_patch(_core239, "run_privileged", _rp)
    _p9_patch(_cron239, "write_root_crontab", _wr)
    _p9_patch(_core239, "helper_present", lambda recheck=False: True)
    _p9_patch(_rc239, "host_opened", lambda is_local, helper: opened)
    _p9_patch(_as239, "_reauth_refusal", lambda u, pw, code: None if pw == _GOOD239 else "wrong password")
    return state


def _set_on239(on):
    _cfg239.update_config(lambda cfg: cfg.update({_rc239.ENABLED_KEY: on}))


def _owner_only239():
    other = _p9_client(_other_super239())
    got = [other.get("/root-cron/%d" % P9_HOST).status_code,
           other.post("/root-cron/%d/change" % P9_HOST, data={"op": "add", "password": _GOOD239}).status_code,
           other.post("/root-cron/switch", data={"on": "1", "password": _GOOD239}).status_code]
    row = _p9_audit("access_denied")
    eq("root cron: another superadmin is refused the page, a change and the switch (403), audited",
       (got, row.success, "root" in row.detail), ([403, 403, 403], False, True))
    page = other.get("/settings").get_data(as_text=True)
    check("Settings: another superadmin sees the Schedules card but not the root cron switch",
          'id="sec-schedules"' in page and 'id="sch-root-cron"' not in page, page[:200])


def _switch239():
    a = _p9_client(P9_ADMIN)
    _p9_patch(_as239, "_reauth_refusal", lambda u, pw, code: None if pw == _GOOD239 else "wrong password")
    _set_on239(False)
    off = a.get("/root-cron/%d" % P9_HOST)
    wrong = a.post("/root-cron/switch", data={"on": "1", "password": _BAD239})
    still = _rc239.enabled()
    row_wrong = _p9_audit("root_cron_enabled")
    a.post("/root-cron/switch", data={"on": "1", "password": _GOOD239})
    on = _rc239.enabled()
    row_on = _p9_audit("root_cron_enabled")
    eq("root cron: off by default the page sends the owner to Settings; the switch needs the password in "
       "the request (a wrong one changes nothing and is audited as refused), and turning it on is audited",
       (off.status_code, "/settings" in (off.headers.get("Location") or ""), wrong.status_code, still,
        row_wrong.success, on, row_on.success),
       (302, True, 302, False, False, True, True))
    page = a.get("/settings").get_data(as_text=True)
    check("Settings: the owner sees the root cron switch, with password field, and the link once it is on",
          'id="sch-root-cron"' in page and 'name="password"' in page and "/root-cron/%d" % P9_LOCAL in page, "")


def _changes239():
    a = _p9_client(P9_ADMIN)
    _set_on239(True)
    writes = []
    cur = "MAILTO=root\n0 1 * * * /old\n"
    _stubs239(cur, writes=writes)
    page = a.get("/root-cron/%d" % P9_HOST).get_data(as_text=True)
    sha = _sha239(cur)
    check("root cron page: lists the job and the other line, with the page's digest in each form",
          "/old" in page and "MAILTO=root" in page and 'value="%s"' % sha in page, page[:300])
    base = {"sha": sha, "password": _GOOD239}
    a.post("/root-cron/%d/change" % P9_HOST, data=dict(base, op="add", schedule="30 4 * * *", command="date +%F"))
    add_row = _p9_audit("root_cron_change")
    a.post("/root-cron/%d/change" % P9_HOST, data=dict(base, op="save", n="2", was="0 1 * * * /old",
                                                        schedule="@daily", command="/new"))
    edit_row = _p9_audit("root_cron_change")
    a.post("/root-cron/%d/change" % P9_HOST, data=dict(base, op="delete", n="2", was="0 1 * * * /old"))
    del_row = _p9_audit("root_cron_change")
    eq("root cron: add, edit and delete each write the whole crontab with the page's digest, a % escaped",
       [(w[0], w[1], w[2]) for w in writes],
       [(P9_HOST, cur + "30 4 * * * date +\\%F\n", sha), (P9_HOST, "MAILTO=root\n@daily /new\n", sha),
        (P9_HOST, "MAILTO=root\n", sha)])
    eq("root cron: each change is audited with the host and the old and new line",
       (add_row.target, add_row.detail, edit_row.detail, edit_row.success, del_row.detail),
       ("p9-host", "add: 30 4 * * * date +\\%F", "edit line 2: 0 1 * * * /old -> @daily /new", True,
        "removed line 2: 0 1 * * * /old"))
    del writes[:]
    refused = [a.post("/root-cron/%d/change" % P9_HOST, data=dict(base, **d)) for d in (
        {"op": "add", "schedule": "61 * * * *", "command": "x"},
        {"op": "save", "n": "2", "was": "0 1 * * * /changed", "schedule": "@daily", "command": "x"},
        {"op": "add", "schedule": "@daily", "command": "x", "sha": "0" * 64},
        {"op": "add", "schedule": "@daily", "command": "x", "password": _BAD239})]
    last = _p9_audit("root_cron_change")
    eq("root cron: a bad schedule, a line that changed, a crontab that changed and a wrong password write "
       "nothing, and the refusal is audited",
       (writes, [r.status_code for r in refused], last.success, "refused" in last.detail),
       ([], [302] * 4, False, True))
    _stubs239(cur, opened=False, writes=writes)
    page = a.get("/root-cron/%d" % P9_LOCAL).get_data(as_text=True)
    a.post("/root-cron/%d/change" % P9_LOCAL, data=dict(base, op="add", schedule="@daily", command="x"))
    eq("root cron: a panel host not opened at install shows how to open it and writes nothing",
       ('id="rc-not-opened"' in page, "PANEL_ROOT_CRON=1" in page, writes), (True, True, []))


def _host_opened239():
    conf = os.path.join(_TMP239, "panel.conf")
    saved = _rc239._CONF
    try:
        _rc239._CONF = conf
        got = []
        for body in (None, "root_cron=no\n", "root_cron=yes\n", "x=1\nroot_cron = yes\n"):
            if body is None:
                if os.path.exists(conf):
                    os.unlink(conf)
            else:
                with open(conf, "w", encoding="utf-8") as fh:
                    fh.write(body)
            got.append(_rc239.host_opened(True, True))
        eq("root cron: the panel host counts as opened only when panel.conf records root_cron=yes; a remote or a "
           "host without the helper always does",
           (got, _rc239.host_opened(False, True), _rc239.host_opened(True, False)),
           ([False, False, True, True], True, True))
    finally:
        _rc239._CONF = saved


# ── 4. Schedules ──────────────────────────────────────────────────────────────────────────────────
def _schedules239():
    """The form parsing and the save; then the OS check, the backup tick and the card (_os_check239)."""
    from panel.core import clock as _clk239
    want = _sc239.utc_hhmm(_clk239.convert_wall_time(5, 30, "America/Los_Angeles", "UTC"))
    new, why = _sc239.parse_form({"tz": "America/Los_Angeles", "backup_at": "05:30", "os_check_at": "",
                                  "update_every": "360", "os_check": "on"})
    eq("schedules: a time typed in the viewer's zone is stored in UTC, empty stays empty, the interval is "
       "one of the choices",
       (new, why), ({_sc239.BACKUP_AT: want, _sc239.OS_CHECK_AT: "", _sc239.UPDATE_EVERY: 360, _sc239.OS_CHECK: True},
                    ""))
    eq("schedules: an unreadable time or interval is refused",
       [bool(_sc239.parse_form(f)[1]) for f in ({"backup_at": "25:00", "update_every": "30"},
                                                 {"update_every": "45"}, {"update_every": "1e3"})], [True] * 3)
    a = _p9_client(P9_ADMIN)
    r = a.post("/settings/schedules", data={"tz": "UTC", "backup_at": "03:15", "os_check_at": "04:00",
                                            "update_every": "720"})
    row = _p9_audit("settings_update")
    stored = _cfg239.load_config()
    eq("schedules save: stores each key (the OS check off when unticked) and audits what changed",
       (r.status_code, stored.get(_sc239.BACKUP_AT), stored.get(_sc239.OS_CHECK_AT), stored.get(_sc239.UPDATE_EVERY),
        stored.get(_sc239.OS_CHECK), row.target, "update_check_minutes" in row.detail),
       (302, "03:15", "04:00", 720, False, "schedules", True))
    eq("schedules: the stored values are what the jobs read",
       (_sc239.backup_at(), _sc239.os_check_at(), _sc239.update_every(), _sc239.os_check_on()),
       ((3, 15), (4, 0), 720 * 60, False))
    _os_check239(a)


def _os_check239(a):
    """The OS check and the backup tick follow what was saved; the card renders; then the keys are cleared."""
    now = _time239.time()
    eq("OS update check: off means never; on, the first pass in a process runs at once, then at the set time",
       (_osu239._os_check_due(now),), (False,))
    _cfg239.update_config(lambda c: c.update({_sc239.OS_CHECK: True}))
    saved_last = _osu239._os_update_state["last_run"]
    try:
        _osu239._os_update_state["last_run"] = 0.0
        first = _osu239._os_check_due(now)
        _osu239._os_update_state["last_run"] = now - 60
        just_ran = _osu239._os_check_due(now)
        _osu239._os_update_state["last_run"] = _sc239.last_slot((4, 0), now) - 60
        missed = _osu239._os_check_due(now)
    finally:
        _osu239._os_update_state["last_run"] = saved_last
    eq("OS update check: due at once in a new process, not again a minute later, due once the set time has "
       "passed since the last check", (first, just_ran, missed), (True, False, True))
    _backup_tick239(now)
    eq("schedules: how often each loop runs is said in its own unit (90 s is 90 seconds, not '1 minutes')",
       [str(_sc239.every_words(n)) for n in (2, 90, 60, 120, 3600, 7200, 86400, None)],
       ["Every 2 seconds", "Every 90 seconds", "Every minute", "Every 2 minutes", "Every hour", "Every 2 hours",
        "Once a day", "Runs continuously"])
    rows = {r["key"]: r for r in _sc239.worker_rows()}
    eq("schedules: every listed loop takes its cadence from the loops' own table, so one that has not run "
       "yet still says how often it runs",
       ([k for k, r in rows.items() if not r["every"]], rows["monitor"]["every"], rows["console-poller"]["every"]),
       ([], 60, 2))
    page = a.get("/settings").get_data(as_text=True)
    check("Settings: the Schedules card has its own form, the three jobs and the background jobs list",
          all(s in page for s in ('action="/settings/schedules"', 'name="backup_at"', 'name="update_every"',
                                  'name="os_check"', 'id="sch-workers"', "js/schedules.js")), "")
    _cfg239.update_config(lambda c: [c.pop(k, None) for k in (_sc239.BACKUP_AT, _sc239.OS_CHECK_AT,
                                                               _sc239.UPDATE_EVERY, _sc239.OS_CHECK)])


def _backup_tick239(now):
    taken = []
    at = _time239.gmtime(now - 300)
    _cfg239.update_config(lambda c: c.update({_sc239.BACKUP_AT: "%02d:%02d" % (at.tm_hour, at.tm_min),
                                              "backup_enabled": True}))
    _p9_patch(_bk239, "create_backup", lambda kind: (taken.append(kind) or True, ""))
    _p9_patch(_bk239, "prune_backups", lambda keep_days=None: 0)
    results = []
    for newest in (now - 7200, now - 60):
        _p9_patch(_bk239, "list_backups", lambda n=newest: [{"kind": "daily", "created": n}])
        results.append(_bk239.daily_backup_tick())
    eq("daily backup: with a time set, one is taken once that time has passed since the newest, and not "
       "again right after", (results, taken), ([True, False], ["daily"]))


# ── 5. text, docs and the installer ───────────────────────────────────────────────────────────────
def _catalog239(lang):
    out = {}
    d = os.path.join(_root, "panel", "translations", lang)
    for name in os.listdir(d):
        with open(os.path.join(d, name), encoding="utf-8") as fh:
            out.update(_json239.load(fh))
    return out


def _text239():
    from panel.routes import root_cron as _rcr239
    from panel.routes import schedules as _scr239
    said = [_rc239.NOT_OPENED, _rc239.CHANGED, _rc239.UNREADABLE, _rc239.NOT_SAVED, _rc239.BAD_LINE, _rc239.TOO_BIG,
            _rcr239.NOT_OWNER, _rcr239.OFF, _rcr239.ON_DONE, _rcr239.OFF_DONE, _rcr239.SAVED, _scr239.SAVED,
            "Every {n} minutes", "Every {n} hours", "Every {n} seconds"]
    said += list(_rcr239._CONFIRM_REFUSED.values())
    said += [w[1] for w in _sc239.WORKERS] + [w[2] for w in _sc239.WORKERS]
    for lang in ("es", "fr"):
        cat = _catalog239(lang)
        eq("root cron and schedules: every sentence the routes say has a %s translation" % lang,
           [s[:40] for s in said if not cat.get(s)], [])
    with open(os.path.join(_root, "install.sh"), encoding="utf-8") as fh:
        ins = fh.read()
    check("install.sh: records the root cron choice in panel.conf as root_cron= (the key the helper reads), "
          "never from a run the panel started",
          "\\nroot_cron=%s\\n" in ins and "${ROOT_CRON_CHOICE}" in ins and _h239.ROOT_CRON_CONF_KEY == "root_cron"
          and "PANEL_SELF_UPDATE" in ins[ins.index("_d1_root_cron_choice() {"):][:600], "")
    with open(os.path.join(_root, ".github", "SECURITY.md"), encoding="utf-8") as fh:
        sec = fh.read()
    check("SECURITY.md: the helper's verb count is the table's", "— %d verbs" % len(_h239.VERBS) in sec,
          len(_h239.VERBS))


try:
    _grammar239()
    _helper_verbs239()
    _remote_forms239()
    _host_opened239()
    _p9_arm(who="part239")
    _owner_only239()
    _switch239()
    _changes239()
    _p9_restore_all()
    _p9_arm(who="part239")
    _schedules239()
    _text239()
finally:
    _p9_restore_all()
    _cfg239.update_config(lambda c: c.pop(_rc239.ENABLED_KEY, None))
    _drop_other239()
check("part239: no check reached a real host", len(_P9_TRIPPED) == _trips239, repr(_P9_TRIPPED[_trips239:][:4]))
