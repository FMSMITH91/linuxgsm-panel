"""Part 19 of the unit suite: review leftovers, moved out of part18 whole.

One TOTP spend, the write gate for root-capable accounts, OverflowError, the panel-host row, the
one-shot ufw delete, the replaced terminal's audit row, Telegram redirects; then the integration
review's three interactions between those fixes, and Semgrep's suppressed findings in the SARIF.

HOW IT RUNS. Right after part18, on part18's app, client and row helpers (imported from it: part18
has already run by then, so importing it runs nothing again), with part12's tripwire re-armed for
the block that drives routes, and every patch and row undone in its finally.
"""
import contextlib as _ctxlib18
import io as _io18
import math as _math18
import os
import shutil as _shutil18b
import subprocess as _sp18  # nosec B404 - runs sh and jq on fixed argvs, on this suite's fixtures
import tempfile as _tf18
import time as _time18
import urllib.error as _ue18
import urllib.request as _ur18
from types import SimpleNamespace as NS

import pyotp as _pyotp18

from unit.part01 import check
from unit.part01 import skip as _skip18
from unit.part05 import _helper as _helper18, _priv as _priv18
from unit.part12 import (_p9, _p9_app, _p9_client, _p9_core, _p9_json, _p9_patch, _p9_restore_all,
                         _p9_sm, _p9_so, _p9_trip)
from unit.part18 import (_A18, _XHR18, _audits18, _ctx18, _forget_sids18, _host18, _mine18,
                         _server18)
from panel.core.config import decrypt_secret as _decrypt18
from panel.db import models as _m18
from panel.db import prefs as _prefs18
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.db.models import Group as _Group18
from panel.ops import terminal_session as _ts18
from panel.ops.ssh_manager import firewall as _fw18
from panel.ops.ssh_manager import hosts as _hosts18
from panel.routes import _shared as _sh18
from panel.routes import auth_routes as _ar18
from panel.routes import host_terminal as _ht18b
from panel.routes import server_files as _sf18
from panel.routes import tags as _tags18
from panel.security import auth as _auth18
from panel.services import notifications as _notif18

# ── 1. one TOTP step compare-and-swap, shared by every live-code route ──────────────────────────
# Two review passes each added a `_spend_totp_step` (auth_routes for login and the mint, tags for
# the password change and 2FA off), and they had already drifted: only one told the loaded row
# about the write.
check("totp spend: login, the mint, the password change and 2FA off all use ONE compare-and-swap",
      _ar18.spend_totp_step is _sh18.spend_totp_step is _tags18.spend_totp_step
      and not hasattr(_ar18, "_spend_totp_step") and not hasattr(_tags18, "_spend_totp_step"),
      repr((getattr(_ar18, "spend_totp_step", None), getattr(_tags18, "spend_totp_step", None))))

# ── 1b. 2FA enrolment spends its code through that same swap ─────────────────────────────
# It assigned the step unconditionally, so two enrolment POSTs with one code both turned 2FA on
# and each rendered its own backup codes — only one set was ever stored.
def _p18b_enrol():
    """Section 1b: 2FA enrolment spends its code through the shared swap."""
    with _ctx18():
        _en18 = User(username="p18_enrol", password_hash=_auth18.hash_password("Str0ng!passw0rd"),
                     is_superadmin=False, is_active=True)
        db.session.add(_en18)
        db.session.commit()
        _en18_id = _en18.id
        _rows18b["users"].append(_en18_id)
    _enc18 = _p9_client(_en18_id)
    _enc18.get("/account/2fa/enable")
    with _enc18.session_transaction() as _s18:
        _en18_secret = _decrypt18(_s18.get("_2fa_setup_secret", ""))
    _en18_code = _pyotp18.TOTP(_en18_secret).now() if _en18_secret else ""
    _en18_step = _auth18.verify_totp_step(_en18_secret, _en18_code) if _en18_secret else None
    with _ctx18():                          # the racing request already spent this step
        db.session.get(User, _en18_id).last_totp_step = _en18_step or 0
        db.session.commit()
    _enc18.post("/account/2fa/enable", data={"password": "Str0ng!passw0rd",  # nosec B105 - a fixture password
                                             "totp_code": _en18_code})
    with _ctx18():
        _en18_after = db.session.get(User, _en18_id).totp_enabled
        db.session.get(User, _en18_id).last_totp_step = 0      # the next step arrives
        db.session.commit()
    _en18_ok = _enc18.post("/account/2fa/enable", data={"password": "Str0ng!passw0rd",  # nosec B105 - a fixture password
                                                        "totp_code": _en18_code})
    with _ctx18():
        _en18_row = db.session.get(User, _en18_id)
        _en18_done = (_en18_row.totp_enabled, _en18_row.last_totp_step)
    check("2FA enrol: a code whose step another request already spent does NOT enable 2FA",
          _en18_step is not None and _en18_after is False, repr((_en18_step, _en18_after)))
    check("2FA enrol: ...while an unspent code does, and its step is recorded (control)",
          _en18_ok.status_code == 200 and _en18_done == (True, _en18_step),
          repr((_en18_ok.status_code, _en18_done, _en18_step)))


# ── 2. file and cron writes as a root-capable account are refused ─────────────────────────
# A row imported before import refused such accounts still reached the write routes: a
# ~/.bashrc, authorized_keys or crontab written as the host's sudo login is root on the host.
_wg18_probes, _wg18_writes = [], []     # the account probes the host was asked; the writes made
_wg18_reply = {"out": ""}               # what the host answers a probe with ("" = it timed out)


def _wg18_run(remote, cmd, **k):
    if "LGSM_ACCT_PROBE_DONE" in cmd:
        _wg18_probes.append(cmd)
        return (_wg18_reply["out"], "", 0) if _wg18_reply["out"] else ("", "timed out", -1)
    return ("", "", 0)


def _wg18_rec(name):
    def _f(*a, **k):
        _wg18_writes.append(name)
        return True, ""
    return _f


def _wg18_all(sid):
    """Every write route once, as the admin: [(route, status)]."""
    out = []
    for _path, _body in (("/api/server/%d/file", {"path": ".bashrc", "content": "x"}),
                         ("/api/server/%d/config", {"raw": "x"}),
                         ("/api/server/%d/delete-path", {"path": ".ssh"}),
                         ("/api/server/%d/cron", {"schedule": "* * * * *", "command": "x"}),
                         ("/api/server/%d/cron/update", {"raw": "x", "schedule": "* * * * *",
                                                        "command": "x"}),
                         ("/api/server/%d/cron/delete", {"raw": "x"}),
                         ("/api/server/%d/cron/run", {"raw": "x"})):
        out.append((_path.split("/")[-1], _A18.post(_path % sid, json=_body).status_code))
    _up = _A18.post("/api/server/%d/upload" % sid, content_type="multipart/form-data",
                    data={"path": ".ssh", "file": (_io18.BytesIO(b"k"), "authorized_keys")})
    out.append(("upload", _up.status_code))
    return out


def _p18b_write_gate():
    """Section 2: file and cron writes as a root-capable account are refused."""
    _wg18_host = _host18("p18-wg-host", "192.0.2.170")
    _wg18_admin = _server18(_wg18_host, "adminacct", 27700)
    _wg18_plain = _server18(_wg18_host, "plaingame", 27701)
    _p9_patch(_p9_sm, "run_command", _wg18_run)
    for _n18 in ("write_file", "add_cron_job", "update_cron_job", "run_cron_job_now",
                 "delete_path", "upload_file"):
        _p9_patch(_sf18, _n18, _wg18_rec(_n18))
    _p9_patch(_p9_sm, "delete_cron_job", _wg18_rec("delete_cron_job"))
    _p9_patch(_p9_sm, "list_cron_jobs", lambda *a, **k: [])
    _sh18._ACCOUNT_VERDICTS.clear()
    _wg18_reply["out"] = ("ACCT adminacct 1000 adminacct adm sudo\nACCT plaingame 1001 plaingame\n"
                          "LGSM_ACCT_PROBE_DONE\n")
    _p18b_write_gate_refused(_wg18_admin)
    _p18b_write_gate_plain(_wg18_host, _wg18_plain)
    _p18b_write_gate_down(_wg18_plain)


def _p18b_write_gate_refused(_wg18_admin):
    """Section 2: every write as the sudo-group account is refused, and audited."""
    _wg18_refused = _wg18_all(_wg18_admin)
    _wg18_w_admin = list(_wg18_writes)
    check("write gate: every file and cron write as a sudo-group account is refused (409)",
          len(_wg18_refused) == 8 and all(c == 409 for _r, c in _wg18_refused),
          repr(_wg18_refused))
    check("write gate: ...and nothing was written on the host", _wg18_w_admin == [],
          repr(_wg18_w_admin))
    _wg18_aud = _audits18("edit_file")
    check("write gate: the refusal is audited, with why",
          bool(_wg18_aud) and _wg18_aud[-1].success is False
          and "can become root" in _wg18_aud[-1].detail, repr(_wg18_aud[-1:]))


def _p18b_write_gate_plain(_wg18_host, _wg18_plain):
    """Section 2: a plain account's writes go through, on a verdict cached for a short while."""
    _wg18_probes_before = len(_wg18_probes)
    _wg18_ok = _wg18_all(_wg18_plain)
    check("write gate: a plain game account's writes still go through (positive control)",
          all(c == 200 for _r, c in _wg18_ok) and len(_wg18_writes) == 8,
          repr((_wg18_ok, _wg18_writes)))
    check("write gate: the verdict is cached — eight writes asked the host once",
          len(_wg18_probes) - _wg18_probes_before == 1,
          "%d probes" % (len(_wg18_probes) - _wg18_probes_before))
    with _ctx18():
        _wg18_remote = db.session.get(RemoteServer, _wg18_host)
        _wg18_n = len(_wg18_probes)
        _sh18.game_account_write_refusal(
            _wg18_remote, "plaingame", now=_time18.monotonic() + _sh18._ACCOUNT_VERDICT_TTL + 1)
    check("write gate: ...for a short while only: past the TTL the host is asked again",
          len(_wg18_probes) == _wg18_n + 1, "%d probes" % (len(_wg18_probes) - _wg18_n))


def _p18b_write_gate_down(_wg18_plain):
    """Section 2: a host that cannot answer is refused, and not cached as a clean bill."""
    _sh18._ACCOUNT_VERDICTS.clear()
    _wg18_reply["out"] = ""
    del _wg18_writes[:]
    _wg18_down = _A18.post("/api/server/%d/file" % _wg18_plain,
                           json={"path": "x.cfg", "content": "x"})
    _wg18_down2 = _A18.post("/api/server/%d/file" % _wg18_plain,
                            json={"path": "x.cfg", "content": "x"})
    check("write gate: a host that cannot answer refuses the write (fail closed), every time",
          _wg18_down.status_code == 409 and _wg18_down2.status_code == 409 and not _wg18_writes
          and "Couldn't check" in (_p9_json(_wg18_down).get("message") or ""),
          repr((_wg18_down.status_code, _wg18_down2.status_code, _wg18_writes)))
    _sh18._ACCOUNT_VERDICTS.clear()


# ── 3. OverflowError: Infinity / 1e400 are numbers to Python's json ───────────────────────
def _p18b_overflow():
    """Section 3: Infinity and 1e400 parse as "not a number" everywhere."""
    _inf18 = float("inf")

    def _raises18b(fn, *a, **k):
        try:
            fn(*a, **k)
            return None
        except Exception as e:  # noqa: BLE001 - the class is the answer
            return type(e).__name__
    check("overflow: _ufw_port_int turns Infinity into the ValueError its callers catch",
          _raises18b(_hosts18._ufw_port_int, _inf18) == "ValueError"
          and _raises18b(_hosts18._ufw_port_int, 1e400) == "ValueError"
          and _hosts18._ufw_port_int(27015.0) == 27015,
          repr(_raises18b(_hosts18._ufw_port_int, _inf18)))
    _rs18 = []
    _sess18 = _ts18.Session("p18-rs", "p18", lambda d: None, lambda r: None)
    _sess18._chan = NS(resize_pty=lambda width, height: _rs18.append((width, height)))
    _rs18_err = (_raises18b(_sess18.resize, _inf18, 24), _raises18b(_sess18.resize, 80, -_inf18),
                 _raises18b(_sess18.resize, _math18.nan, 24))
    _sess18.resize(1e9, 24)
    check("overflow: a terminal resize to Infinity (or NaN) is ignored, not raised",
          _rs18_err == (None, None, None) and _rs18 == [(500, 24)], repr((_rs18_err, _rs18)))
    check("overflow: ...and the paramiko open clamps the same way (the one shared helper)",
          _ts18._term_size(_inf18, 24) is None and _ts18._term_size(1e9, 1) == (500, 5)
          and _ts18._term_size("80", "24") == (80, 24))
    _ov18 = {
        "remote_ufw_delete_rule": _hosts18.remote_ufw_delete_rule(NS(), _inf18),
        "_validate_port": _raises18b(_m18._validate_port, "port", _inf18),
        "_submitted_thresholds": _raises18b(_notif18._submitted_thresholds, {"disk_pct": _inf18}),
        "_apply_user_order": _raises18b(_prefs18._apply_user_order, [NS(id=1)], [_inf18, 1]),
        "can_access_remote": _auth18.can_access_remote(NS(is_superadmin=False), _inf18),
    }
    with _ctx18():
        _ov18["_selected_remotes"] = _raises18b(_p9_app._selected_remotes, [_inf18])
        _ov18["_selected_game_servers"] = _raises18b(_p9_app._selected_game_servers, [_inf18])
    check("overflow: every int() parse of request data answers Infinity as 'not a number'",
          _ov18 == {"remote_ufw_delete_rule": (False, "Invalid rule number"),
                    "_validate_port": "ValueError", "_submitted_thresholds": None,
                    "_apply_user_order": None, "can_access_remote": False,
                    "_selected_remotes": None, "_selected_game_servers": None}, repr(_ov18))


# ── 4. the panel host's own row: edit and delete are superadmin-only ──────────────────────
def _p18b_panel_host_rows():
    """Section 4: the panel host, a granted host, and a delegated admin. -> their ids."""
    with _ctx18():
        _ph18 = RemoteServer(name="p18-panel-host", host="127.0.0.1", port=22, username="local",
                             auth_method="local", auth_credential="", is_local=True,
                             is_online=True)
        _pr18 = RemoteServer(name="p18-granted", host="192.0.2.171", port=22, username="root",
                             auth_method="password", auth_credential="", is_online=True)
        db.session.add_all([_ph18, _pr18])
        db.session.flush()
        db.session.add(GameServer(remote_id=_ph18.id, name="p18-ph-game", short_name="phgame",
                                  game_type="csgo", port=27702, installed=True, status="offline"))
        _dg18 = _Group18(name="p18_delegated", description="", is_default=False)
        _dg18.set_permissions([_auth18.MANAGE_REMOTES])
        _dg18.servers.extend([_ph18, _pr18])
        _du18 = User(username="p18_deleg", password_hash=_auth18.hash_password("Str0ng!passw0rd"),
                     is_superadmin=False, is_active=True)
        _du18.groups.append(_dg18)
        db.session.add_all([_dg18, _du18])
        db.session.commit()
        _ph18_id, _pr18_id, _du18_id, _dg18_id = _ph18.id, _pr18.id, _du18.id, _dg18.id
        _rows18b["hosts"] += [_ph18_id, _pr18_id]
        _rows18b["users"].append(_du18_id)
        _rows18b["groups"].append(_dg18_id)
    return _ph18_id, _pr18_id, _du18_id


def _p18b_panel_host():
    """Section 4: the panel host's own row is superadmin-only."""
    _ph18_id, _pr18_id, _du18_id = _p18b_panel_host_rows()
    _D18 = _p9_client(_du18_id)
    _ph18_edit = _D18.post("/remotes/%d/edit" % _ph18_id,
                           data={"name": "p18-renamed", "host": "127.0.0.1", "ssh_port": "22",
                                 "ssh_user": "local"})
    _ph18_del = _D18.post("/remotes/%d/delete" % _ph18_id, json={"password": "Str0ng!passw0rd"},  # nosec B105 - a fixture password
                          headers=_XHR18)
    with _ctx18():
        _ph18_row = db.session.get(RemoteServer, _ph18_id)
        _ph18_state = (_ph18_row.name if _ph18_row else None,
                       GameServer.query.filter_by(remote_id=_ph18_id).count())
    check("panel-host row: a delegated admin whose group holds it cannot edit it (403)",
          _ph18_edit.status_code == 403 and _ph18_state[0] == "p18-panel-host",
          repr((_ph18_edit.status_code, _ph18_state)))
    check("panel-host row: ...nor delete it, and its game servers stay in the panel",
          _ph18_del.status_code == 403 and _ph18_state == ("p18-panel-host", 1),
          repr((_ph18_del.status_code, _ph18_state)))
    _pr18_edit = _D18.post("/remotes/%d/edit" % _pr18_id,
                           data={"name": "p18-granted-renamed", "host": "192.0.2.171",
                                 "ssh_port": "22", "ssh_user": "root"})
    _A18.post("/remotes/%d/edit" % _ph18_id,
              data={"name": "p18-panel-host-2", "host": "127.0.0.1", "ssh_port": "22",
                    "ssh_user": "local"})
    with _ctx18():
        _pr18_name = db.session.get(RemoteServer, _pr18_id).name
        _ph18_name2 = db.session.get(RemoteServer, _ph18_id).name
    check("panel-host row: ...while the same admin still edits an ordinary host they were granted, "
          "and a superadmin still edits the panel host (controls)",
          _pr18_edit.status_code in (200, 302) and _pr18_name == "p18-granted-renamed"
          and _ph18_name2 == "p18-panel-host-2",
          repr((_pr18_edit.status_code, _pr18_name, _ph18_name2)))


# ── 6. ufw-delete-num-if: the check and the delete in one root run ────────────────────────
def _p18b_ufw_helper():
    """Section 6: the helper verb ufw-delete-num-if. -> the listing it was driven with."""
    _ud18_listing = ("Status: active\n\n     To                         Action      From\n"
                     "     --                         ------      ----\n"
                     "[ 1] 22/tcp                     ALLOW IN    Anywhere                   # ssh\n"
                     "[ 2] 27015/udp                  ALLOW IN    Anywhere\n")
    _ud18_runs = []

    def _ud18_run(argv, **k):
        _ud18_runs.append(argv[1:])
        return NS(returncode=0, stdout=_ud18_listing if argv[1] == "status" else "Rule deleted\n",
                  stderr="")
    _ud18_saved = (_helper18.subprocess, _helper18.resolve)
    try:
        _helper18.subprocess = NS(run=_ud18_run)
        _helper18.resolve = lambda prog: "/usr/sbin/" + prog
        # What the verb prints goes to the panel; here it is kept off the suite's output.
        with _ctxlib18.redirect_stdout(_io18.StringIO()), \
                _ctxlib18.redirect_stderr(_io18.StringIO()):
            _ud18_moved = _helper18.do_ufw_delete_num_if(["2", "22/tcp ALLOW IN Anywhere # ssh"],
                                                         "")
            _ud18_moved_runs = list(_ud18_runs)
            _ud18_ok = _helper18.do_ufw_delete_num_if(["1", "22/tcp ALLOW IN Anywhere # ssh"], "")
    finally:
        _helper18.subprocess, _helper18.resolve = _ud18_saved
    check("helper ufw-delete-num-if: a rule that is no longer the one checked is NOT deleted",
          _ud18_moved == _helper18.UFW_RULE_MOVED == _priv18.UFW_RULE_MOVED
          and _ud18_moved_runs == [["status", "numbered"]], repr((_ud18_moved, _ud18_moved_runs)))
    check("helper ufw-delete-num-if: ...the rule that still matches is (positive control)",
          _ud18_ok == 0 and _ud18_runs[-1] == ["delete", "1"], repr((_ud18_ok, _ud18_runs)))
    check("ufw-delete-num-if: the helper and the panel hold the rule text to the same pattern",
          _helper18.UFW_RULE_TEXT_RE == _priv18.UFW_RULE_TEXT_RE)
    return _ud18_listing


# The remote rendering, run for real under this machine's sh and awk with a fake ufw on PATH.
def _p18b_ufw_remote(_ud18_listing):
    """Section 6: the verb's remote rendering, under this machine's sh and awk."""
    if _shutil18b.which("awk") and _shutil18b.which("sh"):
        _ufd18 = _tf18.mkdtemp(prefix="p18-ufw-")
        with open(os.path.join(_ufd18, "ufw"), "w") as _fh18:
            _fh18.write("#!/bin/sh\nif [ \"$1\" = status ]; then cat <<'L'\n%sL\nexit 0; fi\n"
                        "if [ \"$1\" = delete ]; then read a; echo \"deleted $2 $a\"; exit 0; fi\n"
                        "exit 1\n" % _ud18_listing)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stub the suite runs itself
        os.chmod(os.path.join(_ufd18, "ufw"), 0o700)
        _renv18 = dict(os.environ, PATH=_ufd18 + ":" + os.environ.get("PATH", ""))

        def _remote18(n, text):
            r = _sp18.run(["sh", "-c", _priv18.remote_command("ufw-delete-num-if", [n, text])],  # nosec B603 B607 - sh, a fixed argv, the verb's own rendering
                          env=_renv18, capture_output=True, text=True, timeout=30)
            return r.returncode, r.stdout.strip()
        _rr18 = (_remote18("1", "22/tcp ALLOW IN Anywhere # ssh"),
                 _remote18("2", "22/tcp ALLOW IN Anywhere # ssh"),
                 _remote18("9", "22/tcp ALLOW IN Anywhere # ssh"))
        _shutil18b.rmtree(_ufd18, ignore_errors=True)
        check("remote ufw-delete-num-if: deletes rule n only while it still reads the text sent; "
              "a moved or missing rule exits 3 and deletes nothing",
              _rr18[0] == (0, "deleted 1 y") and _rr18[1][0] == 3 and _rr18[2][0] == 3
              and "deleted 2" not in _rr18[1][1] and "deleted 9" not in _rr18[2][1], repr(_rr18))
    else:
        _skip18("remote ufw-delete-num-if: the rendering under sh and awk",
                "sh or awk is not installed here")


# The panel side: a keyed delete sends the rule's text; one it cannot express falls back.
def _p18b_ufw_panel():
    """Section 6: the panel side of a keyed ufw delete."""
    _pd18_sent = []
    _pd18_rules = [{"num": "1", "detail": "22/tcp  ALLOW IN  Anywhere  # ssh"},
                   {"num": "2", "detail": "27015  ALLOW IN  Anywhere  # it's mine"}]
    _pd18_moved = {"on": False}

    def _pd18_status(_s):
        g = _fw18._group_ufw_rules(_pd18_rules)
        return {"installed": True, "enabled": True, "rules": _pd18_rules,
                "groups": [dict(x, protected=False) for x in g]}

    def _pd18_priv(s, verb, args=(), **k):
        _pd18_sent.append((verb, list(args)))
        if verb == "ufw-delete-num-if" and _pd18_moved["on"]:
            return ("ufw-delete-num-if: rule moved", "", 3)
        return ("Rule deleted", "", 0)
    _p9_patch(_fw18, "remote_ufw_status", _pd18_status)
    _p9_patch(_p9_core, "run_privileged", _pd18_priv)
    _pd18_k1 = _pd18_status(None)["groups"][0]["key"]
    _pd18_k2 = _pd18_status(None)["groups"][1]["key"]
    _pd18_a = _hosts18.remote_ufw_delete_rule(NS(), 1, expect_key=_pd18_k1)
    _pd18_b = _hosts18.remote_ufw_delete_rule(NS(), 2, expect_key=_pd18_k2)
    _pd18_moved["on"] = True
    _pd18_c = _hosts18.remote_ufw_delete_rule(NS(), 1, expect_key=_pd18_k1)
    check("ufw delete: with the rule's identity, the host re-checks the rule's text itself",
          _pd18_sent[:1] == [("ufw-delete-num-if", ["1", "22/tcp ALLOW IN Anywhere # ssh"])]
          and _pd18_a == (True, "Rule 1 deleted"), repr((_pd18_sent[:1], _pd18_a)))
    check("ufw delete: ...a rule whose text the verb cannot carry falls back to the plain delete",
          _pd18_sent[1:2] == [("ufw-delete-num", [2])] and _pd18_b[0] is True,
          repr(_pd18_sent[1:2]))
    check("ufw delete: ...and when the host finds the rule moved, nothing is reported deleted",
          _pd18_c[0] is False and "changed on the host" in _pd18_c[1], repr(_pd18_c))


# ── 7b. a second term_open on one socket writes the replaced shell's close row ────────────
def _p18b_terminal():
    """Section 7b: a second term_open on one socket audits the shell it replaced."""
    _t18a = _host18("p18-term-a", "192.0.2.172")
    _t18b = _host18("p18-term-b", "192.0.2.173")
    _p9_patch(_ht18b._ts, "open_session", lambda sid, remote, is_local, **k: None)

    def _t18_closes():
        with _ctx18():
            return [(a.target, a.detail) for a in AuditLog.query.filter_by(
                action="terminal_close").order_by(AuditLog.id).all()]
    _t18_before = len(_t18_closes())
    _tsio18 = _p9.socketio.test_client(_p9, flask_test_client=_A18)
    _tsio18.emit("term_open", {"remote_id": _t18a, "cols": 80, "rows": 24})
    _tsio18.emit("term_open", {"remote_id": _t18b, "cols": 80, "rows": 24})
    _t18_mid = _t18_closes()[_t18_before:]
    with _ht18b._sid_lock:
        _t18_sids = [s for s, e in _ht18b._sid_host.items() if e[0] in (_t18a, _t18b)]
        _t18_on = [e[0] for s, e in _ht18b._sid_host.items() if s in _t18_sids]
    _tsio18.disconnect()
    check("terminal: re-opening on the same socket audits the shell it replaced",
          _t18_mid == [("p18-term-a", "replaced by a new terminal on the same connection")],
          repr(_t18_mid))
    check("terminal: ...and the socket now holds only the new host",
          _t18_on == [_t18b], repr(_t18_on))
    _forget_sids18(_t18_sids)


# ── 7c. the Telegram reads refuse a redirect, as _post does ───────────────────────────────
def _p18b_telegram():
    """Section 7c: the Telegram reads refuse a redirect."""
    _tg18_tok = "123456789:" + "A" * 30
    _tg18_opened, _tg18_urlopen = [], []

    class _TgOp18:
        def __init__(self, exc=None, body=b'{"ok": true, "result": {"username": "p18bot"}}'):
            self.exc, self.body = exc, body

        def open(self, req, timeout=None):
            _tg18_opened.append(req.full_url)
            if self.exc:
                raise self.exc
            return _io18.BytesIO(self.body)

    def _tg18_no_urlopen(*a, **k):
        _tg18_urlopen.append(a)
        raise OSError("urlopen is not the opener these reads may use")
    _p9_patch(_notif18, "_OPENER", _TgOp18())
    _p9_patch(_ur18, "urlopen", _tg18_no_urlopen)
    _tg18_me = _notif18.telegram_get_me(_tg18_tok)
    _p9_patch(_notif18, "_OPENER", _TgOp18(exc=_ue18.HTTPError(
        "https://api.telegram.org/x", 302, "Found", {"Location": "http://169.254.169.254/"}, None)))
    _tg18_upd = _notif18.telegram_get_updates(_tg18_tok, timeout=1)
    check("telegram reads: getMe and getUpdates go through the no-redirect opener, never urlopen",
          _tg18_me == "p18bot" and len(_tg18_opened) == 2 and not _tg18_urlopen,
          repr((_tg18_me, _tg18_opened, _tg18_urlopen)))
    check("telegram reads: ...and a 3xx is a failed read (None), not followed",
          _tg18_upd is None, repr(_tg18_upd))
    check("telegram reads: the opener they use is the one that refuses redirects",
          any(isinstance(h, _notif18._NoRedirect) for h in _real_opener18.handlers),
          repr(_real_opener18.handlers))


_rows18b = {"users": [], "hosts": [], "groups": []}
_mine18_hosts_before = len(_mine18["hosts"])
_real_opener18 = _notif18._OPENER
# The sections above are functions, run here in order under the tripwire; the finally below undoes
# every patch and removes every row they made, whichever of them raised.
try:
    # part12's tripwire, re-armed for this block as part18 arms it: nothing below may reach a host.
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part18's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9.socketio, "emit", lambda event, data=None, **k: None)
    _p18b_enrol()
    _p18b_write_gate()
    _p18b_overflow()
    _p18b_panel_host()
    _p18b_ufw_remote(_p18b_ufw_helper())
    _p18b_ufw_panel()
    _p18b_terminal()
    _p18b_telegram()
finally:
    _p9_restore_all()
    _sh18._ACCOUNT_VERDICTS.clear()
    with _ctx18():
        for _gid18 in _rows18b["groups"]:
            _g18 = db.session.get(_Group18, _gid18)
            if _g18 is not None:
                db.session.delete(_g18)
        for _uid18 in _rows18b["users"]:
            _u18 = db.session.get(User, _uid18)
            if _u18 is not None:
                db.session.delete(_u18)
        for _hid18 in _rows18b["hosts"] + _mine18["hosts"][_mine18_hosts_before:]:
            GameServer.query.filter_by(remote_id=_hid18).delete()
            _h18 = db.session.get(RemoteServer, _hid18)
            if _h18 is not None:
                db.session.delete(_h18)
        db.session.commit()


# ── integration review: three interactions between the review fixes ──────────────────────────────
# (1) The TOTP and backup-code spends became immediate conditional UPDATEs, which open SQLite's
# write transaction on the spot. The password change and 2FA enrolment then ran bcrypt (tpool) with
# that lock held, and every other writer sat in SQLite's hub-blocking busy handler. The bcrypt work
# must come BEFORE the spend in both routes — checked on the source order of the two bodies.
import inspect as _ir_inspect  # noqa: E402
_ir_pw = _ir_inspect.getsource(_tags18)
_ir_pw = _ir_pw[_ir_pw.index("def account_change_password"):]
check("integration: the password change hashes the new password before spending the second factor",
      "_new_hash = hash_password(new)" in _ir_pw
      and _ir_pw.index("_new_hash = hash_password(new)") < _ir_pw.index("_spend_second_factor(")
      and "u.set_password(_new_hash)" in _ir_pw, _ir_pw[:200])
_ir_en = _ir_inspect.getsource(_ar18)
_ir_en = _ir_en[_ir_en.index("_enrol_step = ("):]
check("integration: 2FA enrolment hashes its backup codes before spending the step",
      _ir_en.index("set_backup_codes(codes)") < _ir_en.index("spend_totp_step(_u, _enrol_step)"),
      _ir_en[:300])

# (2) The Discord bot's hold after a fatal close is lifted by ANY save of the settings, not only by
# the watcher happening to read an "off" config: an untick-save-tick-save inside one 15 s poll left
# the config unchanged by the time it was read, and the hold stood for six hours.
from unit.part07 import _bf_watch, _bf_n  # noqa: E402


def _ir_quick_resave(n, cfg):
    """Save the settings twice within one poll (off, then on again): the config reads the same."""
    if n == 3:
        _bf_n._discord_saves[0] += 2


_ir_calls, _, _ = _bf_watch([4014], hours=0.2, on_sleep=_ir_quick_resave)
check("integration: a settings save inside one poll still lifts the Discord fatal-close hold",
      len(_ir_calls) == 2, "%d sessions" % len(_ir_calls))
_ir_calls, _, _ = _bf_watch([4014], hours=0.2)
check("integration: ...while with no save it holds (control)", len(_ir_calls) == 1,
      "%d sessions" % len(_ir_calls))
_ir_gen = _bf_n.discord_settings_generation()
_ir_saved_cfg = _bf_n._cfg
try:
    _ir_store = {}
    _bf_n._cfg = lambda: {}
    _ir_saver = getattr(_bf_n, "update_config", None)
    try:
        _bf_n.update_config = lambda fn: fn(_ir_store)
        _bf_n.save_settings(telegram={}, discord={}, events={})
    except Exception:  # nosec B110 - only the generation bump is under test here
        pass
    finally:
        if _ir_saver is not None:
            _bf_n.update_config = _ir_saver
finally:
    _bf_n._cfg = _ir_saved_cfg
check("integration: save_settings bumps the generation the hold is keyed on",
      _bf_n.discord_settings_generation() == _ir_gen + 1,
      "%d -> %d" % (_ir_gen, _bf_n.discord_settings_generation()))

# (3) A panel-host helper installed before ufw-delete-num-if existed answers "unknown verb" (rc 2):
# the delete falls back to ufw-delete-num, still under the lock and after the guard.
from panel.ops.ssh_manager import _core as _ir_core  # noqa: E402
_ir_rules = [{"num": "1", "detail": "22/tcp  ALLOW IN  Anywhere  # ssh"}]
_ir_sent = []


def _ir_status(_s):
    g = _fw18._group_ufw_rules(_ir_rules)
    return {"installed": True, "enabled": True, "rules": _ir_rules,
            "groups": [dict(x, protected=False) for x in g]}


def _ir_old_helper(s, verb, args=(), **k):
    _ir_sent.append(verb)
    if verb == "ufw-delete-num-if":
        return ("", "panel-helper: unknown verb 'ufw-delete-num-if'", 2)
    return ("Rule deleted", "", 0)


_ir_saved = (_fw18.remote_ufw_status, _ir_core.run_privileged)
try:
    _fw18.remote_ufw_status = _ir_status
    _ir_core.run_privileged = _ir_old_helper
    _ir_key = _ir_status(None)["groups"][0]["key"]
    _ir_res = _hosts18.remote_ufw_delete_rule(NS(), 1, expect_key=_ir_key)
finally:
    _fw18.remote_ufw_status, _ir_core.run_privileged = _ir_saved
check("integration: an older helper without ufw-delete-num-if still deletes, via ufw-delete-num",
      _ir_sent == ["ufw-delete-num-if", "ufw-delete-num"] and _ir_res == (True, "Rule 1 deleted"),
      repr((_ir_sent, _ir_res)))

# ── Semgrep's SARIF carries the nosemgrep-suppressed findings, and code scanning alerted on them ──
# The workflow drops them before upload. Driven: the workflow's own jq line, on a SARIF shaped like
# Semgrep 1.178's (a suppressed result carries "suppressions": [{"kind": "inSource"}]).
import json as _sg_json  # noqa: E402
import re as _sg_re  # noqa: E402
_sg_wf = open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
    __file__)))), ".github", "workflows", "security-code.yml")).read()
_sg_m = _sg_re.search(r"jq '([^']+)' \\\n\s+semgrep\.sarif > semgrep\.open\.sarif\n\s+mv semgrep\.open\.sarif "
                      r"semgrep\.sarif", _sg_wf)
check("semgrep upload: suppressed findings are filtered out of the SARIF before upload",
      _sg_m is not None and _sg_wf.index("semgrep.open.sarif") < _sg_wf.index("sarif_file: semgrep.sarif"),
      "no jq filter between the scan and upload-sarif")
if _sg_m is not None and _shutil18b.which("jq"):
    _sg_in = {"runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [
        {"ruleId": "a", "suppressions": [{"kind": "inSource"}]},
        {"ruleId": "b"},
        {"ruleId": "c", "suppressions": []}]}]}
    _sg_out = _sp18.run(["jq", _sg_m.group(1)], input=_sg_json.dumps(_sg_in), capture_output=True,  # nosec B603 B607 - jq, the workflow's own filter
                         text=True, timeout=30)
    _sg_ids = [r["ruleId"] for r in _sg_json.loads(_sg_out.stdout)["runs"][0]["results"]]
    check("semgrep upload: ...the filter drops only the suppressed result and keeps the run intact",
          _sg_ids == ["b", "c"] and "tool" in _sg_json.loads(_sg_out.stdout)["runs"][0], repr(_sg_ids))


# ── Renovate keeps the workflows' sha256-pinned downloads current, and nothing else ─────────────
# gitleaks, actionlint, osv-scanner and the Codacy coverage reporter are release binaries fetched by
# tag and checked against a sha256. Dependabot cannot see them, so they were bumped by hand, or not
# at all.
# .github/renovate.json runs ONE regex manager over the workflows (Dependabot keeps everything
# else, so the two never propose the same update). Its github-release-attachments lookup fetches
# releases/tags/<value>, so the value must be the exact tag the URL downloads: `v${VERSION}` in a
# URL would have Renovate look up a tag that does not exist. And a pinned download nobody marked
# would silently never be proposed, so every `sha256sum -c` in a workflow must have a match.
import glob as _rn_glob  # noqa: E402

_rn_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with open(os.path.join(_rn_root, ".github", "renovate.json"), encoding="utf-8") as _rn_fh:
    _rn_cfg = _sg_json.load(_rn_fh)
_rn_mgrs = _rn_cfg.get("customManagers") or [{}]
check("renovate: one regex manager over the workflows, no other manager, no dashboard, a release "
      "age floor",
      _rn_cfg.get("enabledManagers") == ["custom.regex"] and len(_rn_mgrs) == 1
      and _rn_mgrs[0].get("customType") == "regex"
      and _rn_mgrs[0].get("managerFilePatterns") == ["/^\\.github/workflows/[^/]+\\.ya?ml$/"]
      and len(_rn_mgrs[0].get("matchStrings") or []) == 1
      and _rn_cfg.get("dependencyDashboard") is False
      and _sg_re.fullmatch(r"[1-9][0-9]* days", _rn_cfg.get("minimumReleaseAge") or "") is not None,
      repr({k: _rn_cfg.get(k) for k in ("enabledManagers", "dependencyDashboard", "minimumReleaseAge")}))
# Renovate's matchStrings are JavaScript (RE2) regexes: `(?<name>` is Python's `(?P<name>`.
_rn_pat = _sg_re.compile(_sg_re.sub(r"\(\?<(?=[A-Za-z])", "(?P<",
                                    (_rn_mgrs[0].get("matchStrings") or ["(?!)"])[0]))


def _rn_uncovered(text):
    """Renovate's matches in one workflow's text, and how many checksummed downloads they leave."""
    _found = list(_rn_pat.finditer(text))
    _sums = len([_l for _l in text.splitlines()
                 if "sha256sum -c" in _l and not _l.lstrip().startswith("#")])
    return _found, _sums - len(_found)


_rn_deps, _rn_bad = [], []
for _rn_wf in sorted(_rn_glob.glob(os.path.join(_rn_root, ".github", "workflows", "*.yml"))):
    with open(_rn_wf, encoding="utf-8") as _rn_fh:
        _rn_txt = _rn_fh.read()
    _rn_found, _rn_left = _rn_uncovered(_rn_txt)
    if _rn_left:
        _rn_bad.append("%s: %d checksummed download(s) Renovate does not match"
                       % (os.path.basename(_rn_wf), _rn_left))
    for _rn_m in _rn_found:
        _rn_deps.append(_rn_m.group("depName"))
        _rn_dl = "https://github.com/%s/releases/download/${" % _rn_m.group("depName")
        if _rn_m.group("datasource") != "github-release-attachments" or _rn_dl not in _rn_txt:
            _rn_bad.append("%s: %s is not downloaded by the tag Renovate looks up"
                           % (os.path.basename(_rn_wf), _rn_m.group("depName")))
    if "/releases/download/v${" in _rn_txt:
        _rn_bad.append("%s: a download URL adds `v` to its version" % os.path.basename(_rn_wf))
check("renovate: every sha256-checked download in a workflow is matched, and fetched by the tag "
      "Renovate looks up",
      not _rn_bad and sorted(_rn_deps) == ["codacy/codacy-coverage-reporter", "gitleaks/gitleaks",
                                            "google/osv-scanner", "rhysd/actionlint"],
      repr((_rn_bad, _rn_deps)))
_rn_ctl = ("          # renovate: datasource=github-release-attachments depName=o/r\n"
           "          VERSION: 'v1.2.3'\n          SHA256: '%s'\n"
           "        run: echo \"$SHA256  f\" | sha256sum -c -\n" % ("a" * 64))
check("renovate: ...and the count catches a pinned download with no marker (control)",
      len(_rn_uncovered(_rn_ctl)[0]) == 1 and _rn_uncovered(_rn_ctl)[1] == 0
      and _rn_uncovered(_rn_ctl.replace("# renovate:", "# pinned:"))[1] == 1,
      repr(_rn_uncovered(_rn_ctl)))


# ── what an install puts on the host, an update keeps current ──────────────────────────────────
# The owner's rule: "The files it installs should also be the files it keeps updated". The systemd
# unit was the one piece a fresh install wrote and no update ever touched: a host kept whatever unit
# it was first given. Every install step a fresh install runs (ensure_*, install_*, write_*) must be
# run by the update path too; the only fresh-only writes allowed are named below with the reason.
with open(os.path.join(_rn_root, "install.sh"), encoding="utf-8") as _iu_fh:
    _iu_src = _iu_fh.read()


def _iu_code(text):
    """`text` with its comment lines dropped: an explanation naming a step is not a call to it."""
    return "\n".join(_l for _l in text.splitlines() if not _l.lstrip().startswith("#"))


def _iu_fn(name):
    _i = _iu_src.index("\n%s() {" % name) + 1
    return _iu_src[_i:_iu_src.index("\n}\n", _i) + 3]


_iu_upd = _iu_code(_iu_src[_iu_src.index("\n# UPDATE PATH"):_iu_src.index("\n# FRESH INSTALL PATH")])
_iu_fresh = _iu_code(_iu_src[_iu_src.index("\n# FRESH INSTALL PATH"):])
_IU_STEP = _sg_re.compile(r"^\s*(?:\[\[[^\]\n]*\]\]\s*&&\s*)?((?:ensure|install|write)_[a-z0-9_]+)\b",
                          _sg_re.M)
_iu_fresh_steps = set(_IU_STEP.findall(_iu_fresh))
_iu_upd_steps = set(_IU_STEP.findall(_iu_upd))
check("install.sh: every install step a fresh install runs, an update runs as well",
      len(_iu_fresh_steps) >= 10 and "ensure_service_unit" in _iu_fresh_steps
      and _iu_fresh_steps <= _iu_upd_steps,
      "fresh only: %r" % sorted(_iu_fresh_steps - _iu_upd_steps))
# Written inline by a fresh install alone, on purpose: /etc/apt/apt.conf.d/20auto-upgrades turns
# unattended OS updates on once, and from then on the panel's Auto-updates card owns the setting;
# rewriting it on each update would undo the operator's choice. (The one-time OS upgrade, the
# firewall rule and linger are commands, not files, and the Firewall page owns the rule.)
_iu_inline = set(_sg_re.findall(r'(?:\btee|\bcat\s*>|>)\s*"?(/(?:etc|usr|var)/[^"\s;)]+)', _iu_fresh))
check("install.sh: ...and the only system file a fresh install writes inline is 20auto-upgrades",
      _iu_inline == {"/etc/apt/apt.conf.d/20auto-upgrades"}, repr(sorted(_iu_inline)))
check("install.sh: no unit is written except through ensure_service_unit",
      _iu_src.count('cat > "${UNIT_FILE}"') == 0
      and _iu_code(_iu_src).count("ensure_service_unit") >= 4,
      repr(_iu_code(_iu_src).count("ensure_service_unit")))

# Where in the update it runs: the unit is snapshotted before the service is stopped, refreshed
# before it is started again, and put back by BOTH rollbacks before their reload, so restored code
# runs under the unit it shipped with. The no-op update refreshes it too, and reloads.
_iu_snap, _iu_stop = _iu_upd.find("snapshot_service_unit"), _iu_upd.find('info "[1/6]')
_iu_s5 = _iu_upd[_iu_upd.find('info "[5/6]'):]
_iu_rb = [_m.start() for _m in _sg_re.finditer(r"restore_service_unit\n\s+svc daemon-reload", _iu_upd)]
_iu_noop = _iu_upd[:_iu_upd.find("update_noop_line\n        exit 0")]
check("install.sh: the update snapshots the unit first, refreshes it before the start, and both "
      "rollbacks put it back before reloading",
      0 <= _iu_snap < _iu_stop
      and -1 < _iu_s5.find("ensure_service_unit") < _iu_s5.find("svc start linuxgsm-panel.service")
      and len(_iu_rb) == 2
      and "ensure_service_unit" in _iu_noop[-900:] and "svc daemon-reload" in _iu_noop[-900:],
      repr((_iu_snap, _iu_stop, len(_iu_rb))))

# Driven: the four functions in bash, on a unit in a scratch directory.
_iu_dir = _tf18.mkdtemp()
_iu_script = ("set -u\nwarn() { echo \"WARN $*\"; }\nok() { echo \"OK $*\"; }\n"
              + "".join(_iu_fn(_n) for _n in ("render_service_unit", "ensure_service_unit",
                                              "snapshot_service_unit", "restore_service_unit"))
              + r'''
U="$1/sys/linuxgsm-panel.service"; UNIT_FILE="$U"; RUN_AS_ROOT=1; PANEL_USER=lgsmpanel
PANEL_DIR=/home/lgsmpanel/linuxgsm-panel
ensure_service_unit; echo "fresh=${UNIT_CHANGED} mode=$(stat -c %a "$U")"
grep -qx 'User=lgsmpanel' "$U" && grep -qx 'WantedBy=multi-user.target' "$U" && echo "root-unit"
i1="$(stat -c %i:%Y "$U")"; sleep 1
ensure_service_unit; echo "same=${UNIT_CHANGED} untouched=$([[ "$(stat -c %i:%Y "$U")" == "$i1" ]] && echo yes)"
printf 'OLD UNIT\nno trailing newline' > "$U"
snapshot_service_unit; ensure_service_unit; echo "changed=${UNIT_CHANGED}"
grep -qx 'User=lgsmpanel' "$U" && echo "refreshed"
restore_service_unit; echo "restored=$(cmp -s "$U" <(printf 'OLD UNIT\nno trailing newline') && echo exact)"
ls "$1/sys" | grep -c '\.service\.' | sed 's/^/leftovers=/'
UNIT_FILE="$1/user/linuxgsm-panel.service"; RUN_AS_ROOT=0
ensure_service_unit; grep -q '^User=' "$UNIT_FILE" || echo "user-unit=$(grep -c 'WantedBy=default.target' "$UNIT_FILE")"
mkdir -p "$1/ro"; UNIT_FILE="$1/ro/x.service"; echo keep > "$UNIT_FILE"; chmod 0555 "$1/ro"
ensure_service_unit; echo "ro=${UNIT_CHANGED} kept=$(cat "$UNIT_FILE")"; chmod 0755 "$1/ro"
''')
try:
    _iu_out = _sp18.run(["bash", "-c", _iu_script, "iu", _iu_dir],  # nosec B603 B607 - install.sh's own functions, in a scratch dir
                        capture_output=True, text=True, timeout=60)
    _iu_lines = _iu_out.stdout.split()
finally:
    _shutil18b.rmtree(_iu_dir, ignore_errors=True)
check("install.sh unit (driven): written when missing, 0644, the root layout; NOT rewritten when "
      "the text is the same",
      "fresh=1" in _iu_lines and "mode=644" in _iu_lines and "root-unit" in _iu_lines
      and "same=0" in _iu_lines and "untouched=yes" in _iu_lines,
      repr((_iu_out.stdout, _iu_out.stderr[-300:])))
check("install.sh unit (driven): ...replaced when it differs, and a rollback puts the old one back "
      "byte for byte, leaving no temporary file",
      "changed=1" in _iu_lines and "refreshed" in _iu_lines and "restored=exact" in _iu_lines
      and "leftovers=0" in _iu_lines, repr(_iu_out.stdout))
check("install.sh unit (driven): ...the per-user layout has no User= and starts with the session; "
      "a unit it cannot write is warned about and left as it was",
      "user-unit=1" in _iu_lines
      and (os.geteuid() == 0   # root writes through a 0555 directory: nothing to refuse it
           or ("ro=0" in _iu_lines and "kept=keep" in _iu_lines and "WARN" in _iu_out.stdout)),
      repr(_iu_out.stdout))


# ── the checks a pull request must pass to merge: required, and run on every pull request ──────
# GitHub's protect-main ruleset requires the checks .github/required-checks.txt names. A required
# check whose workflow skipped a pull request (a path filter) holds it forever, so every Actions
# check named there must be a job of a workflow with an UNFILTERED pull_request trigger. And every
# job of such a workflow is named, so a new job is required, or the build says why not.
with open(os.path.join(_rn_root, ".github", "required-checks.txt"), encoding="utf-8") as _rq_fh:
    _rq = [tuple(_p.strip() for _p in _l.split("|", 1)) for _l in _rq_fh.read().splitlines()
           if _l.strip() and not _l.lstrip().startswith("#")]


def _rq_on_pr(text):
    """(has a pull_request trigger, that trigger carries a path filter)."""
    _on = text[:text.index("\npermissions:")] if "\npermissions:" in text else text
    _m = _sg_re.search(r"^  pull_request:\n((?:    .*\n)*)", _on, _sg_re.M)
    return (_m is not None, bool(_m) and _sg_re.search(r"^    paths(-ignore)?:", _m.group(1), _sg_re.M)
            is not None)


_rq_jobs = {}   # workflow file -> [(job name template, matrix-free regex)]
for _rq_wf in sorted(_rn_glob.glob(os.path.join(_rn_root, ".github", "workflows", "*.yml"))):
    with open(_rq_wf, encoding="utf-8") as _rq_fh:
        _rq_txt = _rq_fh.read()
    _rq_body = _rq_txt[_rq_txt.index("\njobs:\n"):]
    _rq_list = []
    for _jm in _sg_re.finditer(r"^  ([A-Za-z0-9_-]+):\n((?:    .*\n|\n)*)", _rq_body, _sg_re.M):
        _nm = _sg_re.search(r"^    name: (.+)$", _jm.group(2), _sg_re.M)
        _tpl = _nm.group(1).strip() if _nm else _jm.group(1)
        _rx = "".join("(.+?)" if _sg_re.fullmatch(r"\$\{\{[^}]*\}\}", _part) else _sg_re.escape(_part)
                      for _part in _sg_re.split(r"(\$\{\{[^}]*\}\})", _tpl))
        _rq_list.append((_tpl, _rx))
    _rq_jobs[os.path.basename(_rq_wf)] = (_rq_txt, _rq_list)

_rq_bad, _rq_hosts = [], set()
for _app, _name in _rq:
    if _app != "github-actions":
        if _app not in ("codacy-production", "sonarqubecloud"):
            _rq_bad.append("%s: not an app this list knows" % _app)
        continue
    _hits = [(_wf, _tpl, _m) for _wf, (_txt, _jl) in _rq_jobs.items() for _tpl, _rx in _jl
             for _m in [_sg_re.fullmatch(_rx, _name)] if _m]
    if not _hits:
        _rq_bad.append("%r: no workflow job has this name" % _name)
        continue
    for _wf, _tpl, _m in _hits:
        _txt = _rq_jobs[_wf][0]
        _on_pr, _filtered = _rq_on_pr(_txt)
        if not _on_pr or _filtered:
            _rq_bad.append("%r: %s does not run on every pull request" % (_name, _wf))
        # A matrix value named in the check must still be in the matrix: dropping ubuntu-22.04 or
        # Python 3.10 from it renames the check, and the ruleset would wait for the old name.
        for _val in _m.groups():
            if _sg_re.search(r"[\s\x22'\[,]%s[\s\x22',\]]" % _sg_re.escape(_val), _txt) is None:
                _rq_bad.append("%r: %s's matrix has no %r" % (_name, _wf, _val))
        _rq_hosts.add(_wf)
for _wf in sorted(_rq_hosts):
    for _tpl, _rx in _rq_jobs[_wf][1]:
        if not any(_a == "github-actions" and _sg_re.fullmatch(_rx, _n) for _a, _n in _rq):
            _rq_bad.append("%s: job %r is not a required check" % (_wf, _tpl))
check("required checks: each one is a job of a workflow that runs on every pull request, and "
      "every job of those workflows is required",
      len(_rq) >= 18 and not _rq_bad
      and {"ci.yml", "codeql.yml", "security-code.yml", "security.yml", "lighthouse.yml",
           "complexity.yml"} <= _rq_hosts,
      repr((_rq_bad[:6], sorted(_rq_hosts))))
check("required checks: ...and the list includes Codacy, SonarCloud, the tests, CodeQL's gate and the "
      "complexity gate",
      {("codacy-production", "Codacy Static Code Analysis"),
       ("sonarqubecloud", "SonarCloud Code Analysis"),
       ("github-actions", "Open code-scanning alerts (PR)"),
       ("github-actions", "complexity (Codacy limits)")} <= set(_rq)
      and sum(1 for _a, _n in _rq if _n.startswith("checks (")) >= 3, repr(_rq))
# The complexity gate: its own pull-request-only workflow (never on main, where the update gate
# would read a skipped job), hash-pinned tools, and its self-test before its verdict.
_cx = _rq_jobs.get("complexity.yml", ("", []))[0]
check("complexity gate: pull requests only, hash-pinned Lizard and Pylint, self-test first",
      _rq_on_pr(_cx) == (True, False) and "\n  push:" not in _cx
      and "-r .github/ci-requirements/complexity.txt" in _cx
      and -1 < _cx.find("complexity_gate.py --self-test") < _cx.rfind("complexity_gate.py\n"),
      _cx[-600:])
# Fuzz and ClusterFuzzLite are required too, so they run on every pull request; a pull request that
# changes nothing they fuzz passes at once. That is a scope step's job, first in each: it must list
# what the old path filter listed (the harnesses' modules, the fuzz tree, what the job installs),
# and every step that builds or fuzzes must wait on it.
_sc_bad = []
for _sc_wf, _sc_must in (("fuzz.yml", ("panel/ops/ssh_manager/**", "panel/ops/system_ops.py",
                                       "panel/core/terminal.py", "tests/fuzz/**", "requirements.txt",
                                       ".github/ci-requirements/atheris.txt")),
                         ("cflite_pr.yml", ("panel/ops/ssh_manager/**", "panel/ops/system_ops.py",
                                            "panel/core/terminal.py", "tests/fuzz/**",
                                            ".clusterfuzzlite/**", "requirements.txt"))):
    _sc_txt = _rq_jobs.get(_sc_wf, ("", []))[0]
    _sc_steps = _sc_txt[_sc_txt.find("    steps:\n"):]
    _sc_at = _sc_steps.find("        id: scope\n")
    _sc_list = _sc_steps[_sc_steps.find("scope=(", _sc_at):_sc_steps.find("            )", _sc_at)]
    _sc_after = [_b for _b in _sc_steps[_sc_at:].split("\n      - ")[1:]
                 if _sg_re.search(r"(uses: (actions/checkout|actions/setup-python|google/clusterfuzzlite)"
                                  r"|^name: (Install|Fuzz))", _b, _sg_re.M)]
    if _sc_at < 0 or _sc_steps.find("\n      - ") < _sc_at - 400:
        _sc_bad.append("%s: no scope step first" % _sc_wf)
    _sc_bad += ["%s: scope lacks %s" % (_sc_wf, _w) for _w in _sc_must if "'%s'" % _w not in _sc_list]
    _sc_bad += ["%s: a step runs without the scope: %s" % (_sc_wf, _b.splitlines()[0])
                for _b in _sc_after if "steps.scope.outputs.run == 'true'" not in _b]
    if len(_sc_after) < 2:
        _sc_bad.append("%s: read %d gated steps" % (_sc_wf, len(_sc_after)))
check("fuzz workflows: a scope step first, listing what the path filter did, and every build or fuzz "
      "step waits on it",
      not _sc_bad, repr(_sc_bad))
# SonarCloud's free-plan gate cannot be made "0 new issues", so a required job checks that itself:
# pull requests only, self-test first, the pull request's number and head commit passed as env.
_sn = _rq_jobs.get("sonar-new-issues.yml", ("", []))[0]
check("SonarCloud new issues: pull requests only, self-test first, the head commit from the event",
      _rq_on_pr(_sn) == (True, False) and "\n  push:" not in _sn
      and -1 < _sn.find("sonar_new_issues.py --self-test") < _sn.find("sonar_new_issues.py --pr")
      and "SHA: ${{ github.event.pull_request.head.sha }}" in _sn
      and '--sha "$SHA"' in _sn and "${{ github.event.pull_request.head.sha }}\n" not in _sn.split(
          "run:")[-1], _sn[-500:])
check("required checks: ...including SonarCloud's zero-new-issues job, Dependency Review, actionlint "
      "and every fuzz job",
      {("github-actions", "SonarCloud new issues"), ("github-actions", "Dependency Review"),
       ("github-actions", "actionlint"), ("github-actions", "fuzz the diff (address)")} <= set(_rq)
      and sum(1 for _a, _n in _rq if _n.startswith("fuzz (")) == 6, repr(_rq))


# ── SonarCloud reads only UTF-8 ─────────────────────────────────────────────────────────────────
# Its analysis warned "There are problems with file encoding" for two literal U+FFFD characters in
# tests (part01, part13): the scanner reports every U+FFFD as "Invalid character encountered", in a
# file that is valid UTF-8. Found only by running the scanner locally, after three guesses (vendor
# files, images, a NUL in the fuzz corpus) were each merged and left it standing. Every file it reads,
# sources and tests, that no exclusion covers must decode, and hold no U+FFFD (write "\ufffd") and
# no NUL (its charset detection refuses a file with one).
import fnmatch as _sq_fnm  # noqa: E402

with open(os.path.join(_rn_root, ".sonarcloud.properties"), encoding="utf-8") as _sq_fh:
    _sq_props = dict(_l.split("=", 1) for _l in _sq_fh.read().splitlines()
                     if "=" in _l and not _l.lstrip().startswith("#"))
_sq_excl = [_p.strip() for _p in _sq_props.get("sonar.exclusions", "").split(",") if _p.strip()]
_sq_texcl = [_p.strip() for _p in _sq_props.get("sonar.test.exclusions", "").split(",") if _p.strip()]


def _sq_excluded(path, pats=None):
    """Sonar's `**/` matches any depth, zero included: try the pattern with and without it."""
    return any(_sq_fnm.fnmatchcase(path, _p) or (_p.startswith("**/")
                                                 and _sq_fnm.fnmatchcase(path, _p[3:]))
               for _p in (_sq_excl if pats is None else pats))


_sq_bad, _sq_walk = [], []
for _sq_dp, _sq_dns, _sq_fns in os.walk(_rn_root):
    _sq_dns[:] = [_d for _d in _sq_dns if _d not in (".git", "data", "venv", ".venv", "env",
                                                     "__pycache__", ".pytest_cache", "node_modules",
                                                     ".idea", ".vscode", ".claude")]
    _sq_walk += [os.path.relpath(os.path.join(_sq_dp, _f), _rn_root).replace(os.sep, "/")
                 for _f in _sq_fns if not _f.endswith((".pyc", ".db", ".run.log"))]
for _sq_f in _sq_walk:
    if (_sq_excluded(_sq_f, _sq_texcl) if _sq_f.startswith("tests/") else _sq_excluded(_sq_f)):
        continue
    with open(os.path.join(_rn_root, _sq_f), "rb") as _sq_fh:
        _sq_b = _sq_fh.read()
    try:
        _sq_b.decode(_sq_props.get("sonar.sourceEncoding", "UTF-8").strip())
    except UnicodeDecodeError:
        _sq_bad.append(_sq_f)
        continue
    if b"\0" in _sq_b:
        _sq_bad.append(_sq_f + " (NUL)")
    if "\ufffd".encode("utf-8") in _sq_b:
        _sq_bad.append(_sq_f + " (U+FFFD)")
check("sonarcloud: every file it reads, sources and tests, is UTF-8 with no U+FFFD and no NUL",
      len(_sq_walk) >= 300 and not _sq_bad and _sq_excluded("docs/screenshots/01-dashboard.png")
      and _sq_excluded("a.png") and not _sq_excluded("panel/x.py")
      and _sq_excluded("tests/fuzz/corpus/console/esc_control", _sq_texcl),
      repr(_sq_bad[:6]))

# ── ...and what SonarCloud reads is pinned here, so narrowing it has to change this test ────────
# A pull request that adds a subtree to sonar.exclusions (or a sonar.inclusions that leaves one
# out) takes those files out of the analysis: the pull request shows no new issues in them, and on
# main their issues close as if fixed. Both Sonar checks stay green while judging less. The keys,
# the source and test roots and every exclusion are pinned, and every source file the scanner could
# read (Python, JavaScript, templates, shell, outside tests/ and static/vendor/) must not be
# excluded, so a scope change is a change to this test as well.
_sq_allowed_excl = {"tests/**", "static/vendor/**", "**/*.png", "**/*.jpg", "**/*.jpeg", "**/*.gif",
                    "**/*.webp", "**/*.ico", "**/*.woff", "**/*.woff2", "**/*.ttf"}
_sq_keys = {_k.strip(): _v.strip() for _k, _v in _sq_props.items()}
_sq_src = [_f for _f in _sq_walk if _f.endswith((".py", ".js", ".html", ".sh"))
           and not _f.startswith(("tests/", "static/vendor/"))]
_sq_scope_bad = (
    ["keys: %r" % sorted(_sq_keys)] * (set(_sq_keys) != {
        "sonar.python.version", "sonar.sources", "sonar.tests", "sonar.exclusions",
        "sonar.test.exclusions", "sonar.sourceEncoding"})
    + ["sonar.sources=%r" % _sq_keys.get("sonar.sources")] * (_sq_keys.get("sonar.sources") != ".")
    + ["sonar.tests=%r" % _sq_keys.get("sonar.tests")] * (_sq_keys.get("sonar.tests") != "tests")
    + ["exclusion %r is not one of the pinned set" % _p for _p in _sq_excl
       if _p not in _sq_allowed_excl]
    + ["sonar.test.exclusions=%r" % _sq_texcl] * (_sq_texcl != ["tests/fuzz/corpus/**"])
    + ["%s is excluded" % _f for _f in _sq_src if _sq_excluded(_f)])
check("sonarcloud: its scope is pinned (keys, roots, exclusions) and excludes no source file",
      not _sq_scope_bad and len(_sq_src) >= 150
      and {"app.py", "install.sh", "panel/ops/system_ops.py", "templates/base.html",
           "static/js/panel.js"} <= set(_sq_src),
      repr((_sq_scope_bad[:6], len(_sq_src))))

# ── CodeQL analyses a pull request in FULL, as main does ───────────────────────────────────────
# By default the action is diff-informed on a PR: it reports alerts only on the lines the PR
# changes. #387 removed the last use of a module global on a line it left alone; its PR gate read
# 0 alerts and main went red on py/unused-global-variable. The analyze job must switch the
# feature off (codeql-action src/feature-flags.ts: CODEQL_ACTION_DIFF_INFORMED_QUERIES).
with open(os.path.join(_rn_root, ".github", "workflows", "codeql.yml"), encoding="utf-8") as _cq_fh:
    _cq_src = _cq_fh.read()
_cq_job = _cq_src.split("\n  analyze:\n", 1)[-1].split("\n  pr-alerts", 1)[0].split("\n    steps:\n", 1)[0]
check("codeql: the analyze job turns diff-informed analysis OFF, so a PR is judged on every alert",
      '\n    env:\n      CODEQL_ACTION_DIFF_INFORMED_QUERIES: "false"\n' in _cq_job, _cq_job[-600:])
