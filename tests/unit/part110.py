"""Part 110 of the unit suite: the nineteenth review's panel-host fixes (review 1017b, builder A).

* A panel-host reboot whose host row could not be READ is refused (503), never sent bare: a bare
  reboot kills the host's game servers and brings none back (owner's clean-reboot rule).
* Every reader of "the panel's port" that means the port it serves NOW asks the bound port
  (config.bound_port, BOOT_PORT), not config.json's, which is the next start's: Serve Enable/Disable
  and the Tailscale page, Close public panel port and its status, the firewall's lock-out guard and
  the ports no game server may take, the debug report's jail and port-conflict checks, and the setup
  wizard's "still answers on" line. A failed restart after a port move also records the old port
  back for the helper, which publishes only the port panel.conf names.
* A second database Repair while the first is starting is refused (it launched a second concurrent
  job on per-user installs), and a panel-host reboot is refused while a repair is starting.
* The helper's restore copy and folder download never block opening a fifo staged or swapped in.
* The debug report's downloadable file no longer says the panel runs as root through the Recent
  log's source label, nor the panel account's sudo/admin/wheel groups (page-only, like **Runs as**).

HOW IT RUNS. Routes on part12's app with every host call stubbed; the helper in a child python under
part43's bounded runner (a blocked fifo open is killed with its group, never left behind); the debug
report's sections with their reads stubbed. Nothing reaches a host, sudo or the checkout's data/.
"""
import contextlib as _ctx110
import io as _io110
import os
import shutil as _shutil110
import sys as _sys110
import tarfile as _tar110
import tempfile as _tf110
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _h110, _root
from unit.part12 import (P9_ADMIN, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client, _p9_core, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_so, _p9_ts)
from unit.part20 import _jl as _jl110
from unit.part43 import _run_bounded43
from unit.part108 import _ANY108
from panel.core import i18n as _i18n110
from panel.db.models import AuditLog, db
from panel.ops import backup as _bk110
from panel.ops.debug_report import _base as _base110
from panel.ops.debug_report import _src_journal as _sj110
from panel.ops.debug_report import hosts as _dh110
from panel.ops.debug_report import install as _in110
from panel.ops.debug_report import logs as _lg110
from panel.ops.debug_report import network as _nw110
from panel.ops.ssh_manager import firewall as _fw110
from panel.ops.ssh_manager import hosts as _hosts110
from panel.ops.ssh_manager import ufweval as _ue110
from panel.routes import panel_backup as _pb110
from panel.routes import remote_security as _rs110
from panel.routes import remote_vps as _rv110
from panel.routes import route_helpers as _rh110
from panel.services import host_reboot as _hr110
from panel.services import reboot_words as _rw110

_TRIP110_START = len(_P9_TRIPPED)
_TMP110 = _tf110.mkdtemp(prefix="lgsm-unit-p110-")


@_ctx110.contextmanager
def _bound110(port):
    """Bind this app to `port` (BOOT_PORT), or to nothing known when None; put back after."""
    had, was = "BOOT_PORT" in _p9.config, _p9.config.get("BOOT_PORT")
    _p9.config.pop("BOOT_PORT", None)
    if port is not None:
        _p9.config["BOOT_PORT"] = port
    try:
        yield
    finally:
        _p9.config.pop("BOOT_PORT", None)
        if had:
            _p9.config["BOOT_PORT"] = was


def _saved_port110(port, **more):
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), port=port, **more))


# ── 1. the reboot route never reboots bare on an unread host row ─────────────────────────────────
class _Unread110:
    """RemoteServer for the reboot route, whose host-row read raises (or finds nothing)."""

    def __init__(self, raises):
        self.raises = raises

    @property
    def query(self):
        return self

    def filter_by(self, **_k):
        return self

    def first(self):
        if self.raises:
            raise RuntimeError("database is locked (part110)")
        return None


def _reboot110(client):
    sent = []
    _p9_patch(_p9_so, "server_reboot", lambda delay=5: (sent.append(delay), (True, "Server will reboot"))[1])
    got = {}
    for case, raises in (("row unread", True), ("no row", False)):
        _p9_patch(_pb110, "RemoteServer", _Unread110(raises))
        n0 = len(sent)
        r = client.post("/api/server-management/reboot", json={"delay": 5})
        got[case] = (r.status_code, _p9_json(r).get("error"), len(sent) - n0)
    check("reboot route: a panel-host row that could not be READ refuses with a 503 and sends no reboot (it "
          "fell through to a bare reboot that kills the host's game servers and brings none back)",
          got["row unread"] == (503, "host_unread", 0), repr(got))
    check("reboot route: ...while a read that worked and found no row (no servers on the panel's host) "
          "still reboots as before (control)", got["no row"][0] == 200 and got["no row"][2] == 1, repr(got))


# ── 2. the port this process serves on ───────────────────────────────────────────────────────────
def _serve110(client):
    seen = {}
    _p9_patch(_p9_ts, "disable_tailscale_serve",
              lambda mount, port: (seen.setdefault("disable", []).append(port), (True, "removed"))[1])
    _p9_patch(_p9_ts, "setup_tailscale_serve",
              lambda **k: (seen.setdefault("enable", []).append(k.get("port")), (False, "p110 stop"))[1])
    _saved_port110(5077, bind_host=_ANY108, tailscale_setup_done=True)
    with _bound110(5000):
        client.post("/api/tailscale/serve", json={"action": "disable", "mount": "/"})
        client.post("/api/tailscale/serve", json={"action": "enable", "mount": "/", "funnel": False})
    with _bound110(None):
        client.post("/api/tailscale/serve", json={"action": "disable", "mount": "/"})
    check("Tailscale Serve: with a saved port change waiting for its restart, Disable and Enable act on the "
          "port the panel serves on (Disable found no route at config.json's port, so a Funnelled panel "
          "could not be taken off the internet, and Enable published a port nothing listened on)",
          seen.get("disable", [])[:1] == [5000] and seen.get("enable") == [5000], repr(seen))
    check("Tailscale Serve: ...and with no bound port known, config.json's port as before (control)",
          seen.get("disable", [])[1:] == [5077], repr(seen))


def _rules110(ports):
    """`ufw status numbered` rows: 22, then each of `ports`, open to everyone."""
    return [{"num": str(i + 1), "detail": "%s/tcp  ALLOW IN  Anywhere" % p}
            for i, p in enumerate([22] + list(ports))]


def _close110(client, bound, rules_ports):
    """Close public panel port on a stand-in firewall holding `rules_ports`: (reply, the ports left open)."""
    rules = _rules110(rules_ports)

    def status(remote):
        return {"installed": True, "enabled": True, "rules": list(rules),
                "groups": _fw110._group_ufw_rules([dict(r) for r in rules])}

    def delete(remote, n, force=False, expect_key=None):
        rules[:] = [dict(r, num=str(i + 1)) for i, r in enumerate(x for x in rules if x["num"] != str(n))]
        return True, "deleted"
    _p9_patch(_rv110, "remote_ufw_status", status)
    _p9_patch(_rv110, "remote_ufw_delete_rule", delete)
    _p9_patch(_rv110._fw_rules, "remote_ufw_default_allows_in", lambda remote: False)
    _saved_port110(5077, tailscale_setup_done=True)
    with _bound110(bound):
        r = client.post("/api/remote/%d/close-panel-port" % P9_LOCAL)
    return _p9_json(r), sorted(int(x["detail"].split("/")[0]) for x in rules if not x["detail"].startswith("22/"))


def _close_port110(client):
    both, left = _close110(client, 5000, [5000, 5077])
    check("close panel port: with a port change waiting for its restart, BOTH of the panel's ports close: "
          "the one it serves on and the saved one (it closed config.json's alone, left the served port "
          "open and said the panel was reachable only over the tailnet)",
          both.get("success") is True and left == [], repr((both, left)))
    only, left_o = _close110(client, None, [5000, 5077])
    check("close panel port: ...and with no bound port known, config.json's port alone, as before (control)",
          only.get("success") is True and left_o == [5000], repr((only, left_o)))


def _status110(client):
    plain = ("Status: active\n\nTo                         Action      From\n"
             "--                         ------      ----\n"
             "5000/tcp                   ALLOW       Anywhere\n")
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: (plain, "", 0)
              if verb == "ufw-status" else ("", "p110: unexpected verb", 1))
    _p9_patch(_rv110, "_r26b_sshd_ports", lambda remote: [])
    # The status reads sshd's ports itself now (review 1017c): ssh.socket answers nothing here.
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    _saved_port110(5077)
    got = {}
    for case, bound in (("bound 5000", 5000), ("no bound port", None)):
        with _bound110(bound):
            got[case] = _p9_json(client.get("/api/remote/%d/ssh-status" % P9_LOCAL)).get("panel_port_open")
    check("ssh-status: the public panel port reads open while the port the panel serves on is open (it read "
          "config.json's saved port, so Close public panel port was disabled with the served port open)",
          got == {"bound 5000": True, "no bound port": False}, repr(got))


def _guard110():
    rows = _rules110([5000, 5077])
    _p9_patch(_fw110, "_fwssh_served_ports", lambda server: [22])
    _p9_patch(_fw110, "_live_tailscale_state", lambda server, enabled, groups: (False, False))
    _p9_patch(_fw110, "_panel_served_over_tailscale", lambda server: False)
    _p9_patch(_hosts110, "_sshd_current_ports", lambda server: [22])
    _p9_patch(_ue110, "local_addrs", lambda: None)   # the panel host's addresses (ufweval): unread
    _saved_port110(5077, tailscale_setup_done=False)
    got = {}
    for case, bound in (("bound 5000", 5000), ("no bound port", None)):
        with _bound110(bound), _p9.app_context():
            gs = _fw110._annotate_firewall_protection(NS(is_local=True), True,
                                                      _fw110._group_ufw_rules([dict(r) for r in rows]))
            got[case] = (sorted(g["port_num"] for g in gs if g.get("is_panel") and g.get("protected")),
                         sorted(_hosts110.protected_host_ports(NS(is_local=True))))
    check("firewall guard: with a port change waiting for its restart, the rule for the port the panel "
          "serves on is protected as the way in, and the saved port's too (only config.json's was: the "
          "live rule was an ordinary delete x)",
          got["bound 5000"][0] == ["5000", "5077"], repr(got))
    check("firewall guard: ...and no game server may take either port", got["bound 5000"][1] == [22, 5000, 5077],
          repr(got))
    check("firewall guard: ...with no bound port known, config.json's port alone (control)",
          got["no bound port"] == (["5077"], [22, 5077]), repr(got))


def _jail_report110():
    jail = os.path.join(_TMP110, "jail.local")
    with open(jail, "w", encoding="utf-8") as fh:
        fh.write("[linuxgsm-panel]\n")
    asked = []
    _p9_patch(_p9_so, "_F2B_PANEL_JAIL", jail)
    _p9_patch(_p9_so, "panel_jail_health", lambda log, port, wl=None: (asked.append(port), dict(
        logpath=True, port=port == 5002, backend=True, allports=False, banaction=True, ignoreip=True,
        filter=True))[1])
    _p9_patch(_nw110, "_load_cfg", lambda: ({"port": 5003}, True))
    _p9_patch(_nw110, "bounded", lambda ctx, jobs, reserve=0.5: {n: ("timeout", None) for n, _f in jobs})
    sec = _nw110.section_network(NS(app=NS(config={"BOOT_PORT": 5002})))
    text = "\n".join(sec.lines + sec.page_lines)
    check("debug report: the panel-login jail's port is checked against the port the panel serves on (with "
          "a port change waiting for its restart, a correct jail read 'port = config' x)",
          asked == [5002] and "port = served port ✓" in text, repr((asked, text[-400:])))


def _conflicts110():
    _p9_patch(_dh110, "host_cols", lambda ctx: [{"id": 1, "transport": "local", "port": 22}])
    _p9_patch(_dh110, "gs_cols", lambda ctx: [{"id": 7, "remote_id": 1, "port": 5000, "query_port": None,
                                              "game_type": "gmod"}])
    _saved_port110(5077)
    ctx = NS(app=NS(config={"BOOT_PORT": 5000}), memo=lambda key, fn: fn())
    got = _dh110.port_conflicts(ctx)
    check("debug report: a game server on the port the panel serves on is a conflict (it compared "
          "config.json's saved port, and missed the one that makes a crashed server look healthy)",
          [(c[0], c[1]) for c in got if c[2]] == [(1, 5000)], repr(got))


def _complete110():
    _saved_port110(5077)
    with _bound110(5000), _p9.app_context():
        facts = _rh110._complete_facts(_p9_cfg.load_config())
    check("setup wizard: the complete page's 'still answers on' address names the port the panel serves "
          "on, not the one a restart moves it to", facts.get("panel_port") == 5000, repr(facts))


def _record_back110(client):
    recorded = []
    _p9_patch(_rs110, "remote_ufw_close_port", lambda *a, **k: (True, "closed"))
    _p9_patch(_rs110, "remote_ufw_open_port", lambda *a, **k: (True, "opened"))
    _p9_patch(_p9_so, "ensure_panel_fail2ban", lambda log, port, wl=None: (True, "jail"))
    _p9_patch(_p9_so, "panel_fail2ban_status", lambda: {"installed": True})
    _p9_patch(_p9_so, "port_in_use", lambda port: False)
    _p9_patch(_p9_so, "record_panel_port", lambda port: (recorded.append(int(port)), (True, ""))[1])
    got = {}
    for case, ok in (("restart failed", False), ("restart scheduled", True)):
        _p9_patch(_p9_so, "restart_panel", lambda *a, _ok=ok, **k: (_ok, "p110"))
        _saved_port110(5000, bind_host=_ANY108, tailscale_setup_done=True)
        del recorded[:]
        r = client.post("/api/panel/change-port", json={"port": 5077, "bind_host": _ANY108})
        got[case] = (_p9_json(r).get("success"), list(recorded))
    check("panel port: a move whose restart could not be scheduled records the old port back as the panel's "
          "for the helper (it publishes only that port, so Enable on the Tailscale page was refused)",
          got["restart failed"] == (False, [5077, 5000]), repr(got))
    check("panel port: ...and a move whose restart was scheduled records only the new port (control)",
          got["restart scheduled"] == (True, [5077]), repr(got))


# ── 3. one database repair at a time, and no panel-host reboot beside it ────────────────────────
def _repair110(client):
    base = os.path.join(_TMP110, "checkout")
    os.makedirs(os.path.join(base, "venv", "bin"))
    for f in (("venv", "bin", "python3"), ("db_maintenance.py",)):
        with open(os.path.join(base, *f), "w", encoding="utf-8") as fh:
            fh.write("")
    launched = []
    saved = dict(_p9_so._r30a_repair_launched)
    _p9_patch(_p9_so, "PANEL_DIR", base)
    _p9_patch(_p9_so, "_r30a_repair_launch", lambda b, py, dbm: (launched.append(b), (True, "repairing"))[1])
    _p9_patch(_p9_so, "_update_in_progress", lambda: False)
    _p9_patch(_bk110, "restore_pending", lambda: False)
    _p9_so._r30a_repair_launched.update(ts=0.0, dir="")
    try:
        first = _p9_json(client.post("/api/panel/repair-db"))
        ts_first = _p9_so._r30a_repair_launched["ts"]
        second = _p9_json(client.post("/api/panel/repair-db"))
        kept = _p9_so._r30a_repair_launched["ts"] == ts_first
        blockers = _hr110._panel_host_blockers()
    finally:
        _p9_so._r30a_repair_launched.clear()
        _p9_so._r30a_repair_launched.update(saved)
    check("database repair: a second Repair while the first is starting is refused and launches nothing (on "
          "a per-user install it scheduled a second job rewriting the same database)",
          first.get("success") is True and second.get("success") is False and launched == [base]
          and "already starting" in str(second.get("message")), repr((first, second, launched)))
    check("database repair: ...and the refused click leaves the first one's record as it was", kept, repr(kept))
    check("panel-host reboot: refused while a database repair is starting (the repair can put back a rolling "
          "backup older than the reboot's plan, and the stopped servers then stayed stopped)",
          [b["kind"] for b in blockers] == ["db_repair"], repr(blockers))
    what = _rw110.blocked_sentence(blockers)
    words = [_i18n110.translate(lang, "a database repair of the panel") for lang in ("es", "fr")]
    check("panel-host reboot: ...and that refusal names the repair as the panel's own work, in the viewer's "
          "language (not 'work on the panel')",
          "a database repair of the panel" in str(what) and all(w != "a database repair of the panel" for w in words),
          repr((str(what), words)))


# ── 4. the helper never blocks opening a fifo ────────────────────────────────────────────────────
_HELPER110 = ("import importlib.machinery as m, importlib.util as u, sys\n"
              "ld = m.SourceFileLoader('panel_helper_p110', sys.argv[1])\n"
              "h = u.module_from_spec(u.spec_from_loader(ld.name, ld))\n"
              "ld.exec_module(h)\n")
_RESTORE110 = _HELPER110 + "print('COPIED', ','.join(h.restore_copy_members(sys.argv[2], sys.argv[3])))\n"
# The race: the entry's lstat says "regular file", and by the open it is a fifo.
_TAR110 = _HELPER110 + (
    "import io, os as _os, tarfile\n"
    "class _Os:\n"
    "    def __getattr__(self, n):\n"
    "        return getattr(_os, n)\n"
    "    def lstat(self, p, *a, **k):\n"
    "        return _os.stat(sys.argv[3]) if p == sys.argv[2] else _os.lstat(p, *a, **k)\n"
    "h.os = _Os()\n"
    "with tarfile.open(fileobj=io.BytesIO(), mode='w|gz') as tf:\n"
    "    h._r31a_tar_add(tf, sys.argv[2], 'x')\n"
    "    print('ADDED', len(tf.getmembers()))\n")


def _helper_run110(code, *args):
    return _run_bounded43([_sys110.executable, "-I", "-c", code, os.path.join(_root, "tools", "panel-helper")]
                          + list(args))


def _fifo_restore110():
    stage, data = os.path.join(_TMP110, "stage"), os.path.join(_TMP110, "data")
    os.makedirs(stage)
    os.makedirs(data)
    os.mkfifo(os.path.join(stage, "panel.db"), 0o600)
    with open(os.path.join(stage, "config.json"), "w", encoding="utf-8") as fh:
        fh.write("{}\n")
    out, err, rc = _helper_run110(_RESTORE110, stage, data)
    check("helper restore: a fifo staged under a member name is skipped, and the other members still copy "
          "(root's open waited for a writer for ever, with the panel already stopped)",
          rc == 0 and "COPIED config.json" in out and not os.path.exists(os.path.join(data, "panel.db")),
          "rc %r %r %r" % (rc, out, err[-300:]))


def _fifo_tar110():
    fifo, reg = os.path.join(_TMP110, "swapped"), os.path.join(_TMP110, "regular")
    os.mkfifo(fifo, 0o600)
    with open(reg, "w", encoding="utf-8") as fh:
        fh.write("x\n")
    out, err, rc = _helper_run110(_TAR110, fifo, reg)
    check("helper folder download: a file swapped for a fifo between its lstat and its open is skipped, never "
          "waited on (tarfile.add plain-opened it, parking the download until the transport gave up)",
          rc == 0 and "ADDED 0" in out, "rc %r %r %r" % (rc, out, err[-300:]))


def _tar_same110():
    """The rewritten walk archives what tarfile.add did: files, a subfolder, a symlink, a hard link, a fifo."""
    top = os.path.join(_TMP110, "game")
    os.makedirs(os.path.join(top, "sub"))
    for name, body in (("a.cfg", "one\n"), (os.path.join("sub", "b.txt"), "two\n" * 50)):
        with open(os.path.join(top, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    os.symlink("a.cfg", os.path.join(top, "link"))
    os.link(os.path.join(top, "a.cfg"), os.path.join(top, "hard"))
    os.mkfifo(os.path.join(top, "pipe"), 0o600)

    def members(fn):
        buf = _io110.BytesIO()
        fn(buf)
        with _tar110.open(fileobj=_io110.BytesIO(buf.getvalue()), mode="r:gz") as tf:
            return sorted((m.name, m.type, m.size, m.linkname,
                           tf.extractfile(m).read() if m.isreg() else b"") for m in tf.getmembers())

    def reference(buf):
        with _tar110.open(fileobj=buf, mode="w|gz") as tf:
            tf.add(top, arcname="game", recursive=False)
            for root, dirs, files in os.walk(top):
                for name in dirs + files:
                    full = os.path.join(root, name)
                    tf.add(full, arcname=os.path.join("game", os.path.relpath(full, top)), recursive=False)
    new, old = members(lambda b: _h110._emit_dir_tar(top, b)), members(reference)
    check("helper folder download: an ordinary folder archives exactly as before (files and their bytes, a "
          "subfolder, a symlink as a link, a second hard link as a link, a fifo as an entry)",
          new == old and len(new) == 7, repr((new, old)))


# ── 5. the downloadable debug report keeps the privilege model page-only ────────────────────────
def _report_privilege110():
    got = {}
    for source in ("root", "helper"):
        _p9_patch(_sj110, "read", lambda max_lines=5000, timeout=10, _s=source: {
            "source": _s, "lines": [_jl110(i, "panel line %d" % i, pid=11) for i in range(3)], "why": None})
        res = _lg110.section_recent_log(_base110.Ctx(app=None, deadline_s=20.0))
        got[source] = ("\n".join(res.lines), "\n".join(res.page_lines))
    check("debug report: the Recent log's source line in the file is the same for the helper and for a "
          "panel running as root ('read directly' named the privilege model in a public attachment)",
          all("- **Source**: system journal · " in f and "read directly" not in f and "helper" not in f
              for f, _p in got.values()), repr(got))
    check("debug report: ...and which privileged read it was is on the page only",
          "read directly" in got["root"][1] and "via the privileged helper" in got["helper"][1], repr(got))


def _report_groups110():
    res = _base110.Result()
    for name, fn in (("_model", lambda: ("system", "system service", "a login account (uid 1000)")),
                     ("_interpreter", lambda: "p110"), ("_under_unit", lambda: "p110"),
                     ("panel_conf_text", lambda: "p110"), ("_groups", lambda: ["sudo"])):
        _p9_patch(_in110, name, fn)
    _in110._identity_lines(res, {})
    check("debug report: the panel account's groups (sudo, admin, wheel) are on the page only, like Runs as",
          not any("Groups" in ln for ln in res.lines)
          and any("Groups" in ln and "sudo" in ln for ln in res.page_lines), repr((res.lines, res.page_lines)))


_CFG110 = _p9_cfg.load_config()
with _p9.app_context():
    _AUDIT110 = db.session.query(db.func.max(AuditLog.id)).scalar() or 0
try:
    _p9_arm(who="part110")
    _A110 = _p9_client(P9_ADMIN)
    _reboot110(_A110)
    _p9_restore_all()
    _p9_arm(who="part110")
    for _fn110 in (_serve110, _close_port110, _status110, _record_back110, _repair110):
        _fn110(_A110)
        _p9_restore_all()
        _p9_arm(who="part110")
    for _fn110 in (_guard110, _jail_report110, _conflicts110, _complete110, _report_privilege110,
                   _report_groups110):
        _fn110()
        _p9_restore_all()
        _p9_arm(who="part110")
    _fifo_restore110()
    _fifo_tar110()
    _tar_same110()
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG110)
    _shutil110.rmtree(_TMP110, ignore_errors=True)
    with _p9.app_context():
        # This part's own rows only: later parts count from their own start.
        AuditLog.query.filter(AuditLog.id > _AUDIT110).delete(synchronize_session=False)
        db.session.commit()

check("part110: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP110_START, repr(_P9_TRIPPED[_TRIP110_START:][:6]))
