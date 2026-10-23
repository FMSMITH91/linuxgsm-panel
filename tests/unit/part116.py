"""Part 116 of the unit suite: the twentieth review's panel-host fixes (review 1017c, builder A).

* Every reader of the panel's port or bind address that means where it serves NOW asks this
  process (BOOT_PORT / BOOT_BIND / BOOT_TLS), not config.json, which is the next start's: the
  change-port route's "current" port (its refusal, the old rule's close, the rollback's jail and
  helper record), the Tailscale page's Disable lock-out guard and its direct-link scheme, the
  Public panel access label, the login jail's all-ports choice, the debug report's HSTS and
  Serve-scheme lines, manage.py's setup link, and the two scripts that run outside the process:
  install.sh's port record on an update that restarts nothing, and uninstall.sh's firewall and
  Serve teardown (the root-owned panel.conf's port too).
* The downloadable debug report never tells which system-journal read was made or tried: the
  file's lines are the same whether the panel runs as root, through the helper, or unprivileged.
* The helper's folder download pads a file that shrank while being read, and names it in the
  archive, instead of writing a .tar.gz no tool can open.

HOW IT RUNS. Routes on part12's app with every host call stubbed; the debug report's sections with
their reads stubbed; the helper loaded in-process (part05); install.sh's and uninstall.sh's own text
under bash with shell stand-ins and a real listening socket of this process. Nothing reaches a host,
sudo or the checkout's data/.
"""
import contextlib as _ctx116
import io as _io116
import os
import runpy as _runpy116
import shutil as _shutil116
import socket as _sock116
import subprocess as _sp116  # nosec B404 - bash over this checkout's own scripts, fixed argv
import tarfile as _tar116
import tempfile as _tf116
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _h116, _root
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_so, _p9_ts)
from unit.part20 import _jl as _jl116
from unit.part108 import _ANY108
from panel.db.models import AuditLog, db
from panel.ops.debug_report import _base as _base116
from panel.ops.debug_report import logs as _lg116
from panel.ops.debug_report import network as _nw116
from panel.ops.debug_report import process as _pr116
from panel.routes import remote_security as _rs116
from panel.routes import tailscale as _tsr116

_TRIP116_START = len(_P9_TRIPPED)
_TMP116 = _tf116.mkdtemp(prefix="lgsm-unit-p116-")
_LOOP116 = "127.0.0.1"  # NOSONAR(S1313) - loopback, the bind a stand-in boot record names; never dialled


@_ctx116.contextmanager
def _boot116(**vals):
    """Set app.config BOOT_* keys (a value of None removes the key); put every one back after."""
    saved = {k: (k in _p9.config, _p9.config.get(k)) for k in vals}
    for k, v in vals.items():
        _p9.config.pop(k, None)
        if v is not None:
            _p9.config[k] = v
    try:
        yield
    finally:
        for k, (had, was) in saved.items():
            _p9.config.pop(k, None)
            if had:
                _p9.config[k] = was


def _saved116(**keys):
    _p9_cfg.save_config(dict(_p9_cfg.load_config(), **keys))


# ── 1. change-port: the "current" port is the one the panel serves on ─────────────────────────
def _move116(client, boot, saved, to, restart_ok, in_use=()):
    """One change-port on stand-ins: (reply, the calls it made by kind)."""
    calls = {"open": [], "close": [], "jail": [], "record": [], "in_use": []}
    _p9_patch(_rs116, "remote_ufw_open_port", lambda r, p, *a, **k: (calls["open"].append(int(p)), (True, "ok"))[1])

    def close(r, p, *a, **k):
        calls["close"].append(int(p))
        if k.get("deleted") is not None:
            k["deleted"].append("v4")
        return True, "closed"
    _p9_patch(_rs116, "remote_ufw_close_port", close)
    _p9_patch(_rs116, "remote_ufw_put_back_tcp", lambda r, p, fams, c: (calls["open"].append(int(p)), (True, ""))[1])
    _p9_patch(_p9_so, "ensure_panel_fail2ban",
              lambda log, port, wl=None: (calls["jail"].append(int(port)), (True, "j"))[1])
    _p9_patch(_p9_so, "panel_fail2ban_status", lambda: {"installed": True})
    _p9_patch(_p9_so, "port_in_use", lambda port: (calls["in_use"].append(int(port)), int(port) in in_use)[1])
    _p9_patch(_p9_so, "record_panel_port", lambda port: (calls["record"].append(int(port)), (True, ""))[1])
    _p9_patch(_p9_so, "restart_panel", lambda *a, **k: (restart_ok, "p116"))
    _saved116(port=saved, bind_host=_ANY108, tailscale_setup_done=True)
    with _boot116(BOOT_PORT=boot):
        r = client.post("/api/panel/change-port", json={"port": to, "bind_host": _ANY108})
    return _p9_json(r), calls


def _change_port116(client):
    body, c = _move116(client, 5000, 6000, 7000, False)
    check("change-port: with an earlier move waiting for its restart, a second move whose restart fails "
          "too keeps the jail and the helper's record on the port the panel serves (it pointed both at "
          "config.json's port, which nothing served)",
          (body.get("success"), c["jail"], c["record"]) == (False, [7000, 5000], [7000, 5000]), repr((body, c)))
    check("change-port: ...and it closes the served port's rule (put back after the failed restart) and the "
          "rule the unapplied move had opened, never leaving either behind",
          (sorted(c["close"]), c["open"]) == ([5000, 6000], [7000, 5000]), repr(c))
    body, c = _move116(client, 5000, 6000, 5000, True, in_use=(5000,))
    check("change-port: a move back to the port the panel serves on is not refused as 'in use' (the panel's "
          "own listener), is recorded for the helper, and closes the unapplied port's rule",
          (body.get("success"), c["in_use"], c["record"], c["close"]) == (True, [], [5000], [6000]),
          repr((body, c)))
    body, c = _move116(client, 5000, 6000, 6000, True)
    check("change-port: ...and retrying the saved move is a change, not 'already the panel's binding'",
          (body.get("success"), c["close"], c["record"]) == (True, [5000], [6000]), repr((body, c)))
    body, c = _move116(client, 5000, 5000, 5000, True)
    check("change-port: with nothing pending, the binding the panel has is still refused as unchanged (control)",
          (body.get("success"), "already" in str(body.get("message")), c["record"]) == (False, True, []),
          repr((body, c)))


# ── 2. Tailscale: Disable's lock-out guard reads the bind this process has ─────────────────────
def _disable116(client):
    seen = []
    _p9_patch(_p9_ts, "disable_tailscale_serve", lambda mount, port: (seen.append(port), (True, "removed"))[1])
    got = {}
    for case, bound in (("bound loopback", _LOOP116), ("bound public", _ANY108), ("no boot record", None)):
        _saved116(port=5000, bind_host=_ANY108, tailscale_setup_done=True)
        n0 = len(seen)
        with _boot116(BOOT_BIND=bound, BOOT_PORT=5000):
            r = client.post("/api/tailscale/serve", json={"action": "disable", "mount": "/"})
        got[case] = (r.status_code, len(seen) - n0, str(_p9_json(r).get("message")))
    check("Tailscale Disable: refused while the panel is still bound to loopback and a public bind waits for "
          "the restart (the stored 0.0.0.0 let it remove the only way in)",
          got["bound loopback"][:2] == (400, 0) and "restart" in got["bound loopback"][2], repr(got))
    check("Tailscale Disable: ...and allowed when the panel really listens publicly, or nothing is recorded "
          "(control)", got["bound public"][1] == 1 and got["no boot record"][1] == 1, repr(got))


def _scheme116():
    got = {}
    for case, tls in (("serves TLS", True), ("serves http", False)):
        with _boot116(BOOT_TLS=tls), _p9.app_context():
            # config.json says the next start serves http (a loopback bind behind Serve).
            got[case] = _tsr116._panel_scheme({"use_https": True, "tailscale_setup_done": True,
                                                "bind_host": _LOOP116})
    check("Tailscale page: the direct links' scheme is the one this process serves (a saved loopback bind "
          "made it http:// to a port still speaking TLS)", got == {"serves TLS": "https", "serves http": "http"},
          repr(got))


# ── 3. the host page's Public panel access label ──────────────────────────────────────────────────
def _label116(client):
    _p9_patch(_p9_so, "get_server_status", lambda *a, **k: {
        "has_sudo": True, "ufw": {"enabled": True, "rules": []}, "tailscale_ssh": {"enabled": False, "running": True},
        "tailscale_ssh_allowed": False, "tailscale_interface": "tailscale0", "tailscale_ufw_allowed": False,
        "updates": {}, "uptime": ""})
    _p9_patch(_p9_ts, "panel_funnel_facts", lambda cfg: {})
    got = {}
    for case, boot in (("pending", 5000), ("same", 6000)):
        _saved116(port=6000)
        with _boot116(BOOT_PORT=boot):
            page = client.get("/server-management").get_data(as_text=True)
        i = page.find("<span>Public panel access</span>")
        got[case] = page[i:page.find("</div>", i)] if i >= 0 else page[:200]
    check("host page: 'Public panel access' names the port the panel serves on, the one Close acts on first, "
          "and the saved one beside it while its restart waits (it named config.json's alone)",
          "</span> 5000; <span>saved for the next restart:</span> 6000)" in got["pending"], repr(got))
    check("host page: ...and with no change pending, the one port alone (control)",
          "</span> 6000)" in got["same"] and "next restart" not in got["same"], repr(got))


# ── 4. the login jail and the debug report ask what this process does ─────────────────────────────
def _proxied116():
    got = {}
    for case, bound in (("bound loopback", _LOOP116), ("bound public", _ANY108)):
        _saved116(bind_host=_ANY108, trust_proxy=False, tailscale_setup_done=False)
        with _boot116(BOOT_BIND=bound), _p9.app_context():
            got[case] = _p9_so._panel_login_proxied()
    check("login jail: a panel still bound to loopback (a public bind waiting for its restart) bans on every "
          "port, as its logins come through a proxy (the stored bind alone said 'direct')",
          got == {"bound loopback": True, "bound public": False}, repr(got))


def _report_tls116():
    _p9_patch(_nw116, "_load_cfg", lambda: ({"use_https": True, "tailscale_setup_done": True,
                                             "bind_host": _LOOP116}, True))
    hsts = (_nw116._self_tls({"_R32A_SELF_TLS": True}), _nw116._self_tls({"_R32A_SELF_TLS": False}))
    check("debug report: the HSTS line asks what the header itself decided (from the config the process "
          "started with), not config.json's next start", hsts == (True, False), repr(hsts))
    import app as _app116
    line, mark = _pr116._scheme_line({"BOOT_TLS": True}, {"use_https": True, "tailscale_setup_done": True,
                                                          "bind_host": _LOOP116})
    check("debug report: Scheme agreement compares what Serve writes use now, not the next start's scheme "
          "(a saved loopback bind read as a MISMATCH warning)", "MISMATCH" not in mark and "https+insecure" in line
          and hasattr(_app116, "_serve_scheme_now"), repr(line))


# ── 5. the downloadable report never tells which journal read it was ──────────────────────────────
class _Os116(object):
    """system_ops.os with this process's ids replaced (never the real one: _run_verb's shell branch)."""

    def __init__(self, euid):
        self.euid = euid

    def __getattr__(self, name):
        return getattr(os, name)

    def geteuid(self):
        return self.euid

    def getuid(self):
        return self.euid


def _journal_stands116(helper, euid, lines):
    """system_ops as a host with or without the helper, as `euid`, whose system journal holds `lines`."""
    answer = ("\n".join(lines) + "\n", "", 0) if lines else ("", "", 1)
    _p9_patch(_p9_so, "_helper_present", lambda: helper)
    _p9_patch(_p9_so, "os", _Os116(euid))
    # The user journal is empty everywhere, so each model reaches its own system-journal read.
    _p9_patch(_p9_so, "_debug_run", lambda argv, timeout=10, **k: ("", "", 1) if "--user" in argv else answer)
    _p9_patch(_p9_so, "_run_verb", lambda verb, args=(), timeout=30, merge_stderr=True: answer)


def _journal_models116():
    """{model: (file text, page text)} of both journal sections, with and without journal lines."""
    lines = [_jl116(i, "panel line %d" % i, pid=11) for i in range(3)]
    out = {}
    for model, helper, euid in (("helper", True, 1000), ("root", False, 0), ("unprivileged", False, 1000)):
        for have in (True, False):
            _journal_stands116(helper, euid, lines if have else [])
            ctx = _base116.Ctx(app=None, deadline_s=20.0)
            res = [fn(ctx) for fn in (_lg116.section_recent_log, _lg116.section_journal_digest)]
            out[(model, have)] = ("\n".join(ln for r in res for ln in r.lines),
                                  "\n".join(ln for r in res for ln in r.page_lines))
    return out


def _journal_in116(files, have):
    """Are `files` one text, with no posture line, holding a journal line exactly when it was read (`have`)?"""
    return (len(set(files.values())) == 1 and not any(_base116.POSTURE_RE.search(f) for f in files.values())
            and all(("panel line 0" in f) == have for f in files.values()))


def _report_journal116():
    out = _journal_models116()
    clock = __import__("re").compile(r"report generated \d\d:\d\d:\d\d")
    for have in (True, False):
        files = {m: clock.sub("", out[(m, have)][0]) for m in ("helper", "root", "unprivileged")}
        # ...and the journal's lines are in it exactly when one was read (review 1022c: with every model's
        # read failing, the three "Source: none" files were as equal, and the "journal read" case passed).
        check("debug report: the downloadable file's journal lines are the SAME whichever way the panel is "
              "privileged (%s): a root-run panel with no helper said 'system journal via root' and "
              "'(privileged read)'" % ("journal read" if have else "no journal readable"),
              _journal_in116(files, have),
              repr(files)[:900])
    pages = {m: out[(m, False)][1] for m in ("helper", "root", "unprivileged")}
    check("debug report: ...and which read was tried is on the page only, one per model",
          "read directly" in pages["root"] and "via the privileged helper" in pages["helper"]
          and "without sudo" in pages["unprivileged"], repr(pages))
    held = [_base116.POSTURE_RE.search(s) is not None for s in (
        "- **Source**: none (user journal: no entries, rc 1; system journal via root: timed out)",
        "- **Source**: system journal (privileged read) · 3 lines", "- **Source**: system journal · 3 lines")]
    check("debug report: the posture backstop also withholds the old wordings, not the new one",
          held == [True, True, False], repr(held))


# ── 6. the helper's folder download survives a file that shrinks while it is read ─────────────────
def _tar_shrink116():
    top = os.path.join(_TMP116, "game")
    os.makedirs(top)
    for name, size in (("a.json", 20000), ("b.txt", 300)):
        with open(os.path.join(top, name), "wb") as fh:
            fh.write(name[0].encode() * size)
    _shrunk_archive116(top)


def _shrunk_archive116(top):
    """Build the folder download of `top` while its a.json is rewritten in place, then judge the archive."""

    class _Shrinking116(_tar116.TarFile):
        """A TarFile whose file is rewritten in place by the game right after its header is taken."""

        def gettarinfo(self, name=None, arcname=None, fileobj=None):
            ti = super().gettarinfo(name, arcname, fileobj)
            if ti is not None and (arcname or "").endswith("a.json"):
                os.truncate(os.path.join(top, "a.json"), 100)
            return ti
    buf = _io116.BytesIO()
    # The helper's own `tarfile` name, never the stdlib module's attributes (part-wide rule).
    _p9_patch(_h116, "tarfile", NS(open=_Shrinking116.open, TarInfo=_tar116.TarInfo))
    try:
        _h116._emit_dir_tar(top, buf)
    finally:
        _p9_restore_all()
    try:
        with _tar116.open(fileobj=_io116.BytesIO(buf.getvalue()), mode="r:gz") as tf:
            got = {m.name: (m.size, tf.extractfile(m).read() if m.isreg() else b"") for m in tf.getmembers()}
    except (_tar116.TarError, OSError, EOFError) as exc:
        got = {"error": repr(exc)}
    _judge_tar116(got)


def _judge_tar116(got):
    a = got.get("game/a.json", (0, b""))
    check("helper folder download: a file that shrinks while it is read leaves an archive every tool can open, "
          "its later members intact (it wrote a .tar.gz nothing could read, served as a success)",
          (got.get("game/b.txt"), a) == ((300, b"b" * 300), (20000, b"a" * 100 + b"\0" * 19900)),
          repr({k: (v[0] if isinstance(v, tuple) else v) for k, v in got.items()}))
    notes = got.get("game/PANEL-DOWNLOAD-NOTES.txt", (0, b""))[1].decode("utf-8", "replace")
    check("helper folder download: ...and the archive names the file that changed, in a notes member",
          ("game/a.json" in notes, "game/b.txt" in notes) == (True, False), repr(notes))


# ── 7. manage.py's setup link names the port the running panel listens on ──────────────────────────
def _manage116():
    """(manage.py's _r32a_ functions, the setup link's port expressions that ask the running panel first).

    From manage.py's text: importing manage builds a second app.
    """
    import ast as _ast116
    with open(os.path.join(_root, "manage.py"), encoding="utf-8") as fh:
        tree = _ast116.parse(fh.read())
    fns = {n.name: n for n in tree.body if isinstance(n, _ast116.FunctionDef)}
    keep = [n for name, n in fns.items() if name.startswith("_r32a_")]
    # The call site: the link's port is the running panel's first, config.json's only without one.
    link = [n for n in _ast116.walk(fns["cmd_setup_token"]) if isinstance(n, _ast116.BoolOp)
            and isinstance(n.op, _ast116.Or) and isinstance(n.values[0], _ast116.Call)
            and getattr(n.values[0].func, "id", "") == "_r32a_running_port"]
    # Only those functions, written out and run as a file of their own (runpy), with manage.py's `os`.
    only = os.path.join(_TMP116, "manage_r32a.py")
    with open(only, "w", encoding="utf-8") as fh:
        fh.write(_ast116.unparse(_ast116.Module(body=keep, type_ignores=[])))
    return NS(**_runpy116.run_path(only, init_globals={"os": os})), link


def _setup_link116():
    _mg116, link = _manage116()
    proc = os.path.join(_TMP116, "proc")
    pid = os.path.join(proc, "4242")
    for d in ("fd", "net"):
        os.makedirs(os.path.join(pid, d))
    app_py = os.path.join(_TMP116, "panel", "app.py")
    os.makedirs(os.path.dirname(app_py))
    open(app_py, "w").close()
    with open(os.path.join(pid, "cmdline"), "wb") as fh:
        fh.write(b"/venv/bin/python3\0app.py\0")
    os.symlink(os.path.dirname(app_py), os.path.join(pid, "cwd"))
    os.symlink("socket:[777]", os.path.join(pid, "fd", "5"))
    os.symlink("socket:[888]", os.path.join(pid, "fd", "6"))
    hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    with open(os.path.join(pid, "net", "tcp"), "w", encoding="ascii") as fh:
        fh.write(hdr + "   0: 00000000:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000  %d        0 777\n"
                 % os.getuid()
                 + "   1: 0100007F:1770 0100007F:9999 01 00000000:00000000 00:00000000 00000000  %d        0 888\n"
                 % os.getuid())
    got = (_mg116._r32a_running_port(proc, app_py), _mg116._r32a_running_port(proc, app_py + "x"))
    check("manage.py setup-token: the link names the port the running panel listens on (5000 here), found by "
          "its own sockets, not config.json's next start; another checkout's process is not it",
          got == (5000, None), repr(got))
    check("manage.py setup-token: ...and the printed link asks it first, config.json's port only when no running "
          "panel answers", len(link) == 1, repr(len(link)))


# ── 8. install.sh and uninstall.sh, which run outside the process ────────────────────────────────
def _sh_fn116(text, name):
    i = text.index("\n%s() {\n" % name) + 1
    return text[i:text.index("\n}\n", i) + 3]


def _bash116(script, env=None):
    r = _sp116.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   env=dict(os.environ, LC_ALL="C.UTF-8", **(env or {})))
    return r.stdout, r.stderr, r.returncode


def _free_port116():
    with _sock116.socket() as s:
        s.bind((_LOOP116, 0))
        return s.getsockname()[1]


def _install_record116():
    with open(os.path.join(_root, "install.sh"), encoding="utf-8") as fh:
        text = fh.read()
    fns = "".join(_sh_fn116(text, n) for n in ("_r25j_panel_port_to_record", "_r25j_is_panel_port",
                                                "_r25j_port_held_by_other", "_r32a_owner_listens"))
    conf = os.path.join(_TMP116, "panel.conf")
    lsock = _sock116.socket()
    lsock.bind((_LOOP116, 0))
    lsock.listen(1)
    served, saved, gone = lsock.getsockname()[1], _free_port116(), _free_port116()
    got = {}
    try:
        for case, prev in (("panel running on the recorded port", served), ("panel stopped", gone)):
            with open(conf, "w", encoding="utf-8") as fh:
                fh.write("panel_port=%d\n" % prev)
            out, err, rc = _bash116('set -euo pipefail\nPANEL_DIR=%s\n_R25J_CHOSEN_PORT=""\n'
                                    "_r26a_cfg_port() { echo %d; }\n%s_r25j_panel_port_to_record %s\n"
                                    % (_TMP116, saved, fns, conf))
            got[case] = (out.strip(), rc, err[-200:])
    finally:
        lsock.close()
    check("install.sh: an update that restarts nothing keeps the recorded port while the panel still listens "
          "there (it wrote config.json's unapplied port over it, and the helper refused Serve)",
          got["panel running on the recorded port"][:2] == (str(served), 0), repr(got))
    check("install.sh: ...and with the panel stopped (the full update's path) config.json's port is recorded "
          "(control)", got["panel stopped"][:2] == (str(saved), 0), repr(got))


def _between116(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i) + len(end)]


def _uninstall116():
    with open(os.path.join(_root, "uninstall.sh"), encoding="utf-8") as fh:
        text = fh.read()
    rec = text[text.index('_R32A_REC_PORT=""'):text.index("\n# ── Stop + remove the service")]
    ufw = _between116(text, '_r32a_cfg_port="${PANEL_PORT}"', 'PANEL_PORT="${_r32a_cfg_port}"\n')
    tsl = _between116(text, '_r32a_ts_port="${PANEL_PORT}"', 'PANEL_PORT="${_r32a_ts_port}"\n')
    panel_dir, other = os.path.join(_TMP116, "inst"), os.path.join(_TMP116, "other")
    for d in (panel_dir, other):
        os.makedirs(d, exist_ok=True)
    conf, state = os.path.join(_TMP116, "shared.conf"), os.path.join(_TMP116, "ufw-state")
    shims = ('warn() { echo "WARN $*"; }\nok() { echo "OK $*"; }\nsudo_note() { :; }\nU_SUDO=""\n'
             'ufw() { case "$1" in\n'
             '  show) cat "$UFW_STATE" ;;\n'
             '  delete) grep -vxF "ufw $2 $3" "$UFW_STATE" > "$UFW_STATE.n" || true;'
             ' mv -f "$UFW_STATE.n" "$UFW_STATE" ;;\n'
             '  esac; return 0; }\n'
             'tailscale() { :; }\n_ts_sudo_note_first() { return 0; }\n'
             '_ts_panel_routes() { echo "ROUTES<$1>"; }\n_ts_remove_routes() { echo "REMOVE $1"; }\n')
    got = {}
    for case, owner in (("this install's record", panel_dir), ("another install's record", other)):
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("panel_dir=%s\npanel_port=5000\n" % owner)
        with open(state, "w", encoding="utf-8") as fh:
            fh.write("ufw allow 5000/tcp\nufw allow 6000/tcp\n")
        out, err, rc = _bash116("set -euo pipefail\nPANEL_DIR=%s\nSHARED_CONF=%s\nUFW_STATE=%s\nPANEL_PORT=6000\n"
                                "TS_DONE=1\nTS_CONF_UNREAD=0\n%s%s\n%s\n%s\necho \"PORT=${PANEL_PORT}\"\n"
                                % (panel_dir, conf, state, shims, rec, ufw, tsl))
        with open(state, encoding="utf-8") as fh:
            got[case] = (fh.read(), [ln for ln in out.split("\n") if ln.startswith(("REMOVE", "PORT="))], rc,
                         err[-200:])
    check("uninstall.sh: the port panel.conf records for THIS install loses its rule and its Serve routes too "
          "(after a failed port-change restart the served port's ALLOW stayed open on a host with no panel)",
          got["this install's record"][:3] == ("", ["REMOVE ROUTES<6000>", "REMOVE ROUTES<5000>", "PORT=6000"], 0),
          repr(got))
    check("uninstall.sh: ...and another install's recorded port is never touched (control)",
          got["another install's record"][:3] == ("ufw allow 5000/tcp\n", ["REMOVE ROUTES<6000>", "PORT=6000"], 0),
          repr(got))


# ── 9. an invite redeemed under a name taken a moment earlier ────────────────────────────────────
def _invite_race116():
    from panel.db.models import Invite, User
    from panel.routes import admin_notifications as _an116
    from panel.security import auth as _auth116
    secret = "Str0ng!" + "passw0rd-p116"
    mine = {"users": [], "invites": []}
    got = {}
    try:
        with _p9.app_context():
            taken = User(username="p116_taken", password_hash=_auth116.hash_password(secret),
                         display_name="p116", is_superadmin=False, is_active=True)
            db.session.add(taken)
            db.session.commit()
            mine["users"].append(taken.id)
            creator = db.session.get(User, P9_ADMIN)
            inv, tok = Invite.mint(creator, hours=24, note="p116-race")
            db.session.add(inv)
            db.session.commit()
            mine["invites"].append(inv.id)
        for case, name in (("name taken meanwhile", "p116_taken"), ("free name", "p116_fresh")):
            # The form's own "taken" check already ran and passed: the other redemption committed after it.
            _p9_patch(_an116, "_invite_form", lambda _n=name: (_n, secret, None))
            try:
                r = _p9.test_client().post("/invite/" + tok, data={"username": name})
            except Exception as exc:  # noqa: BLE001 - an exception out of the route fails by name below
                db.session.rollback()
                got[case] = ("raised", type(exc).__name__)
                continue
            with _p9.app_context():
                row = Invite.query.filter_by(note="p116-race").first()
                fresh = User.query.filter_by(username="p116_fresh").first()
                if fresh is not None and fresh.id not in mine["users"]:
                    mine["users"].append(fresh.id)
                got[case] = (r.status_code, "taken" in r.get_data(as_text=True), row.used_by_id is None,
                             row.used_at is None)
    finally:
        _p9_restore_all()
        with _p9.app_context():
            Invite.query.filter(Invite.id.in_(mine["invites"] or [-1])).delete(synchronize_session=False)
            for uid in mine["users"]:
                urow = db.session.get(User, uid)
                if urow is not None:
                    db.session.delete(urow)
            db.session.commit()
    check("invite: a username taken by another redemption between the form's check and the insert answers "
          "'taken' (400) and leaves the invite usable (the unique constraint answered a bare 500)",
          got.get("name taken meanwhile") == (400, True, True, True), repr(got))
    check("invite: ...and a free name still creates the account and uses the invite (control)",
          got.get("free name", (0,))[0] == 302 and got["free name"][2:] == (False, False), repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
_CFG116 = _p9_cfg.load_config()
with _p9.app_context():
    _AUDIT116 = db.session.query(db.func.max(AuditLog.id)).scalar() or 0
try:
    _p9_arm(who="part116")
    _A116 = _p9_client(P9_ADMIN)
    for _fn116 in (_change_port116, _disable116, _label116):
        _fn116(_A116)
        _p9_restore_all()
        _p9_arm(who="part116")
    for _fn116 in (_scheme116, _proxied116, _report_tls116, _report_journal116):
        _fn116()
        _p9_restore_all()
        _p9_arm(who="part116")
    # Re-armed after each, as above (review 1022a): _shrunk_archive116's and _invite_race116's own
    # `_p9_restore_all()` also disarm the tripwire, so the four after the archive ran unarmed while
    # the closing check said every host call was stubbed.
    for _fn116 in (_tar_shrink116, _setup_link116, _install_record116, _uninstall116, _invite_race116):
        _fn116()
        _p9_restore_all()
        _p9_arm(who="part116")
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG116)
    _shutil116.rmtree(_TMP116, ignore_errors=True)
    with _p9.app_context():
        AuditLog.query.filter(AuditLog.id > _AUDIT116).delete(synchronize_session=False)
        db.session.commit()

check("part116: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP116_START, repr(_P9_TRIPPED[_TRIP116_START:][:6]))
