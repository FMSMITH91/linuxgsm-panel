"""Part 75 of the unit suite: the eighth review's routes, tools, page and i18n fixes (builder C).

Held here, each against the code path the finding named:

* a failed install's reason is shown in the VIEWER's language (it was stored as English by a
  worker with no viewer), while install_error itself stays English and an old row is shown as it
  was written.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import html as _html75
import inspect as _inspect75
import json as _json75
import os
from types import SimpleNamespace as _NS75

from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_delete_server, _p9_drain,
                         _p9_host_row, _p9_json, _p9_new_server, _p9_patch, _p9_restore_all, _p9_row, _p9_set)
from panel.core import i18n as _i18n75
from panel.core.panel_state import _install_jobs as _install_jobs75, _install_lock as _install_lock75
from panel.db.models import User as _U75, db as _db75
from panel.routes import manage_servers as _ms75

_XHR75 = {"X-Requested-With": "XMLHttpRequest"}


def _lang75(lang):
    with _p9.app_context():
        _db75.session.get(_U75, P9_ADMIN).language = lang
        _db75.session.commit()


def _cat75(lang):
    with _p9.test_request_context("/"):
        return _i18n75.catalog(lang)


def _banner75(client, sid):
    """The failed-install banner's reason line for server `sid` on the dashboard, unescaped."""
    page = client.get("/").get_data(as_text=True)
    at = page.find('data-server-id="%d"' % sid)
    if at < 0:
        return None
    mark = '<div class="mt-1" data-no-i18n>'
    start = page.find(mark, at)
    if start < 0:
        return None
    start += len(mark)
    return _html75.unescape(page[start:page.find("</div>", start)])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A failed install's reason, in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The install runs on a worker with no viewer, so the reason it wrote onto the row was English,
# and the dashboard's failed-install banner showed every es/fr viewer that English.
# part12's transport tripwire is armed at the top of each block below that drives a route; the part
# ends by checking nothing it drove reached a real host.
_TRIP75_START = len(_P9_TRIPPED)
_ES75, _FR75 = _cat75("es"), _cat75("fr")
_sids75 = []
try:
    _p9_arm(who="part75")
    _A75 = _p9_client(P9_ADMIN)

    def _failed75(name, detail="", **kw):
        """A new row failed through the install job's own recorder (_InstallRun.fail)."""
        sid = _p9_new_server(P9_HOST, "p75fail%d" % len(_sids75), "csgo", 27900 + len(_sids75),
                             installed=False, status="installing")
        _sids75.append(sid)
        with _p9.app_context():
            run = _ms75._InstallRun(_p9, sid, None)
            run.first_load()         # a job queued without an entry takes the row's identity here
            run.fail(name, detail, **kw)
        return sid

    _game75 = _failed75("Invalid game type",
                        _i18n75.Sentence("'{game}' is not a valid LinuxGSM shortname.", game="zzz"))
    _tail75 = _failed75("LinuxGSM setup failed", "fatal: no route to host")
    _old75 = _p9_new_server(P9_HOST, "p75old", "csgo", 27950, installed=False, status="failed",
                            install_error="Invalid game type: written by an older panel")
    _sids75.append(_old75)

    check("install failure: install_error itself stays the English sentence (audit, logs and the "
          "debug report read it)",
          _p9_row(_game75).install_error == "Invalid game type: 'zzz' is not a valid LinuxGSM shortname."
          and _p9_row(_tail75).install_error == "LinuxGSM setup failed: fatal: no route to host",
          repr((_p9_row(_game75).install_error, _p9_row(_tail75).install_error)))

    _lang75("es")
    _es_game75 = _banner75(_A75, _game75)
    check("install failure: an es viewer reads the dashboard's failed-install reason in Spanish, step "
          "and sentence both — it was the English the worker wrote",
          _es_game75 == "%s: %s" % (_ES75["Invalid game type"], _i18n75.fill(
              _ES75["'{game}' is not a valid LinuxGSM shortname."], game="zzz")), repr(_es_game75))
    _es_tail75 = _banner75(_A75, _tail75)
    check("install failure: ...the host's own words in it are kept as written, the step translated",
          _es_tail75 == "%s: fatal: no route to host" % _ES75["LinuxGSM setup failed"], repr(_es_tail75))
    _es_old75 = _banner75(_A75, _old75)
    check("install failure: ...and a row failed by an older panel (no recorded build) is shown exactly "
          "as it was written",
          _es_old75 == "Invalid game type: written by an older panel", repr(_es_old75))

    # The retry refusal names the reason too, for a cause a retry cannot change.
    _final75 = _failed75(_i18n75.Sentence("This game is not downloadable with an anonymous Steam login — "
                                          "it needs an account that owns it. Put a Steam username and "
                                          "password in the server's LinuxGSM config (steamuser / "
                                          "steampass) and install again."),
                         "raw tail", retryable=False, explained=True)
    _retry75 = _p9_json(_A75.post("/servers/%d/retry-install" % _final75, headers=_XHR75))
    _want75 = _ES75["This game is not downloadable with an anonymous Steam login — it needs an account "
                    "that owns it. Put a Steam username and password in the server's LinuxGSM config "
                    "(steamuser / steampass) and install again."]
    check("install failure: Retry's refusal quotes the reason in the viewer's language",
          _want75 in (_retry75.get("message") or _retry75.get("error") or ""), repr(_retry75))

    _lang75("fr")
    _fr_game75 = _banner75(_A75, _game75)
    check("install failure: a fr viewer reads it in French, with French spacing before the colon",
          _fr_game75 == "%s : %s" % (_FR75["Invalid game type"], _i18n75.fill(
              _FR75["'{game}' is not a valid LinuxGSM shortname."], game="zzz")), repr(_fr_game75))

    # The job's own fixed details are panel sentences, not host text: driven through the job.
    _rv75 = _inspect75.unwrap(_p9.view_functions["retry_install"])
    _rij75 = dict(zip(_rv75.__code__.co_freevars,
                      (c.cell_contents for c in _rv75.__closure__)))["_run_install_job"]
    _empty75 = _p9_new_server(P9_HOST, "p75empty", "csgo", 27951, installed=False, status="installing")
    _sids75.append(_empty75)
    _rij75(_empty75, P9_HOST, "", "csgo", "csgoserver", 27951, [])
    _p9_drain()
    _fr_empty75 = _banner75(_A75, _empty75)
    check("install failure: the job's own 'missing instance name' detail is French too (a fixed "
          "sentence, not the host's words)",
          _fr_empty75 == "%s : %s" % (_FR75["Preparing user account"],
                                      _FR75["internal error: missing instance name"]), repr(_fr_empty75))

    # A recorded build that no longer says what install_error says is not shown: something wrote
    # the English column alone. Nor is a record the panel could not have written.
    _p9_set(_tail75, install_error="LinuxGSM setup failed: a newer reason")
    _stale75 = _banner75(_A75, _tail75)
    _bad75 = []
    for _rec75 in ('{"t": "{x}", "v": {"template": "y"}}', "[" * 5000 + "]" * 5000, "{nope",
                   _json75.dumps({"t": "a", "v": {}, "extra": 1}), '{"t": 5, "v": {}}'):
        _p9_set(_old75, install_error_i18n=_rec75)
        _bad75.append(_banner75(_A75, _old75))
    check("install failure: a recorded build that no longer matches install_error, or one the panel "
          "could not have written, falls back to the English (no 500)",
          _stale75 == "LinuxGSM setup failed: a newer reason"
          and _bad75 == ["Invalid game type: written by an older panel"] * 5, repr((_stale75, _bad75)))

    # Cleared with the reason: a retry that starts, and an install that finishes.
    with _p9.app_context():
        _run75 = _ms75._InstallRun(_p9, _game75, None)
        _run75.first_load()
        _run75.finish("ok")
    check("install failure: a finished install clears the recorded build with the reason",
          _p9_row(_game75).install_error == "" and _p9_row(_game75).install_error_i18n is None,
          repr(_p9_row(_game75).install_error_i18n))
    # ...and a retry that starts clears it with the reason too. The job it starts never runs (its
    # thread is a stand-in that is never started), and its progress entry is dropped.
    _p9_patch(_ms75, "threading", _NS75(Thread=lambda target=None, daemon=None: _NS75(start=lambda: None)))
    _p9_set(_tail75, install_error_i18n='{"t": "LinuxGSM setup failed: again", "v": {}}',
            install_error="LinuxGSM setup failed: again")
    _again75 = _p9_json(_A75.post("/servers/%d/retry-install" % _tail75, headers=_XHR75))
    with _install_lock75:
        _install_jobs75.pop(_tail75, None)
    check("install failure: a retry that starts clears the recorded build with the reason",
          _again75.get("success") is True and _p9_row(_tail75).install_error == ""
          and _p9_row(_tail75).install_error_i18n is None, repr((_again75, _p9_row(_tail75).install_error_i18n)))
finally:
    _lang75("en")
    _p9_restore_all()
    for _s75 in _sids75:
        _p9_delete_server(_s75)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A config write made while a route waited is not reverted by its save
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The change-port route read config.json, ran `ss` and `ip` (which yield to other greenlets), and
# then save_config()'d the whole dict it had read — so a key a background writer committed in that
# window (a game backup's clock, the announced panel update) was silently put back. The setup
# wizard's Tailscale steps had the same shape around the tailscale commands and the SSH test.
from panel.core import config as _cfg75  # noqa: E402
from panel.ops import system_ops as _so75  # noqa: E402
from panel.routes import remote_security as _rs75, route_helpers as _rh75  # noqa: E402
from unit.part05 import _root as _root75  # noqa: E402
from unit.part16 import _ANY16 as _ANY75  # noqa: E402


def _bg_write75(key):
    """A background writer committing `key` through update_config, as a backup worker does."""
    def _apply(c):
        c[key] = "kept"
    _cfg75.update_config(_apply)


def _port_scan75(port):
    _bg_write75("p75_during_scan")     # lands while the route waits on the port scan
    return False


_saved_cfg75 = dict(_cfg75.load_config())
try:
    _p9_arm(who="part75")
    _cfg75.save_config(dict(_saved_cfg75, port=5000, bind_host=_ANY75))
    _p9_patch(_rs75, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
    _p9_patch(_rs75, "remote_ufw_close_port", lambda *a, **k: (True, "ok"))
    _p9_patch(_so75, "ensure_panel_fail2ban", lambda *a, **k: (True, "jail updated"))
    _p9_patch(_so75, "panel_fail2ban_status", lambda: {"installed": True})
    _p9_patch(_so75, "restart_panel", lambda *a, **k: (True, "scheduled"))
    _p9_patch(_so75, "port_in_use", _port_scan75)
    _cp75 = _p9_json(_p9_client(P9_ADMIN).post("/api/panel/change-port",
                                               json={"port": 5091, "bind_host": _ANY75}))
    _after75 = _cfg75.load_config()
    check("config: a key written while change-port scanned the port survives its save, and the move "
          "is saved — the route saved the whole dict it read first",
          _cp75.get("success") is True and _after75.get("p75_during_scan") == "kept"
          and _after75.get("port") == 5091, repr((_cp75, _after75.get("p75_during_scan"), _after75.get("port"))))

    # The wizard's end-of-setup Serve record, handed the dict read when its request began.
    _stale75 = dict(_cfg75.load_config())
    _bg_write75("p75_during_serve")
    with _p9.app_context(), _p9.test_request_context("/"):
        _rh75._record_auto_serve(_stale75, "/", True, "ok")
    _after75 = _cfg75.load_config()
    check("config: the setup wizard's Serve record keeps a key written while Tailscale ran, and sets "
          "its own", _after75.get("p75_during_serve") == "kept" and _after75.get("tailscale_setup_done") is True
          and _stale75.get("tailscale_mount") == "/", repr(_after75))

    # The class: no route saves a whole dict it read earlier.
    _whole75 = []
    for _walk75 in os.walk(os.path.join(_root75, "panel", "routes")):
        _dir75 = _walk75[0]
        for _fn75 in _walk75[2]:
            if _fn75.endswith(".py"):
                with open(os.path.join(_dir75, _fn75), encoding="utf-8") as _fh75:
                    _whole75 += ["%s:%d" % (_fn75, _i75) for _i75, _l75 in enumerate(_fh75, 1)
                                 if "save_config(" in _l75 and not _l75.lstrip().startswith("#")]
    check("config: no route calls save_config() — a route writes the keys it changed "
          "(config.set_config_keys), onto the file as it is now", not _whole75, repr(_whole75))
finally:
    _p9_restore_all()
    _cfg75.save_config(_saved_cfg75)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The panel's own machine is a host once
# ════════════════════════════════════════════════════════════════════════════════════════════════
# add_remote's is_local branch made a new is_local row whenever it was posted, though every
# panel-host lookup is filter_by(is_local=True).first(): a second row was a host no page reached.
from panel.db.models import RemoteServer as _RS75  # noqa: E402


def _locals75():
    with _p9.app_context():
        return [r.id for r in _RS75.query.filter_by(is_local=True).all()]


_before75 = _locals75()
try:
    _p9_arm(who="part75")
    _lang75("es")
    _r75 = _p9_client(P9_ADMIN).post("/remotes/add", headers=_XHR75,
                                     data={"name": "p75-second-local", "is_local": "1", "ssh_port": "22"})
    _after75 = _locals75()
    check("local host: a second 'this machine' host is refused, in the viewer's language, and no row is "
          "made — the panel host is the one is_local row",
          len(_before75) == 1 and _r75.status_code == 409 and _after75 == _before75
          and _p9_json(_r75).get("message") == _ES75[
              "The panel's own machine is already a host ('{name}'); it can be added only once."].replace(
              "{name}", _p9_host_row(_before75[0]).name),
          repr((_before75, _after75, _r75.status_code, _r75.get_data(as_text=True)[:200])))
finally:
    _lang75("en")
    _p9_restore_all()
    with _p9.app_context():
        for _x75 in _RS75.query.filter(_RS75.is_local.is_(True), ~_RS75.id.in_(_before75)).all():
            _db75.session.delete(_x75)
        _db75.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The i18n gate reads a message sink inside a lambda or a class body
# ════════════════════════════════════════════════════════════════════════════════════════════════
# shown_literals_py went function by function over _py_own_nodes, which stops at a Lambda or a
# ClassDef as it stops at a def — and nothing else read those nodes, so a fixed message there was
# never asked of es/fr.
import importlib.util as _ilu75  # noqa: E402
import shutil as _shutil75  # noqa: E402
import tempfile as _tf75  # noqa: E402

_spec75 = _ilu75.spec_from_file_location("i18n_scan_p75", os.path.join(_root75, "tools", "i18n_scan.py"))
_scan75 = _ilu75.module_from_spec(_spec75)
_spec75.loader.exec_module(_scan75)
_td75 = os.path.realpath(_tf75.mkdtemp(prefix="lgsm-unit-p75-"))
try:
    os.makedirs(os.path.join(_td75, "panel", "routes"))
    with open(os.path.join(_td75, "app.py"), "w") as _fh75:
        _fh75.write("")
    with open(os.path.join(_td75, "panel", "routes", "r.py"), "w") as _fh75:
        _fh75.write(
            "def register(app):\n"
            "    app.register_error_handler(404, lambda e: (jsonify({'error': 'That page is not here.'}), 404))\n"
            "class Notes:\n"
            "    flash('Said from a class body.', 'info')\n"
            "    def m(self):\n"
            "        flash('Said from a method.', 'info')\n"
            "def plain():\n"
            "    flash('Said from a function.', 'info')\n")
    _shown75 = sorted(_scan75.shown_literals_py(root=_td75))
finally:
    _shutil75.rmtree(_td75, ignore_errors=True)
check("i18n gate: shown_literals_py reads a sink inside a lambda and in a class body, as well as in a "
      "function and a method",
      _shown75 == ["Said from a class body.", "Said from a function.", "Said from a method.",
                   "That page is not here."], repr(_shown75))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. install.sh hands out a link that opens on an IPv6-only host
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The fresh install's "Open the panel" link (the one carrying the setup token) took `hostname -I`'s
# first address when no lookup service answered, and printed an IPv6 one unbracketed:
# https://2001:db8::5:5000/… reads the port as part of the address. #426 fixed the update hint only.
import subprocess as _sp75  # noqa: E402  # nosec B404 - runs bash on install.sh's own blocks

with open(os.path.join(_root75, "install.sh"), encoding="utf-8") as _fh75:
    _INS75 = _fh75.read()


def _ins_region75(start, end):
    i = _INS75.find(start)
    j = _INS75.find(end, i)
    return _INS75[i:j] if 0 <= i < j else 'echo "MISSING REGION %s"; exit 1\n' % start


_FALLBACK75 = _ins_region75("\nhost_addr_fallback() {", "\n}\n") + "\n}\n"
_FRESH75 = _ins_region75('PUBLIC_IP="$(curl -4', "\n# Tailscale address")


def _fresh_ip75(addrs):
    """PUBLIC_IP as the fresh path sets it, with both lookups failing and `hostname -I` saying `addrs`."""
    script = ("set -euo pipefail\ncurl() { return 7; }\naddrs=\"$1\"\n"
              "hostname() { echo \"${addrs}\"; }\n" + _FALLBACK75 + _FRESH75 + '\nprintf "%s" "${PUBLIC_IP}"\n')
    r = _sp75.run(["bash", "-c", script, "p75", addrs],  # nosec B603 B607 - bash, fixed script
                  capture_output=True, text=True, timeout=60)
    return r.stdout + r.stderr


_ip75 = {k: _fresh_ip75(v) for k, v in (("v6 only", "2001:db8::5 fe80::1"),
                                        ("dual", "2001:db8::5 203.0.113.9"),
                                        ("v4", "203.0.113.9 198.51.100.4"))}
check("install.sh: with no lookup answering, the fresh install's address is the host's IPv4 one, and "
      "an IPv6-only host's goes in brackets (the printed link opens)",
      _ip75 == {"v6 only": "[2001:db8::5]", "dual": "203.0.113.9", "v4": "203.0.113.9"}, repr(_ip75))
check("install.sh: no `hostname -I` fallback is left outside host_addr_fallback (each site brackets)",
      _INS75.count("hostname -I 2>") == 1 and _INS75.count("|| host_addr_fallback)") == 2,
      repr(_INS75.count("hostname -I 2>")))


# ── the update hint's firewall read takes a port range or list as a rule for the port ────────────
# ufw_port_state matched only rules naming the port itself. The fresh install's check had learned
# ranges (part56); this one had not, so a `5000:5010/tcp DENY Anywhere` above the ALLOW printed a
# public address the firewall drops, and a range ALLOW printed none.
_UPS75 = _ins_region75("\nufw_port_state() {", "\n}\n") + "\n}\n"


def _ufw_state75(rules):
    script = ("set -euo pipefail\nST=\"$1\"\nid() { echo 0; }\ntimeout() { shift; \"$@\"; }\n"
              "ufw() { printf 'Status: active\\n\\nTo   Action  From\\n%s' \"${ST}\"; }\n" + _UPS75
              + "ufw_port_state 5000\n")
    r = _sp75.run(["bash", "-c", script, "p75", rules],  # nosec B603 B607 - bash, fixed script
                  capture_output=True, text=True, timeout=60)
    return (r.stdout + r.stderr).strip()


_ups75 = {k: _ufw_state75(v) for k, v in (
    ("range deny first", "5000:5010/tcp   DENY   Anywhere\n5000/tcp   ALLOW   Anywhere\n"),
    ("list deny first", "80,5000/tcp   DENY   Anywhere\n5000/tcp   ALLOW   Anywhere\n"),
    ("range allow", "4990:5005/tcp   ALLOW   Anywhere\n"),
    ("range elsewhere", "6000:6010/tcp   DENY   Anywhere\n5000/tcp   ALLOW   Anywhere\n"),
    ("udp range", "5000:5010/udp   DENY   Anywhere\n5000/tcp   ALLOW   Anywhere\n"),
    ("range allow out", "5000:5010/tcp   ALLOW OUT   Anywhere\n"),
    ("range from one net", "5000:5010/tcp   ALLOW   198.51.100.0/24\n"))}
check("install.sh update hint: a port range or list covering the panel port is a rule for it — a "
      "range DENY above the ALLOW is closed, a range ALLOW from Anywhere open",
      (_ups75["range deny first"], _ups75["list deny first"], _ups75["range allow"])
      == ("closed", "closed", "open"), repr(_ups75))
check("install.sh update hint: ...a range that misses the port, a udp range, an outbound range and a "
      "range from one network change nothing (controls)",
      (_ups75["range elsewhere"], _ups75["udp range"], _ups75["range allow out"],
       _ups75["range from one net"]) == ("open", "open", "closed", "closed"), repr(_ups75))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Page scripts that decided by English words the walker has translated
# ════════════════════════════════════════════════════════════════════════════════════════════════
from unit.part01 import skip as _skip75  # noqa: E402
from unit.part47 import _cut47 as _cut75, _node47 as _node75  # noqa: E402

_JS75 = os.path.join(_root75, "static", "js")


def _js75(name):
    with open(os.path.join(_JS75, name), encoding="utf-8") as fh:
        return fh.read()


def _cut_or75(src, head):
    """_cut47's statement, or a comment naming it when the code no longer has it.

    The check that runs it then fails BY NAME instead of this part raising at import.
    """
    return _cut75(src, head) if head in src else "/* MISSING %s */" % head


def _run_js75(name, prog):
    out = _node75(prog)
    if out is None:
        _skip75(name, "node is not installed here")
    return out


# The Connect pill copied its own text when /stats had not answered: an es viewer's placeholder
# ("resolviendo…", the walker's translation of 'resolving…') passed the English comparison and was
# put on the clipboard as the address, with a "Copied" flash.
_name75 = "connect pill: nothing is copied before the address is known"
_out75 = _run_js75(_name75, (
    "global.window = global; const copied = [];\n"
    "global.tf = (s, v) => s.replace('{text}', v.text);\n"
    "window.copyText = (a) => copied.push(a);\n"
    "global.document = {getElementById: () => ({textContent: 'resolviendo…'})};\n"
    "var connectAddr = '';\n" + _cut_or75(_js75("server_detail.js"), "function copyConnect(") + "\n"
    "copyConnect(); document.getElementById = () => ({textContent: 'desconocido'}); copyConnect();\n"
    "const before = copied.splice(0); connectAddr = '[2001:db8::5]:27015'; copyConnect();\n"
    "console.log(JSON.stringify({before: before, after: copied}));\n"))
if _out75 is not None:
    check("connect pill: before /stats answers (or with no address) nothing is copied, whatever language "
          "the placeholder is in — it copied \"resolviendo…\" as the address",
          _out75.get("before") == [], repr(_out75))
    check("connect pill: ...and the address /stats answered is copied (control)",
          _out75.get("after") == ["[2001:db8::5]:27015"], repr(_out75))

# The file page's save lines and the protected-file tooltip were translated BEFORE they were
# written (#426's _tr). The walker then stored the translation as the node's English, so a live
# language switch left them in the old language. Written in English, the walker translates them on
# arrival and again on every switch (its ✓/✗ handling looks up the rest of the line).
_SF75 = _js75("server_files.js")
_said75 = {"✓ Saved — restart the server to apply.": "Saved — restart the server to apply.",
           "✗ Save failed": "Save failed", "✓ Saved — restart to apply.": "Saved — restart to apply.",
           "Protected — required by LinuxGSM/the game": "Protected — required by LinuxGSM/the game"}
_bad75 = [w for w, k in _said75.items() if ("'%s'" % w) not in _SF75 or "_tr('%s')" % k in _SF75
          or k not in _ES75 or k not in _FR75]
check("file page: the save lines and the protected tooltip are written in English for the page's "
      "translator (a switch of language follows them), and each is an es and fr key", not _bad75, repr(_bad75))


# ── the JS i18n gate claims the shapes those strings were written in ────────────────────────────
# Fourteen panel strings had no es/fr entry with the gate green: words after a closing tag up to a
# <br> or the end, a one-word label ending in "." or "!", an element's text split over two
# literals (with a comment beside the `+`), and a busy label handed to a helper (now t()).
_tdj75 = os.path.realpath(_tf75.mkdtemp(prefix="lgsm-unit-p75js-"))
try:
    with open(os.path.join(_tdj75, "x.js"), "w", encoding="utf-8") as _fh75:
        _fh75.write(
            "function a(el, b){\n"
            "  el.innerHTML = '<strong>1.</strong> Open this link and approve it:<br><a href=\"#\">x</a>';\n"
            "  b.innerHTML = '<span class=\"spinner-border\"></span> Detecting…';\n"
            "  el.innerHTML = '<span class=\"text-success\">Installed.</span> Starting…';\n"
            "  el.innerHTML = '<span class=\"text-success\">Connected!</span>';\n"
            "  el.innerHTML = '<span>Still waiting — press the button '  // nosemgrep\n"
            "    + 'again once you have approved it.</span>';\n"
            "  el.innerHTML = '<code>' + name + '</code> is not on this host<br>';\n"
            "}\n")
    _js_found75 = sorted(_scan75.scan_js(js_dir=_tdj75))
finally:
    _shutil75.rmtree(_tdj75, ignore_errors=True)
_want75 = ["Connected!", "Detecting…", "Installed.", "Open this link and approve it:",
           "Still waiting — press the button again once you have approved it."]
check("i18n gate: the JS scan claims words after a closing tag (to a <br> or the end), a one-word "
      "label ending in . or !, and an element's text split over literals with a comment at the +",
      all(w in _js_found75 for w in _want75), repr(_js_found75))
check("i18n gate: ...but not lower-case words after a tag, the rest of a sentence spliced around a "
      "value (control)", "is not on this host" not in _js_found75, repr(_js_found75))


# The install page marked a game "(needs ubuntu 20.04)" when the chosen host ran a newer Ubuntu,
# and kept that note after the host select moved to a host that allows it: an enabled option still
# carried the reason it had been greyed out.
_MS75 = _js75("manage_servers.js")
_name75 = "install page: a game's (needs …) note goes when another host allows it"
_out75 = _run_js75(_name75, (
    "const settle = async () => { for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = '';\n"
    "global.tf = (s, v) => s.replace('{os}', v.os);\n"
    "function mkOpt(value, os, text){ const a = {'data-legacy-os': os}; return {value, textContent: text,\n"
    "  disabled: false, getAttribute: k => (k in a ? a[k] : null), hasAttribute: k => k in a,\n"
    "  setAttribute: (k, v) => { a[k] = v; }, removeAttribute: k => { delete a[k]; }}; }\n"
    "const old = mkOpt('ut2k4', 'ubuntu-20.04', 'Unreal Tournament 2004 (ubuntu-20.04)');\n"
    "const sel = {value: '', options: [old]}, host = {value: '1'};\n"
    "const slug = {'1': 'ubuntu-24.04', '2': 'ubuntu-20.04'};\n"
    "global.fetch = (u) => Promise.resolve({ok: true, json: () => Promise.resolve({os_slug: slug[u.split('/')[3]]})});\n"
    "global.document = {getElementById: id => ({'game-type-select': sel, 'remote-select': host})[id] || null};\n"
    + "".join(_cut_or75(_MS75, "function %s(" % _f75) + "\n" for _f75 in (
        "_osOlder", "_osVersionParts", "_osVersionBelow", "_withoutParenNote"))
    + _cut_or75(_MS75, "function _hostStillSelected(") + "\n" + _cut_or75(_MS75, "function filterGamesForHost(") + "\n"
    "(async () => { filterGamesForHost(); await settle(); const on24 = [old.textContent, old.disabled];\n"
    "  host.value = '2'; filterGamesForHost(); await settle();\n"
    "  console.log(JSON.stringify({on24: on24, on20: [old.textContent, old.disabled]})); })();\n"))
if _out75 is not None:
    check("install page: a game greyed out with \"(needs ubuntu 20.04)\" gets its own text back when the "
          "host select moves to a host that allows it",
          _out75.get("on24") == ["Unreal Tournament 2004 (needs ubuntu 20.04)", True]
          and _out75.get("on20") == ["Unreal Tournament 2004 (ubuntu-20.04)", False], repr(_out75))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. The host page's header says whether the panel can reach the host
# ════════════════════════════════════════════════════════════════════════════════════════════════
# It said "Unknown" for a host the panel had checked and could not reach (the dashboard and the
# Remote Servers list said "Unreachable"), and "Online" for as long as the page stayed open after
# the host died.
import re as _re75  # noqa: E402
from panel.core.panel_state import _monitor_state as _mon75  # noqa: E402
from unit.part12 import _p9_set_host as _p9_set_host75  # noqa: E402

_host_was75 = _p9_host_row(P9_HOST).is_online
_probed_was75 = P9_HOST in _mon75["remotes"]
_seen75 = {}
try:
    _p9_arm(who="part75")
    _p9_patch(_so75, "get_server_status", lambda *a, **k: None)
    for _k75, _on75, _pr75 in (("down", False, True), ("unchecked", False, False), ("up", True, True)):
        _p9_set_host75(P9_HOST, is_online=_on75)
        if _pr75:
            _mon75["remotes"].setdefault(P9_HOST, {})
        else:
            _mon75["remotes"].pop(P9_HOST, None)
        _pg75 = _p9_client(P9_ADMIN).get("/remote/%d/manage" % P9_HOST).get_data(as_text=True)
        _m75 = _re75.search(r'<span class="badge ([^"]*)" id="remote-status"\s+title="([^"]*)">\s*([^<]*?)\s*</span>', _pg75)
        _seen75[_k75] = _m75.groups() if _m75 else None
finally:
    _p9_restore_all()
    _p9_set_host75(P9_HOST, is_online=_host_was75)
    if not _probed_was75:
        _mon75["remotes"].pop(P9_HOST, None)
check("host page: the header badge says Unreachable (red) for a host the panel checked and cannot reach, "
      "Checking… before the first check, Reachable when it answers — it said \"Unknown\" for a dead host",
      _seen75 == {"down": ("bg-danger", "The panel cannot reach this host over SSH", "Unreachable"),
                  "unchecked": ("bg-secondary", "The panel has not checked this host yet", "Checking…"),
                  "up": ("bg-success", "The panel can reach this host over SSH", "Reachable")}, repr(_seen75))

_name75 = "host page: the header badge follows the live read"
_out75 = _run_js75(_name75, (
    "const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };\n"
    "global.window = global; global.MOUNT = ''; global.REMOTE_ID = 3; global.t = s => s;\n"
    "const badge = {className: 'badge bg-success', textContent: 'Reachable', attrs: {},\n"
    "  setAttribute(k, v){ this.attrs[k] = v; }};\n"
    "const stale = {style: {}, textContent: ''};\n"
    "global.document = {getElementById: id => ({'remote-status': badge, 'live-stale': stale})[id] || null};\n"
    "let answer = {error: 'x', unreachable: true};\n"
    "global.fetch = () => Promise.resolve({json: () => Promise.resolve(answer)});\n"
    "function _livePaintCpu(){} function _livePaintMemory(){} function _livePaintDisk(){}\n"
    + _cut_or75(_js75("remote_manage.js"), "function _r18cPaintHostBadge(") + "\n"
    + _cut_or75(_js75("remote_manage.js"), "function pollLive(") + "\n"
    "(async () => { pollLive(); await settle(); const down = [badge.className, badge.textContent];\n"
    "  answer = {error: 'read failed'}; pollLive(); await settle(); const failed = [badge.className, badge.textContent];\n"
    "  answer = {cpu_overall: 1}; pollLive(); await settle();\n"
    "  console.log(JSON.stringify({down, failed, up: [badge.className, badge.textContent]})); })();\n"))
if _out75 is not None:
    check("host page: a live read the host did not answer turns the header badge to Unreachable, a read "
          "that answers back to Reachable, and a failed read of an answering host leaves it",
          _out75 == {"down": ["badge bg-danger", "Unreachable"], "failed": ["badge bg-danger", "Unreachable"],
                     "up": ["badge bg-success", "Reachable"]}, repr(_out75))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. Text an admin or LinuxGSM wrote is shown as written; a page asks only for what it shows
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The login page's site title and custom tagline, and a game's display name on three pages, sat
# where the page's translator reads: one that happened to equal a catalog key was translated.
_saved_cfg75 = dict(_cfg75.load_config())
try:
    _p9_arm(who="part75")
    _cfg75.save_config(dict(_saved_cfg75, site_title="Dashboard", login_tagline="Settings"))
    _login75 = _p9.test_client().get("/login").get_data(as_text=True)
finally:
    _p9_restore_all()
    _cfg75.save_config(_saved_cfg75)
check("login page: the admin's site title and tagline are guarded from the translator (a title equal "
      "to a catalog key was translated), and the default tagline is not",
      '<h3 class="mt-2" data-no-i18n>Dashboard</h3>' in _login75
      and "<span data-no-i18n>Settings</span>" in _login75, _login75[_login75.find("<h3"):][:400])
_tpl75 = {n: open(os.path.join(_root75, "templates", n), encoding="utf-8").read()
          for n in ("dashboard.html", "remote_manage.html", "server_detail.html", "login.html")}
_open75 = [n for n, src in _tpl75.items()
           for line in src.splitlines() if "{{ srv.game_display" in line or "{{ gs.game_display" in line
           or "{{ server.game_display" in line
           if "data-no-i18n" not in line and 'data-type="{{ srv.game_display' not in line]   # an attribute
check("pages: a game's display name is shown inside data-no-i18n wherever it is printed as text",
      not _open75 and "Sign in to manage your game servers{% endif %}" in _tpl75["login.html"], repr(_open75))
check("file page: the listing is asked for only when the page has a file browser (a failed install has "
      "none, and every load spent an SSH round trip on it)",
      "if (document.getElementById('file-list')) browse('');" in _SF75
      and "\nbrowse('');" not in _SF75, "top-level browse('') is not gated")


check("part75: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP75_START, repr(_P9_TRIPPED[_TRIP75_START:][:6]))
