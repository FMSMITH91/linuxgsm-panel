"""Part 221 of the unit suite: the pen test's file-browser, error-page, step-up and outbound-URL findings.

* The file browser never writes, uploads, creates or renames onto a path that decides who can sign
  in to the game account (~/.ssh, the shell start-up files, .pam_environment, .rhosts/.shosts,
  .k5login): by name in Python, and for a write on the path the HOST resolves, so a link to ~/.ssh
  is refused too. Real bash over this part's own fixture tree; the routes on part12's app.
* The panel's web server (wsgi_serve.serve, started for real on loopback) answers a stream that fails
  with a bare 500: no traceback, path or exception text reaches the client.
* Step-up on the remaining root-equivalent POSTs (host firewall, SSH port and mode, close port 22,
  reboot, OS update, panel update, branch switch, key rotation, the host add/edit forms): a stale
  sign-in gets the confirm answer, and the pages' callers (run in node) confirm in place first.
* The ntfy server goes only to public addresses unless the operator marks it as on their own network
  (OWASP SSRF Prevention), with the Test button sending the form's switch.
* A Tailscale route list the joins refuse is a 400 with a plain sentence, before the host is asked.

HOW IT RUNS. On part12's Flask app with its transport tripwire armed for each section, every stub
undone in its finally. Bash runs only over this part's temporary tree; nothing reaches a host, sudo or
the checkout's data/.
"""
import io as _io221
import os as _os221
import shutil as _shutil221
import subprocess as _sp221  # nosec B404 - runs bash over this part's own fixture tree
import tempfile as _tempfile221
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_sf)
from panel.db.models import GameServer as _GS221, RemoteServer as _RS221, db as _db221
from panel.ops.ssh_manager import files as _files221

_trips221 = len(_P9_TRIPPED)
_TREE221 = _tempfile221.mkdtemp(prefix="lgsm-unit-p221-")
_HOME221 = "/home/p221u"
_ROWS221 = {"remotes": [], "servers": []}


def _setup221():
    """A host row and one game server on it; the server's id."""
    with _p9.app_context():
        r = _RS221(name="p221-host", host="p221.example.invalid", port=22, username="admin",
                   auth_method="key", auth_credential="", is_online=True)
        _db221.session.add(r)
        _db221.session.commit()
        gs = _GS221(remote_id=r.id, name="p221-css", short_name="p221u", game_type="css", port=27221,
                    installed=True, status="offline")
        _db221.session.add(gs)
        _db221.session.commit()
        _ROWS221["remotes"].append(r.id)
        _ROWS221["servers"].append(gs.id)
        return gs.id


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Sign-in paths in the game account's home (M2)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _fixture221():
    """The fixture home: ~/.ssh, serverfiles/, and `keys -> .ssh` (a link a mod or the game could plant)."""
    home = _TREE221 + _HOME221
    _shutil221.rmtree(home, ignore_errors=True)
    _os221.makedirs(home + "/.ssh")
    _os221.makedirs(home + "/serverfiles")
    _os221.symlink(".ssh", home + "/keys")
    return home


def _bash221(server, user, sh, timeout=30, selfname=None):
    """shell_as_game_user, run by real bash with the home moved under this part's tree."""
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp221.run(["bash", "-c", sh.replace(_HOME221, _TREE221 + _HOME221)],  # nosec B603 B607
                   capture_output=True, text=True, timeout=timeout, check=False)
    return r.stdout, r.stderr, r.returncode


def _m2_host221():
    """A write whose target RESOLVES to ~/.ssh is refused on the host before a byte is staged."""
    home = _fixture221()
    _p9_patch(_p9_core, "shell_as_game_user", _bash221)
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP221 planted\n"
    got = {"link": _files221.write_file(NS(id=-221), "p221u", "keys/authorized_keys", key),
           "link big": _files221.upload_file(NS(id=-221), "p221u", "keys", "authorized_keys2", b"k" * 90000),
           "plain": _files221.write_file(NS(id=-221), "p221u", "serverfiles/server.cfg", "hostname x\n")}
    left = sorted(_os221.listdir(home + "/.ssh"))
    eq("file browser (real bash): a save and a chunked upload through a link to ~/.ssh are refused on the "
       "host with the sign-in sentence, and nothing is left in ~/.ssh; a plain file still saves (control)",
       (got["link"], got["link big"], got["plain"][0], left,
        open(home + "/serverfiles/server.cfg", encoding="utf-8").read()),
       ((False, _files221.LOGIN_FILE_REFUSED), (False, _files221.LOGIN_FILE_REFUSED), True, [], "hostname x\n"))
    reads = _bash221(None, None, _files221._guarded("p221u", _HOME221 + "/keys/x", "echo READ"))[0].strip()
    eq("file browser (real bash): the read guard is unchanged: a read through the same link still runs",
       reads, "READ")


def _m2_names221():
    """By name, before any round trip: each sign-in path, for each of the four ways to write."""
    names = (".ssh/authorized_keys", ".ssh", ".ssh/rc", ".bashrc", ".profile", ".bash_profile",
             ".bash_login", ".bash_logout", ".pam_environment", ".rhosts", ".shosts", ".k5login",
             "./.ssh/../.ssh/authorized_keys")
    hits = [n for n in names if not _files221._is_login_path(n)]
    eq("file browser: every sign-in path is one by name, written however", hits, [])
    eq("file browser: game files with similar names are not sign-in paths (controls)",
       [_files221._is_login_path(n) for n in (".bashrc.bak", "serverfiles/.ssh", "cfg/.profile", "sshkeys")],
       [False] * 4)
    eq("file browser: rename onto, or out of, a sign-in path, and create in ~/.ssh or as .bash_profile, are "
       "refused with the sign-in sentence",
       [_files221.rename_refusal("p221u", "notes.txt", ".bash_login"),
        _files221.rename_refusal("p221u", ".ssh/authorized_keys2", "authorized_keys"),
        _files221.create_refusal("p221u", ".ssh", "authorized_keys", "file"),
        _files221.create_refusal("p221u", "", ".bash_profile", "file")],
       [_files221.LOGIN_FILE_REFUSED] * 4)
    eq("file browser: the refusal is one an audit row may carry", _files221.write_failure_reason(
        _files221.LOGIN_FILE_REFUSED), _files221.LOGIN_FILE_REFUSED)


def _m2_routes221():
    """The four routes answer the refusal and never reach the host; a plain save still does."""
    gid = _setup221()
    sent = []
    _p9_patch(_p9_core, "shell_as_game_user", lambda server, user, sh, timeout=30, **k: sent.append(sh) or ("", "", 0))
    _p9_patch(_p9_sf, "game_account_write_refusal", lambda *a, **k: None)
    c = _p9_client(P9_ADMIN)
    base = "/api/server/%d/" % gid
    answers = [
        _p9_json(c.post(base + "file", json={"path": ".bashrc", "content": "curl x | sh\n"})),
        _p9_json(c.post(base + "file", json={"path": ".ssh/authorized_keys", "content": "ssh-ed25519 A\n"})),
        _p9_json(c.post(base + "upload", content_type="multipart/form-data",
                        data={"path": ".ssh", "overwrite": "1",
                              "file": (_io221.BytesIO(b"ssh-ed25519 A\n"), "authorized_keys")})),
        _p9_json(c.post(base + "rename-path", json={"path": "notes.txt", "new_name": ".bash_login"})),
        _p9_json(c.post(base + "create-path", json={"dir": ".ssh", "name": "authorized_keys", "kind": "file"})),
    ]
    refused = [(a.get("success"), a.get("message")) for a in answers]
    blocked = list(sent)
    ok = _p9_json(c.post(base + "file", json={"path": "serverfiles/server.cfg", "content": "hostname x\n"}))
    eq("file routes: save, upload, rename and create onto a sign-in path answer the sign-in sentence and "
       "send nothing to the host; a plain save still reaches it (control)",
       (refused, blocked, ok.get("success"), len(sent) > 0),
       ([(False, _files221.LOGIN_FILE_REFUSED)] * 5, [], True, True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A streamed body that fails sends no traceback (L1)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SERVE_JS221 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
from flask import Flask, Response
from panel.core import wsgi_serve

app = Flask("p221")


def _fails():
    raise ConnectionError("p221 stand-in failure /opt/p221/secret-path")
    yield b""


app.add_url_rule("/boom", "boom", lambda: Response(_fails(), mimetype="application/octet-stream"))
app.add_url_rule("/ok", "ok", lambda: "fine")
wsgi_serve.serve(app, "127.0.0.1", int(sys.argv[1]))
"""


def _free_port221():
    import socket as _socket221
    with _socket221.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def _get221(port, path):
    """GET `path` from 127.0.0.1:`port` -> (status, body bytes); (None, b"") when nothing answered."""
    import http.client as _hc221
    conn = _hc221.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return r.status, r.read()
    except (OSError, _hc221.HTTPException):
        return None, b""
    finally:
        conn.close()


def _l1_serve221():
    """The panel's server start (wsgi_serve.serve, run for real on loopback): a failing stream is a bare 500."""
    import sys as _sys221
    import time as _time221
    from unit import REPO_ROOT as _root221
    port = _free_port221()
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    proc = _sp221.Popen([_sys221.executable, "-c", _SERVE_JS221, str(port), str(_root221)],  # nosec B603
                        stdout=_sp221.DEVNULL, stderr=_sp221.PIPE)
    try:
        deadline = _time221.monotonic() + 20
        ready = _get221(port, "/ok")
        while ready[0] != 200 and proc.poll() is None and _time221.monotonic() < deadline:
            _time221.sleep(0.2)
            ready = _get221(port, "/ok")
        status, body = _get221(port, "/boom")
    finally:
        proc.kill()
        err = proc.communicate(timeout=10)[1].decode("utf-8", "replace")
    eq("server: a streamed body that raises before its first byte answers a bare 500 (no traceback, no path, "
       "no exception text); the server still logs the traceback on its own side",
       (ready[0], status, body, "Traceback" in err), (200, 500, b"", True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Step-up on the other root-equivalent POSTs
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STEP_UP_POSTS221 = ("/api/remote/{r}/close-port-22", "/api/remote/{r}/ssh-mode", "/api/remote/{r}/ssh-port",
                     "/api/remote/{r}/reboot", "/api/remote/{r}/os-update/start",
                     "/api/remote/{r}/firewall/open", "/api/remote/{r}/firewall/allow-from",
                     "/api/remote/{r}/firewall/limit", "/api/remote/{r}/firewall/close",
                     "/api/remote/{r}/firewall/delete-rule", "/api/remote/{r}/firewall/settings",
                     "/api/remote/{r}/firewall/block-port", "/api/panel/update", "/api/panel/switch-branch",
                     "/api/panel/encryption/rotate", "/api/server-management/os-update-run",
                     "/api/server-management/reboot")


def _stale221(minutes_ago=60):
    """The superadmin's client, signed in `minutes_ago` minutes ago (past the 10-minute window)."""
    import time as _time221
    c = _p9_client(P9_ADMIN)
    with c.session_transaction() as sess:
        sess["_auth_at"] = _time221.time() - minutes_ago * 60
    return c


def _step_up_routes221():
    """Each listed POST, from a stale sign-in: the confirm answer, before the route does anything."""
    rid = _ROWS221["remotes"][0] if _ROWS221["remotes"] else (_setup221() and _ROWS221["remotes"][0])
    _p9.config["STEP_UP_MINUTES"] = 10
    from panel.ops.ssh_manager import firewall as _fw221
    _p9_patch(_fw221, "remote_ufw_settings", lambda remote: {"enabled": True, "p221": 1})
    c = _stale221()
    wrong = []
    for url in _STEP_UP_POSTS221:
        r = c.post(url.format(r=rid), json={})
        if not (r.status_code == 403 and r.headers.get("X-Reauth-Required") == "1"
                and _p9_json(r).get("error") == "reauth_required"):
            wrong.append((url, r.status_code))
    eq("step-up: every listed root-equivalent POST from a sign-in past the window answers the confirm 403 "
       "(X-Reauth-Required) that panel.js and step_up_form.js act on", wrong, [])
    forms = [c.post(u, data={"name": "p221"}) for u in ("/remotes/add", "/remotes/%d/edit" % rid)]
    eq("step-up: the Add and Edit host forms, sent as plain forms, go to the confirm page and come back",
       [(f.status_code, (f.headers.get("Location") or "").split("?")[0]) for f in forms],
       [(302, "/account/reauth")] * 2)
    got = c.get("/api/remote/%d/firewall/settings" % rid)
    fresh = _p9_client(P9_ADMIN).post("/api/remote/%d/firewall/settings" % rid, json={})
    eq("step-up: reading the firewall settings is not asked again (GET), and a fresh sign-in's change is not "
       "refused by step-up (controls)",
       (got.status_code, _p9_json(got).get("p221"), fresh.headers.get("X-Reauth-Required")), (200, 1, None))


_JS_STUBS221 = r"""
var calls = [], gate = {run: false};
var window = {STEP_UP_TOTP: true, stepUpThen: function(go, totp){ calls.push(['stepUp', totp]); if (gate.run) go(); }};
var MOUNT = '', REMOTE_ID = 7, remoteId = 7, _r32bSshPorts = '22';
var chain = {then: function(){ return chain; }, catch: function(){ return chain; }, finally: function(){ return chain; }};
function fetch(url, init){ calls.push(['fetch', url, (init || {}).method || 'GET']); return chain; }
function el(){ return {value: '8080', style: {}, className: '', innerHTML: '', textContent: '', disabled: false,
                       getAttribute: function(){ return null; }, setAttribute: function(){}}; }
var document = {getElementById: el, querySelectorAll: function(){ return {forEach: function(){}}; }};
function confirmDialog(o){ o.onConfirm(); }
function t(s){ return s; } function tf(s){ return s; } function esc(s){ return s; } function escapeHtml(s){ return s; }
function loadSshStatus(){} function refreshFirewall(){} function watchPanelRestart(){}
"""


def _js_fns221(path, names):
    """The top-level functions `names` of panel/static/js/`path`, each up to the next top-level function."""
    from unit import REPO_ROOT as _root221
    with open(_os221.path.join(_root221, "panel", "static", "js", path), encoding="utf-8") as fh:
        text = fh.read()
    out = []
    for name in names:
        i = text.find("\nfunction %s(" % name)
        j = text.find("\nfunction ", i + 1)
        out.append(text[i:j if j > 0 else len(text)] if i >= 0 else "/* missing %s */" % name)
    return "\n".join(out)


def _node221(name, script):
    """Run `script` in node; its last line parsed as JSON, or None when node is absent or failed."""
    import json as _json221
    if not _shutil221.which("node"):
        from unit.part01 import skip
        skip(name, "no node on this machine")
        return None
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp221.run(["node", "-"], input=script, capture_output=True, text=True, timeout=30, check=False)  # nosec B603 B607
    try:
        return _json221.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"node failed": r.stderr[-400:]}


def _step_up_js221():
    """The pages' callers confirm in place first: nothing is sent until stepUpThen runs the action."""
    fw = _js_fns221("remote_firewall.js", ("_fwStepUp", "_fwPostSetting", "_fwPostSettingNow", "openPort",
                                           "_openPortNow", "_restrictPost", "_restrictPostNow", "_fwValue"))
    host = _js_fns221("remote_manage_host.js", ("_rmhStepUp", "sshMode", "doPanelUpdate", "_doPanelUpdate",
                                                "rotateEncKey", "_rotateEncKey", "changeSshPort"))
    act = r"""
function act(){
  _fwPostSetting({setting: 'logging', value: 'low'}); openPort(); _restrictPost('/firewall/limit', {port: 22}, 'x');
  sshMode('allow'); doPanelUpdate(); rotateEncKey(); changeSshPort();
}
act(); var held = calls.slice(); calls = []; gate.run = true; act();
console.log(JSON.stringify({held: held, ran: calls.filter(function(c){ return c[0] === 'fetch'; })
                                              .map(function(c){ return c[1] + ' ' + c[2]; })}));
"""
    got = _node221("step-up js", _JS_STUBS221 + fw + "\n" + host + "\n" + act)
    if got is None:
        return
    eq("step-up (node): the firewall card's and the host page's actions only ask stepUpThen (with the 2FA "
       "flag) while it holds, then send to their routes once it runs them",
       got, {"held": [["stepUp", True]] * 7,
             "ran": ["/api/remote/7/firewall/settings POST", "/api/remote/7/firewall/open POST",
                     "/api/remote/7/firewall/limit POST", "/api/remote/7/ssh-mode POST",
                     "/api/panel/update-status GET", "/api/panel/encryption/rotate POST",
                     "/api/remote/7/ssh-port POST"]})
    form = r"""
var sent = [];
function _submitAjaxForm(f){ sent.push(f.name); }
function form(name, attrs){ return {name: name, hasAttribute: function(a){ return a in attrs; },
                                    getAttribute: function(a){ return a in attrs ? attrs[a] : null; }}; }
""" + _js_fns221("panel.js", ("_ajaxStepUp",)).split("\nwindow.ajaxForm")[0] + r"""
_ajaxStepUp(form('host', {'data-step-up': '', 'data-step-up-totp': '0'})); _ajaxStepUp(form('tag', {}));
var held = sent.slice(); gate.run = true; _ajaxStepUp(form('host', {'data-step-up': '', 'data-step-up-totp': '1'}));
console.log(JSON.stringify({held: held, sent: sent, asked: calls}));
"""
    got = _node221("step-up ajax form", _JS_STUBS221 + form)
    if got is not None:
        eq("step-up (node): an ajax form marked data-step-up waits for stepUpThen (its 2FA flag passed on); an "
           "unmarked one is sent at once (control)",
           got, {"held": ["tag"], "sent": ["tag", "host"], "asked": [["stepUp", False], ["stepUp", True]]})


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The ntfy server: public addresses only unless marked as on the operator's own network (I3)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ntfy221(addrs, private=None, via_route=None):
    """Send to https://ntfy.p221.example/alerts resolving to `addrs`: (answer, addresses connected to)."""
    import socket as _socket221
    from panel.services import notifications as _nt221
    connected = []

    class _Sock221:
        def __init__(self, *_a):
            pass

        def settimeout(self, _t):
            return None

        def connect(self, sa):
            connected.append(sa[0])
            raise OSError("p221 stand-in: no connection")

        def close(self):
            return None

    def _gai(host, port, *_a, **_k):
        return [(_socket221.AF_INET6 if ":" in a else _socket221.AF_INET, _socket221.SOCK_STREAM, 6, "",
                 (a, port) if ":" not in a else (a, port, 0, 0)) for a in addrs]
    _p9_patch(_nt221, "socket", NS(SOCK_STREAM=_socket221.SOCK_STREAM, getaddrinfo=_gai,
                                   socket=_Sock221, _GLOBAL_DEFAULT_TIMEOUT=_socket221._GLOBAL_DEFAULT_TIMEOUT))
    if via_route is not None:
        r = _p9_client(P9_ADMIN).post("/api/notifications/test", json=dict(
            {"channel": "ntfy", "server": "https://ntfy.p221.example", "topic": "alerts"}, **via_route))
        return _p9_json(r), connected
    return _nt221.send_ntfy("https://ntfy.p221.example", "alerts", "", "p221", private), connected


def _ntfy_ssrf221():
    """Without the switch a LAN, tailnet, ULA or ::a.b.c.d address is refused before any connect."""
    from panel.services import notifications as _nt221
    refused = {a: _ntfy221([a], private=False) for a in ("10.0.0.5", "192.168.1.9", "172.16.3.4", "100.100.100.100",
                                                         "fd12:3456::5", "::ffff:10.0.0.5", "2001:db8::20")}
    wrong = {a: v for a, v in refused.items() if v != ((False, _nt221.NTFY_PRIVATE_REFUSED), [])}
    eq("ntfy: with private addresses not allowed, a server on a LAN, tailnet, ULA, IPv4-mapped LAN or "
       "documentation address is refused before any connect, and says how to allow it", wrong, {})
    eq("ntfy: an IPv4-compatible address (::127.0.0.1, ::10.0.0.5) is refused even with private addresses "
       "allowed", [_ntfy221([a], private=True) for a in ("::7f00:1", "::a00:5")],
       [((False, _nt221.NTFY_ADDRESS_REFUSED), [])] * 2)
    doc = _ntfy221(["203.0.113.9"], private=False)
    lan_on = _ntfy221(["10.0.0.5"], private=True)
    meta_on = _ntfy221(["169.254.169.254"], private=True)
    pub = _ntfy221(["8.8.4.4"], private=False)
    eq("ntfy: a public address is connected to; with the switch on a LAN address is too, and metadata is "
       "still refused either way (controls)",
       (pub[1], lan_on[1], meta_on, doc[0][1] == _nt221.NTFY_PRIVATE_REFUSED),
       (["8.8.4.4"], ["10.0.0.5"], ((False, _nt221.NTFY_ADDRESS_REFUSED), []), True))
    routed = {"off": _ntfy221(["10.0.0.5"], via_route={"private_network": False}),
              "on": _ntfy221(["10.0.0.5"], via_route={"private_network": True})}
    eq("ntfy: the Test button sends the form's switch: off refuses the LAN server with nothing connected, on "
       "tries it",
       (routed["off"][1], "private network" in (routed["off"][0].get("message") or ""), routed["on"][1]),
       ([], True, ["10.0.0.5"]))
    eq("ntfy: settings saved before the switch keep what they had: a self-hosted server stays allowed, "
       "ntfy.sh does not need it; a saved switch is read as saved",
       [_nt221.ntfy_private_network(n) for n in ({"server": "https://ntfy.home.example"},
                                                 {"server": "https://ntfy.sh"}, {},
                                                 {"server": "https://ntfy.home.example", "private_network": False},
                                                 {"private_network": True})],
       [True, False, False, False, True])


def _ntfy_form221():
    """Saving the form stores the switch; the page shows it with the recommendation beside it."""
    from panel.services import notifications as _nt221
    stored = {}
    _p9_patch(_nt221, "update_config", lambda fn: fn(stored))
    _p9_patch(_nt221, "_cfg", lambda: {})
    c = _p9_client(P9_ADMIN)
    c.post("/notifications/save", data={"ntfy_enabled": "on", "ntfy_server": "https://ntfy.home.example",
                                        "ntfy_topic": "alerts", "ntfy_private_network": "on"})
    on = (stored.get("notifications") or {}).get("ntfy", {}).get("private_network")
    c.post("/notifications/save", data={"ntfy_server": "https://ntfy.home.example", "ntfy_topic": "alerts"})
    off = (stored.get("notifications") or {}).get("ntfy", {}).get("private_network")
    _p9_patch(_nt221, "_cfg", lambda: {"ntfy": {"server": "https://ntfy.home.example", "private_network": True}})
    page = c.get("/notifications").get_data(as_text=True)
    eq("ntfy: the switch is saved on and off, and the page shows it ticked with OWASP's recommended value "
       "and the outside-the-recommendation note",
       (on, off, 'name="ntfy_private_network"' in page, "Recommended: off" in page,
        "On: outside the recommendation" in page), (True, False, True, True, True))
    eq("step-up: every page tells its scripts whether a password confirmation also asks for the 2FA code "
       "(this superadmin has none)", "window.STEP_UP_TOTP = false;" in page, True)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Validation failures on the Tailscale joins are 400s (I4)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ts_routes221():
    """A route list the joins refuse is a 400 with the plain sentence, before the host is asked."""
    from panel.routes import remote_tailscale as _rt221
    with _p9.app_context():
        row = _RS221(name="p221-ts", host="p221ts.example.invalid", port=22, username="admin",
                     auth_method="key", auth_credential="", is_online=True)
        _db221.session.add(row)
        _db221.session.commit()
        _ROWS221["remotes"].append(row.id)
        rid = row.id
    called = []
    _p9_patch(_rt221, "remote_tailscale_up_url", lambda *a, **k: called.append("up") or (True, "ALREADY_CONNECTED"))
    _p9_patch(_rt221, "remote_bootstrap_tailscale", lambda *a, **k: called.append("key") or (True, "ok", ""))
    c = _p9_client(P9_ADMIN)
    bad = [c.post("/api/remote/%d/tailscale-up" % rid, json={"advertise_routes": "10.0.0.1"}),
           c.post("/api/remote/%d/tailscale-bootstrap" % rid,
                  json={"auth_key": "tskey-auth-p221", "advertise_routes": "192.168.1.5/24"})]
    good = c.post("/api/remote/%d/tailscale-up" % rid, json={"advertise_routes": "10.0.0.0/24"})
    eq("tailscale: a route list the join refuses answers 400 with the plain sentence for both joins, and the "
       "host is never asked; a usable list still goes through (control)",
       ([(b.status_code, (_p9_json(b).get("message") or "")[:21]) for b in bad], called, good.status_code),
       ([(400, "Routes must be comma-")] * 2, ["up"], 200))


def _cleanup221():
    with _p9.app_context():
        for sid in _ROWS221["servers"]:
            row = _db221.session.get(_GS221, sid)
            if row is not None:
                _db221.session.delete(row)
        for rid in _ROWS221["remotes"]:
            row = _db221.session.get(_RS221, rid)
            if row is not None:
                _db221.session.delete(row)
        _db221.session.commit()
    _shutil221.rmtree(_TREE221, ignore_errors=True)


try:
    for _fn221 in (_m2_host221, _m2_names221, _m2_routes221, _l1_serve221, _step_up_routes221, _step_up_js221,
                   _ntfy_ssrf221, _ntfy_form221, _ts_routes221):
        _p9_arm(who="part221")
        try:
            _fn221()
        finally:
            _p9_restore_all()
finally:
    _p9_restore_all()
    _cleanup221()

check("part221: nothing reached a real transport", len(_P9_TRIPPED) == _trips221, repr(_P9_TRIPPED[_trips221:]))
