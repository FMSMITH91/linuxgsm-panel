"""Part 319 of the unit suite: WordPress's way out through its egress proxy, and the PHP gate under an error page.

1. A WordPress site with the egress proxy: the container's 127.0.0.1:3128 is forwarded to the host port the proxy's
   unit listens on, the proxy started from that unit listens and refuses a host not on its list, the hosts file the
   loopback plugin reads is written and mounted where the plugin reads it, and the plugin lets an HTTPS request to
   those hosts past WordPress's own name lookup (the container has no name server: every update download failed).
2. A WordPress site with full egress has no proxy: no 3128 forward, no hosts file, its old proxy unit disabled, and
   the plugin then sends nothing to the proxy (wp-config still names it: every request failed at once with
   "Failed to connect to 127.0.0.1 port 3128").
3. Switching full egress on the Settings tab installs the site again (its network changes); a note alone does not.
4. A site installed with the files of before is offered Update (the files' revision was raised).
5. The PHP gate: a site's own `ErrorDocument 403 /index.php` turned a refused request into one that ran PHP, as
   Apache does not run authorization again on that redirect. The virtual host's rewrite rules (before any .htaccess,
   on every request and redirect) refuse it; a rewritten request, a subrequest and the site's own error page after
   a refusal of a request that had the token are still served.
6. Put online's answer handled: a failure while handling it is said, not left as an unhandled rejection.

HOW IT RUNS. part12's app and its database. ssh_manager.websites' install runs for real down to the account's
shell, which is recorded (nothing reaches a host: part12's tripwire is armed). Section 1 starts the egress proxy
the bundle carries as its own process on a free loopback port.
"""
import base64 as _b64319
import os
import re as _re319
import socket as _so319
import subprocess as _sp319  # nosec B404 - python3 -I over the egress proxy the bundle carries, on 127.0.0.1
import sys
import tempfile as _tmp319
import time as _time319

from flask import g as _g319

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part301 import _COMMON301, _node301, _page301
from panel.core import config as _cfg319
from panel.db.models import RemoteServer as _Remote319, User as _User319, Website as _Site319, db as _db319
from panel.ops.ssh_manager import websites as _sw319
from panel.routes import websites as _w319
from panel.services import websites as _ws319

_TOKEN319 = "q" * 40
_ROWS319 = {"sites": [], "remotes": [], "users": []}
_SH319 = []
_PROBE319 = {"uid": 1005, "gid": 1005, "splice": True, "cpu_delegated": True, "os": "26.04",
             "podman": "podman version 5.7.0"}


def _post319(uid, path, body=None):
    _g319.pop("_login_user", None)
    return _p9_client(uid).post(path, json=body or {})


def _rows319():
    r = _Remote319(name="p319-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.79")
    su = _User319(username="p319-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db319.session.add_all([r, su])
    _db319.session.commit()
    _ROWS319["remotes"].append(r.id)
    _ROWS319["users"].append(su.id)
    return r, su


def _site319(host, name, kind="wordpress", **kw):
    extra = {"php_version": "8.4"} if kind in _ws319.KINDS_PHP else {}
    extra.update({"app_recipe": "wordpress"} if kind == "wordpress" else {})
    s = _Site319(remote_id=host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg319.encrypt_secret(_TOKEN319), **dict(extra, **kw))
    _db319.session.add(s)
    _db319.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db319.session.commit()
    _ROWS319["sites"].append(s.id)
    return s


def _as_site319(remote, account, sh, timeout=120, stdin_text=None):
    """The account's shell, recorded; it answers as a host where each step worked."""
    _SH319.append((account, sh, stdin_text or ""))
    return True, ""


def _seams319():
    _p9_patch(_sw319, "_as_site", _as_site319)
    _p9_patch(_sw319, "_ids", lambda remote, site: ((1005, 1005), dict(_PROBE319)))
    _p9_patch(_sw319, "runtime_ready", lambda remote: "")
    _p9_patch(_sw319, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "account=exists"))
    _p9_patch(_sw319, "quota_set", lambda *a, **k: (True, "quota"))
    _p9_patch(_sw319, "cpu_limit", lambda *a, **k: (True, "container"))


def _installed319():
    """(install_sh, its stdin bundle, start_sh) of the last install recorded, "" for a part that did not run."""
    inst = [(sh, stdin) for _a, sh, stdin in _SH319 if "SITE_FILES_REFUSED" in sh]
    starts = [sh for _a, sh, _i in _SH319 if "reset-failed" in sh]
    sh, stdin = inst[-1] if inst else ("", "")
    return sh, stdin, starts[-1] if starts else ""


def _file319(stdin, path):
    """The file at `path` (relative to the account's home) in an install bundle, or None when it is not in it."""
    for line in stdin.splitlines():
        p, _sp, data = line.partition(" ")
        if p == path:
            return _b64319.b64decode(data).decode("utf-8")
    return None


def _plugin319(install_sh):
    """The loopback plugin install_sh writes (its base64 argument after the plugin's path), or ""."""
    m = _re319.search(r"%s ([A-Za-z0-9+/=]+)" % _re319.escape(_ws319.LOOPBACK_PLUGIN), install_sh)
    return _b64319.b64decode(m.group(1)).decode("utf-8") if m else ""


def _install319(su, site):
    del _SH319[:]
    r = _post319(su.id, "/websites/%d/update-image" % site.id)
    return (r.status_code,) + _installed319()


def _forward319(quadlet):
    """The host port the container's 3128 is forwarded to (pasta -T 3128:<port>), or None."""
    net = next((ln for ln in quadlet.splitlines() if ln.startswith("Network=")), "")
    m = _re319.search(r"(?:^|,)-T,%d:(\d+)(?:,|$)" % _ws319.EGRESS_INNER_PORT, net[len("Network="):])
    return int(m.group(1)) if m else None


# ── 1. WordPress with its egress proxy ────────────────────────────────────────────────────────────
def _s1_proxy(host, su):
    site = _site319(host, "p319-wp")
    code, sh, stdin, start = _install319(su, site)
    home = "/home/%s/" % site.account
    quadlet = _file319(stdin, "%s/%s.container" % (_ws319.QUADLET_DIR, _ws319.UNIT)) or ""
    unit = _file319(stdin, "%s/%s.service" % (_ws319.USER_UNIT_DIR, _ws319.EGRESS_UNIT)) or ""
    argv = (_re319.search(r"^ExecStart=/usr/bin/python3 -I %h/\S+/egress_proxy\.py (.+)$", unit, _re319.M)
            or _re319.match("()", "")).group(1).split()
    eq("egress (POST /websites/<id>/update-image, a WordPress site): the container's 127.0.0.1:3128 is forwarded to "
       "the very port the proxy's unit listens on, the unit is enabled and restarted with the site, and it reaches "
       "WordPress's two update hosts only",
       (code, _forward319(quadlet) is not None and [str(_forward319(quadlet))] == argv[:1], argv[1:],
        "enable %s.service" % _ws319.EGRESS_UNIT in start, "disable --now %s" % _ws319.EGRESS_UNIT in sh),
       (200, True, ["api.wordpress.org", "downloads.wordpress.org"], True, False))
    plugin = _plugin319(sh)
    hosts = _file319(stdin, _ws319.EGRESS_HOSTS_FILE)
    mount = "Volume=%s%s:%s:ro" % (home, _ws319.RUN_DIR, _ws319.RUN_IN)
    read = _re319.search(r"define\( 'LGSM_PANEL_EGRESS_FILE', '([^']+)' \)", plugin)
    eq("egress: the hosts file is in the bundle, the folder holding it is mounted read-only where the loopback plugin "
       "reads it (the plugin reads exactly that file), and it names the proxy's hosts",
       (hosts, mount in quadlet.splitlines(),
        bool(read) and read.group(1) == _ws319.RUN_IN + _ws319.EGRESS_HOSTS_FILE[len(_ws319.RUN_DIR):]),
       ("api.wordpress.org\ndownloads.wordpress.org\n", True, True))
    check("egress: the loopback plugin lets an HTTPS request (no user, port 443) to one of the proxy's hosts past "
          "WordPress's own address check, which looks the name up where there is no name server (download_url "
          "refused every update download)",
          all(x in plugin for x in ("add_filter( 'http_request_args', 'lgsm_panel_egress_args', 10, 2 );",
                                    "$args['reject_unsafe_urls'] = false;", "'https' !== strtolower( $parts['scheme'] )",
                                    "isset( $parts['user'] )", "443 !== (int) $parts['port']",
                                    "in_array( strtolower( $parts['host'] ), lgsm_panel_egress_hosts(), true )")),
          plugin[-1500:])
    _s1_listening(stdin, argv)


def _free_port319():
    s = _so319.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _ask319(port, line):
    """The proxy's answer (its status line) to one request line, b"" when it does not answer."""
    deadline = _time319.monotonic() + 10
    while True:
        try:
            c = _so319.create_connection(("127.0.0.1", port), timeout=5)
            break
        except OSError:
            if _time319.monotonic() > deadline:
                return b""
            _time319.sleep(0.05)
    try:
        c.sendall(line.encode("ascii") + b"\r\n\r\n")
        return c.recv(64).split(b"\r\n", 1)[0]
    except OSError:
        return b""
    finally:
        c.close()


def _s1_listening(stdin, argv):
    """The proxy the bundle carries, started as its unit starts it (only the port is a free one): it answers."""
    src = _file319(stdin, _ws319.HOME_DIR + "/egress_proxy.py") or ""
    d = _tmp319.mkdtemp(prefix="p319-egress-")
    path = os.path.join(d, "egress_proxy.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    port = _free_port319()
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    proc = _sp319.Popen([sys.executable, "-I", path, str(port)] + argv[1:],  # nosec B603 - fixed argv, own file
                        stdout=_sp319.DEVNULL, stderr=_sp319.PIPE)
    try:
        refused = _ask319(port, "CONNECT example.com:443 HTTP/1.1")
        wrong_port = _ask319(port, "CONNECT api.wordpress.org:80 HTTP/1.1")
        not_connect = _ask319(port, "GET http://api.wordpress.org/ HTTP/1.1")
    finally:
        proc.terminate()
        _err = proc.communicate(timeout=10)[1].decode("utf-8", "replace")
        os.remove(path)
        os.rmdir(d)
    eq("egress: the proxy started from the unit's own command listens on 127.0.0.1 and refuses a host not on its "
       "list, an allowed host on another port and anything but CONNECT (403), saying why in its journal",
       (refused, wrong_port, not_connect, "refused CONNECT example.com:443: not an allowed host on 443" in _err),
       (b"HTTP/1.1 403 Forbidden", b"HTTP/1.1 403 Forbidden", b"HTTP/1.1 403 Forbidden", True))


# ── 2. WordPress with full egress ─────────────────────────────────────────────────────────────────
def _s2_full(host, su):
    site = _site319(host, "p319-full", full_egress=True)
    code, sh, stdin, start = _install319(su, site)
    quadlet = _file319(stdin, "%s/%s.container" % (_ws319.QUADLET_DIR, _ws319.UNIT)) or ""
    plugin = _plugin319(sh)
    eq("full egress (POST /websites/<id>/update-image): no 3128 forward and no hosts file, the proxy unit an earlier "
       "install enabled is disabled and stopped and an earlier hosts file removed, and the proxy is not started",
       (code, bool(quadlet), _forward319(quadlet), _file319(stdin, _ws319.EGRESS_HOSTS_FILE),
        "systemctl --user disable --now %s.service 2>/dev/null; rm -f %s; " % (_ws319.EGRESS_UNIT,
                                                                               _ws319.EGRESS_HOSTS_FILE) in sh,
        _ws319.EGRESS_UNIT in start),
       (200, True, None, None, True, False))
    m = _re319.search(r"function lgsm_panel_no_proxy\( \$send, \$uri, \$check \) \{\n\tif \( array\(\) === "
                      r"lgsm_panel_egress_hosts\(\) \) \{\n\t\treturn false;\n\t\}", plugin)
    check("full egress: with no hosts file the loopback plugin sends nothing to the proxy wp-config names (WordPress "
          "connects directly; it failed at once on 127.0.0.1:3128), and the file it reads is the one install removes",
          bool(m) and "is_readable( LGSM_PANEL_EGRESS_FILE )" in plugin, plugin[-1500:])


# ── 3. the full-egress switch ─────────────────────────────────────────────────────────────────────
def _s3_switch(host, su):
    site = _site319(host, "p319-switch")
    same = {k: getattr(site, k) for k in _w319.LIMITS}
    del _SH319[:]
    _post319(su.id, "/websites/%d/settings" % site.id, {"limits": dict(same), "customer_note": "n", "full_egress": False})
    note_only = _installed319()[0]
    del _SH319[:]
    r = _post319(su.id, "/websites/%d/settings" % site.id, {"limits": dict(same), "full_egress": True})
    sh, stdin, start = _installed319()
    quadlet = _file319(stdin, "%s/%s.container" % (_ws319.QUADLET_DIR, _ws319.UNIT)) or ""
    eq("Settings (POST /websites/<id>/settings): switching full egress on installs the site again, so its network "
       "and WordPress's proxy follow (the switch was saved and nothing changed until another install); a save with "
       "the switch unchanged does not (control)",
       (r.status_code, bool(note_only), bool(sh), bool(quadlet) and _forward319(quadlet) is None, bool(start)),
       (200, False, True, True, True))


# ── 4. Update for the sites already installed ─────────────────────────────────────────────────────
def _s4_update(host):
    site = _site319(host, "p319-old")
    site.image_digest, site.image_key = _w319.current_image(site), "files-3"
    _db319.session.commit()
    old = _w319.update_available(site)
    _w319.note_installed(site)
    eq("Update: a site installed with the files of before (revision files-3) is offered Update, which writes the "
       "gate's rewrite rules, the hosts file and the plugin; once installed again it is not (control)",
       (old, _w319.update_available(site)), (True, False))


# ── 5. the PHP gate ───────────────────────────────────────────────────────────────────────────────
def _vhost_rewrites(conf):
    """The rewrite lines directly in <VirtualHost> (in no <Directory>, <Location>, <Files> or <If> in it)."""
    out, depth, in_vhost = [], 0, False
    for raw in conf.splitlines():
        ln = raw.strip()
        if ln.startswith("<VirtualHost"):
            in_vhost, depth = True, 0
        elif ln.startswith("</VirtualHost"):
            in_vhost = False
        elif in_vhost and ln.startswith("</"):
            depth -= 1
        elif in_vhost and ln.startswith("<"):
            depth += 1
        elif in_vhost and depth == 0 and ln.startswith("Rewrite"):
            out.append(ln)
    return out


def _cond319(test, pattern, headers, env):
    m = _re319.fullmatch(r"%\{(HTTP|ENV):([A-Za-z0-9_-]+)\}", test)
    c = _re319.fullmatch(r"(!?)=(.*)", pattern)
    if not m or not c:
        raise ValueError("part319's model reads only %{HTTP:x} or %{ENV:x} against =v or !=v: " + test + " " + pattern)
    have = (headers if m.group(1) == "HTTP" else env).get(m.group(2), "")
    return (have == c.group(2)) != bool(c.group(1))


def _conds_hold(conds, headers, env):
    """mod_rewrite's conditions: all must hold, a condition flagged [OR] joined with the next."""
    ok, cur, joined = True, False, False
    for test, pattern, flags in conds:
        v = _cond319(test, pattern, headers, env)
        cur = (cur or v) if joined else v
        joined = "OR" in flags
        if not joined:
            ok, cur = ok and cur, False
    return ok and (cur if joined else True)


def _gate_refuses(rules, headers, env, sub=False):
    """(refused, the environment after) of the virtual host's rewrite rules for one request.

    `env` is what Apache gives the request: empty for a client's request; on an internal redirect, the variables of
    the request it came from renamed REDIRECT_<name>, and REDIRECT_STATUS. A client's headers never reach it.
    """
    env, conds = dict(env), []
    if "RewriteEngine On" not in rules:
        return False, env
    for ln in rules:
        words = ln.split()
        if words[0] == "RewriteCond":
            conds.append((words[1], words[2], words[3].strip("[]").split(",") if len(words) > 3 else []))
        elif words[0] == "RewriteRule":
            flags = words[3].strip("[]").split(",") if len(words) > 3 else []
            hold, conds = _conds_hold(conds, headers, env), []
            if not hold or (sub and "NS" in flags):
                continue
            env.update(f[2:].split(":", 1) for f in flags if f.startswith("E="))
            if "F" in flags:
                return True, env
    return False, env


def _redirect319(env, status):
    """The environment of an internal redirect from a request with `env` that ended with `status`."""
    return dict({"REDIRECT_" + k: v for k, v in env.items()}, REDIRECT_STATUS=str(status))


def _s5_gate(host, su):
    site = _site319(host, "p319-php", kind="php")
    _code, _sh, stdin, _start = _install319(su, site)
    conf = _file319(stdin, _ws319.CONF + "/apache.conf") or ""
    rules = _vhost_rewrites(conf)
    tok = {_ws319.GATE_HEADER: _TOKEN319}
    _r1, env1 = _gate_refuses(rules, tok, {})
    _r2, env2 = _gate_refuses(rules, {}, _redirect319(env1, 200))
    _rf, env_f = _gate_refuses(rules, {}, {})
    cases = {
        "through the proxy, a file that is there": (tok, {}, False),
        "through the proxy, rewritten to index.php by .htaccess (the header removed in fixups)":
            ({}, _redirect319(env1, 200), False),
        "rewritten twice": ({}, _redirect319(env2, 200), False),
        "an index lookup (a subrequest) inside a request that passed": ({}, {}, True),
        "the site's own error page after its .htaccess refused a request that had the token":
            ({}, _redirect319(env1, 403), False),
        "on the loopback port with no token": ({}, {}, False),
        "no token, then the error page the site's .htaccess names (ErrorDocument 403 /index.php)":
            ({}, _redirect319(env_f, 403), False),
        "headers forging the marks": ({"REDIRECT_PANEL_GATE": "1", "PANEL_GATE": "1", "Redirect-Status": "200",
                                       "REDIRECT_STATUS": "200"}, {}, False),
        "a wrong token": ({_ws319.GATE_HEADER: "x" * 40}, {}, False),
        "the token with more after it": ({_ws319.GATE_HEADER: _TOKEN319 + "x"}, {}, False)}
    got = {k: _gate_refuses(rules, h, e, sub)[0] for k, (h, e, sub) in cases.items()}
    want = {k: k in ("on the loopback port with no token", "headers forging the marks", "a wrong token",
                     "the token with more after it",
                     "no token, then the error page the site's .htaccess names (ErrorDocument 403 /index.php)")
            for k in cases}
    eq("gate (POST /websites/<id>/update-image, a PHP site's Apache config): the virtual host's rewrite rules, which "
       "no .htaccess changes and which run on every request and internal redirect, refuse a token-less request and "
       "the error page a .htaccess sends it to (Apache skipped the <If> there and ran PHP); rewritten requests, "
       "subrequests and the site's own error pages behind the token are served",
       (bool(rules), got), (True, want))
    loads = "<IfModule !rewrite_module>\n    LoadModule rewrite_module /usr/lib/apache2/modules/mod_rewrite.so\n</IfModule>"
    eq("gate: mod_rewrite is loaded where the image has it off, the token's header is kept out of Vary ([NV]), and "
       "the <If> gate stays behind the rules (control: the authorization check is unchanged)",
       (loads in conf, any("[NV,OR]" in r and _ws319.GATE_HEADER in r for r in rules),
        "<If \"%%{HTTP:%s} != '%s' && %%{ENV:REDIRECT_STATUS} != '200'\">" % (_ws319.GATE_HEADER, _TOKEN319) in conf),
       (True, True, True))


# ── 6. Put online's answer handled ────────────────────────────────────────────────────────────────
def _s6_put_online(_host, su):
    from types import SimpleNamespace
    page = _page301("website.html", su.id, site=SimpleNamespace(id=7, name="shop", kind="php"), can_manage=True,
                    can_files=False, site_admin=True)
    scenario = r"""
  const seen = {};
  WS.post = function () { return Promise.resolve(@ANSWER@); };
  WS.putOnline(7, 'ws-offline-msg', function (ok) { seen.then = ok; });
  for (let i = 0; i < 6; i++) await tick();
  return {msg: $('ws-offline-msg').textContent, then: seen.then === undefined ? 'not run' : seen.then};
"""
    broken = _node301(page, _COMMON301 + ["website_site.js"], scenario.replace("@ANSWER@", "{get success() { throw new Error('x'); }}"),
                      routes={"/api/websites/7": {"success": True, "site": {"id": 7, "name": "shop", "kind": "php"}}})
    fine = _node301(page, _COMMON301 + ["website_site.js"], scenario.replace("@ANSWER@", "{success: true, message: 'Online.'}"),
                    routes={"/api/websites/7": {"success": True, "site": {"id": 7, "name": "shop", "kind": "php"}}})
    eq("Put online (js/websites_common.js WS.putOnline): a failure while its answer is handled is said in the message "
       "and the caller is told it failed, not left as an unhandled rejection; a plain answer is said as before (control)",
       (broken, fine), ({"msg": "That did not work. Nothing was changed.", "then": False}, {"msg": "Online.", "then": True}))


def _cleanup319():
    _db319.session.rollback()
    for model, ids in ((_Site319, _ROWS319["sites"]), (_User319, _ROWS319["users"]), (_Remote319, _ROWS319["remotes"])):
        for i in ids:
            row = _db319.session.get(model, i)
            if row is not None:
                _db319.session.delete(row)
    _db319.session.commit()


def _ran319(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran319.last)."""
    import traceback
    try:
        step(*args)
        _ran319.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db319.session.rollback()
        _ran319.last = traceback.format_exc()[-1500:]
        return False


_ran319.last = ""
_trips319 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part319")
        _seams319()
        _host319, _su319 = _rows319()
        for _sec319 in (_s1_proxy, _s2_full, _s3_switch, _s5_gate):
            check("part319: %s ran to the end" % _sec319.__name__, _ran319(_sec319, _host319, _su319), _ran319.last)
        check("part319: _s4_update ran to the end", _ran319(_s4_update, _host319), _ran319.last)
        check("part319: _s6_put_online ran to the end", _ran319(_s6_put_online, _host319, _su319), _ran319.last)
        eq("part319: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips319:], [])
    finally:
        _p9_restore_all()
        _w319._STATUS.clear()
        _cleanup319()
