"""Part 302 of the unit suite: fixes the websites' first proof round on the test host (P1) turned up.

1. Where the proxy listens (website-proxy-apply): only the host's own addresses, never the tailnet's (Tailscale
   Serve holds its 443), the loopback, link-local or temporary ones; a port another program holds is refused
   in words before anything changes; no address at all is a refusal too; a tunnel's own bind is kept.
2. Starting it: every apply enables the proxy and restarts it (a running proxy loads the new file), and
   success is said only when the unit stays running; otherwise the previous file is put back and the journal's
   last error is said in plain words. A refusal never shows the proxy's raw JSON (that goes to the log).

HOW IT RUNS. tools/panel-helper is loaded by path (as part05 and part299 do) with stand-ins for its subprocess,
pwd and folders (under a scratch folder); ssh_manager.websites runs with a stand-in for its _core; the proxy
routes run through part12's app with every host call a stand-in. Nothing reaches a host (part12's tripwire is
armed) and nothing is installed.
"""
import contextlib as _ctx302
import hashlib as _hashlib302
import importlib.machinery as _mach302
import importlib.util as _ilu302
import io as _io302
import json as _json302
import logging as _logging302
import os
import shutil as _shutil302
import tarfile as _tar302
import tempfile as _tf302
import time as _time302
from datetime import datetime as _dt302
from types import SimpleNamespace as _NS302

from flask import g as _g302

from unit.part01 import _root, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg302
from panel.db.models import (RemoteServer as _Remote302, User as _User302, Website as _Site302,
                             WebsiteDomain as _Dom302, WebsiteProxy as _Proxy302, db as _db302)
from panel.ops.ssh_manager import websites as _sw302
from panel.services import websites as _ws302
from panel.services import websites_proxy as _wp302

_HSPEC302 = _ilu302.spec_from_loader("panel_helper_p302", _mach302.SourceFileLoader(
    "panel_helper_p302", os.path.join(_root, "tools", "panel-helper")))
_H302 = _ilu302.module_from_spec(_HSPEC302)
_HSPEC302.loader.exec_module(_H302)
_H302.NSSWITCH_FILE = os.path.join(_root, "tests", "no-such-nsswitch.conf")

_TOKEN302 = "p" * 40
_UNIT302 = "lgsm-web-proxy.service"
# Documentation addresses only (RFC 5737, RFC 3849), and made-up tailnet ones.
_IPJ302 = _json302.dumps([
    {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "scope": "host"}, {"local": "::1", "scope": "host"}]},
    {"ifname": "ens3", "addr_info": [{"local": "203.0.113.7", "scope": "global"},
                                     {"local": "2001:db8::7", "scope": "global"},
                                     {"local": "2001:db8::beef", "scope": "global", "temporary": True},
                                     {"local": "fe80::7", "scope": "link"}]},
    {"ifname": "tailscale0", "addr_info": [{"local": "100.100.1.2", "scope": "global"},
                                           {"local": "fd7a:115c:a1e0::2", "scope": "global"}]}])
_IPJ_TAILNET_ONLY302 = _json302.dumps([
    {"ifname": "lo", "addr_info": [{"local": "127.0.0.1", "scope": "host"}]},
    {"ifname": "tailscale0", "addr_info": [{"local": "100.100.1.2", "scope": "global"}]}])
_TAILSCALED302 = ('LISTEN 0 4096 100.100.1.2%tailscale0:443 0.0.0.0:* users:(("tailscaled",pid=809,fd=27))\n'
                  'LISTEN 0 4096 [fd7a:115c:a1e0::2]%tailscale0:443 [::]:* users:(("tailscaled",pid=809,fd=28))\n')
_RUNNING302 = "ActiveState=active\nSubState=running\nNRestarts=0\n"
_LOOPING302 = "ActiveState=activating\nSubState=auto-restart\nNRestarts=3\n"
_BUSY_JSON302 = ('{"level":"error","ts":1.5,"msg":"loading new config: http app module: start: listening on :443: '
                 'listen tcp :443: bind: address already in use"}')
_OLD_CONF302 = _H302.WEB_CONF_HEAD + ": the previous one\n{\n\tadmin off\n}\n"


# ── the helper's stand-ins ──────────────────────────────────────────────────────────────────────
class _Pw302:
    def __init__(self, names):
        self.names = names

    def getpwnam(self, name):
        if name not in self.names:
            raise KeyError(name)
        return _NS302(pw_name=name, pw_uid=self.names[name], pw_gid=self.names[name], pw_dir="/home/" + name)


class _Sub302:
    """The helper's subprocess: answers each tool from `host` (a dict) and records every argv."""
    TimeoutExpired = __import__("subprocess").TimeoutExpired

    def __init__(self, host):
        self.host, self.calls = host, []

    def _answer(self, argv):
        tool = os.path.basename(argv[0])
        h = self.host
        if argv[0] == _H302.WEB_PROXY_BIN:
            return h.get("validate_rc", 0), "", h.get("validate_err", "")
        if tool == "systemctl" and argv[1:2] == ["show"]:
            states = h.setdefault("states", [_RUNNING302])
            return 0, states.pop(0) if len(states) > 1 else states[0], ""
        if tool == "curl" and "-o" in argv:
            with open(argv[argv.index("-o") + 1], "wb") as fh:
                fh.write(h.get("archive", b"not the release"))
            return 0, "", ""
        if tool == "openssl":
            return 0, "notAfter=%s\n" % h["enddates"][argv[-1]], ""
        if tool == "nft" and argv[1:3] == ["list", "tables"]:
            return 0, h.get("tables", ""), ""
        return 0, {"ip": h.get("ip", _IPJ302), "ss": h.get("ss", _TAILSCALED302),
                   "journalctl": h.get("journal", "")}.get(tool, ""), ""

    def run(self, argv, *_a, **_kw):
        self.calls.append(list(argv))
        rc, out, err = self._answer(argv)
        return _NS302(returncode=rc, stdout=out.encode(), stderr=err.encode())


_PATHS302 = {"WEB_PROXY_DIR": "lib", "WEB_PROXY_BIN": "lib/caddy", "WEB_PROXY_ETC": "etc", "WEB_PROXY_CONF": "etc/Caddyfile",
             "WEB_PROXY_CERTS": "etc/certs", "WEB_PROXY_STATE": "state", "WEB_PROXY_UNIT_FILE": "units/proxy.service",
             "WEB_JOURNAL_CONF": "units/journald.conf", "WEB_GUARD_FILE": "etc/egress-guard.nft",
             "WEB_GUARD_UNIT_FILE": "units/guard.service", "WEB_MARK_DIR": "marks"}


def _plain_write302(path, data, _mode, _uid=0, _gid=0):
    """_web_write without the owner change (that needs root; part299 holds the modes and owners)."""
    with open(path, "wb") as fh:
        fh.write(data)


def _tree302(d, installed, old_conf, made_dirs):
    """The helper's folders under `d`, its binary when `installed`, and the running file `old_conf`."""
    for n, rel in _PATHS302.items():
        setattr(_H302, n, os.path.join(d, rel))
    for sub_dir in (("units", "marks", "lib", "etc/certs", "state") if made_dirs else ("units", "marks")):
        os.makedirs(os.path.join(d, sub_dir), exist_ok=True)
    if installed:
        open(_H302.WEB_PROXY_BIN, "wb").close()
    if old_conf is not None and made_dirs:
        with open(_H302.WEB_PROXY_CONF, "w", encoding="utf-8") as fh:
            fh.write(old_conf)


def _run302(fn, out):
    with _ctx302.redirect_stdout(out), _ctx302.redirect_stderr(_io302.StringIO()):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - a verb that goes further than it should is a result, not a crash
            return "raised %s" % type(e).__name__


def _conf302():
    if not os.path.isfile(_H302.WEB_PROXY_CONF):
        return None
    with open(_H302.WEB_PROXY_CONF, encoding="utf-8") as fh:
        return fh.read()


def _helper302(fn, host, installed=True, old_conf=_OLD_CONF302, made_dirs=True):
    """Run helper verb `fn` in a scratch tree: (rc, stdout, argvs, the Caddyfile after or None, the tree)."""
    d = _tf302.mkdtemp(prefix="wp1-p302-")
    names = tuple(_PATHS302) + ("pwd", "subprocess", "resolve", "_web_write", "_web_pid_uid", "_web_arch",
                                "WEB_START_POLL")
    saved = {n: getattr(_H302, n) for n in names}
    sub, out = _Sub302(host), _io302.StringIO()
    try:
        _tree302(d, installed, old_conf, made_dirs)
        _H302.pwd, _H302.subprocess = _Pw302(host.get("pw", {"lgsmweb": 990})), sub
        _H302.resolve, _H302._web_write = (lambda prog: "/usr/bin/" + prog), _plain_write302
        _H302._web_pid_uid = lambda pid: 990 if pid == "4242" else 0
        _H302._web_arch, _H302.WEB_START_POLL = (lambda: "amd64"), 0
        rc = _run302(fn, out)
        tree = sorted(os.path.relpath(os.path.join(t, x), d) for t, dirs, files in os.walk(d) for x in dirs + files)
        return rc, out.getvalue(), sub.calls, _conf302(), tree
    finally:
        for n, v in saved.items():
            setattr(_H302, n, v)
        _shutil302.rmtree(d, ignore_errors=True)


def _dom302(name, did=1):
    return _NS302(domain=name, is_primary=True, id=did, verified_at=_dt302(2026, 1, 1), cert_mode="acme",
                  own_cert_pem="", own_key_secret="")


def _site302(**kw):
    base = dict(id=5, name="blog", kind="static", account="ws5", port=20005, enabled=True, proxy_secret="enc",
                domains=[_dom302("blog.example.org")], max_body_mb=64, static_cache=True, custom_rules="[]",
                page_cache=False, page_cache_ttl=300, access_log=False, raw_proxy_snippet="", opcache=True,
                php_settings="{}", php_ini_custom="")
    base.update(kw)
    return _NS302(**base)


def _proxy302(mode="public", provider=""):
    return _NS302(exposure_mode=mode, cidrs=lambda: [], presets=lambda: [], origin_pull_mtls=False,
                  tunnel_provider=provider)


def _doc302(proxy=None):
    text = _wp302.render([_site302()], proxy, None, secret_of=lambda s: _TOKEN302)
    return _sw302.apply_doc(text, [_site302()], proxy)


def _systemctl302(calls):
    """The systemctl verbs a helper run used, without its state reads."""
    return [c[1:] for c in calls if os.path.basename(c[0]) == "systemctl" and c[1:2] != ["show"]]


def _panel_says302(out):
    """What ssh_manager.websites.proxy_apply answers for the helper's refusal `out` (its _helper a stand-in)."""
    saved = _sw302._helper
    _sw302._helper = lambda *a, **k: (False, out)
    try:
        return _sw302.proxy_apply(None, "# text", (), None, True)
    finally:
        _sw302._helper = saved


# ── 1. where the proxy listens ──────────────────────────────────────────────────────────────────
def _s1_bind():
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["start"], _doc302()), {})
    eq("website-proxy-apply (verb): the proxy listens on the host's own addresses only: never the tailnet's "
       "(Tailscale Serve holds its 443), the loopback, a link-local or a temporary one",
       (rc, [ln for ln in (conf or "").split("\n") if "default_bind" in ln], "applied=yes" in out.split("\n")),
       (0, ["\tdefault_bind 203.0.113.7 [2001:db8::7]"], True))
    tunnel = _proxy302("tunnel", "cloudflare")
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["start"], _doc302(tunnel)), {})
    eq("website-proxy-apply (verb): a tunnel's configuration keeps its own loopback bind, and its port is the one "
       "checked (control)",
       (rc, [ln for ln in (conf or "").split("\n") if "default_bind" in ln], any(c[0].endswith("/ip") for c in calls)),
       (0, ["\tdefault_bind 127.0.0.1"], False))


def _s1_refusals():
    busy = _TAILSCALED302 + 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=77,fd=6))\n'
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["start"], _doc302()), {"ss": busy})
    said = _panel_says302(out)
    eq("website-proxy-apply (verb + ssh layer): another program on 443 of a bind address is refused first, naming "
       "it in plain words; nothing is validated, swapped or restarted",
       (rc, [ln for ln in out.split("\n") if ln.startswith("busy=")], conf == _OLD_CONF302, _systemctl302(calls),
        said),
       (1, ["busy=443 0.0.0.0 nginx"], True, [],
        (False, "Port 443 on 0.0.0.0 is already used by nginx, so the web proxy cannot listen there. Nothing was "
                "changed.")))
    own = _TAILSCALED302 + 'LISTEN 0 4096 203.0.113.7:443 0.0.0.0:* users:(("caddy",pid=4242,fd=9))\n'
    rc, out, _c, _conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["reload"], _doc302()), {"ss": own})
    eq("website-proxy-apply (verb): the running proxy's own listeners are not a collision (control)", rc, 0)
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["start"], _doc302()),
                                          {"ip": _IPJ_TAILNET_ONLY302})
    eq("website-proxy-apply (verb + ssh layer): a host with no address outside its loopback and tailnet is refused "
       "in words, never a proxy that binds everything",
       (rc, "bind=none" in out.split("\n"), conf == _OLD_CONF302, _systemctl302(calls), _panel_says302(out)),
       (1, True, True, [], (False, _sw302.NO_BIND)))


# ── 2. starting it ──────────────────────────────────────────────────────────────────────────────
def _s2_start():
    for arg in ("start", "reload"):
        rc, out, calls, _conf, _t = _helper302(lambda: _H302.do_website_proxy_apply([arg], _doc302()), {})
        eq("website-proxy-apply %s (verb): the proxy is enabled AND restarted, so a running proxy loads the new file "
           "and one left running comes back after a reboot" % arg,
           (rc, _systemctl302(calls)), (0, [["enable", _UNIT302], ["restart", _UNIT302]]))
    host = {"states": [_LOOPING302], "journal": "starting\n" + _BUSY_JSON302 + "\n"}
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["start"], _doc302()), host)
    said = _panel_says302(out)
    eq("website-proxy-apply (verb + ssh layer): a proxy left restarting (auto-restart) is a failure: the previous "
       "file is put back, the proxy is stopped and disabled, and the journal's error is said in plain words",
       (rc, "applied=yes" in out, conf == _OLD_CONF302, _systemctl302(calls)[-1], said, "{" in said[1]),
       (1, False, True, ["disable", "--now", _UNIT302],
        (False, "The web proxy did not start with the new configuration, so the previous one was put back: another "
                "program already listens on :443"), False))
    host = {"states": [_RUNNING302, _RUNNING302, _LOOPING302]}   # before the restart, one read after, then dying
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["reload"], _doc302()), host)
    eq("website-proxy-apply (verb): one running read is not enough: a proxy that dies right after is a failure, and "
       "the running proxy gets its previous file back with a restart",
       (rc, conf == _OLD_CONF302, _systemctl302(calls)[-1]), (1, True, ["restart", _UNIT302]))


def _s2_plain_errors():
    host = {"validate_rc": 1, "validate_err": '{"level":"error","ts":1.5,"msg":"adapting config using caddyfile: '
                                              '/etc/lgsm-web-proxy/Caddyfile.candidate:72: unrecognized directive: '
                                              'respond_bogus"}\n'}
    rc, out, calls, conf, _t = _helper302(lambda: _H302.do_website_proxy_apply(["start"], _doc302()), host)
    eq("website-proxy-apply (verb): a refused configuration's error is printed in plain words (the message, a line "
       "number), never Caddy's JSON record or its file path; the running file is kept",
       (rc, [ln for ln in out.split("\n") if ln.startswith("error=")], conf == _OLD_CONF302),
       (1, ["error=line 72: unrecognized directive: respond_bogus"], True))
    log, logged = _sw302._core._log, []
    handler = _logging302.Handler()
    handler.emit = lambda record: logged.append(record.getMessage())
    log.addHandler(handler)
    try:
        said = _panel_says302("valid=no\nerror=" + _BUSY_JSON302.replace("loading new config: ", ""))
    finally:
        log.removeHandler(handler)
    eq("proxy apply (ssh layer): an older helper's raw JSON line becomes its message for the page, and the whole "
       "line goes to the panel's log only",
       ("{" in said[1], said[1].startswith("The web proxy refused the new configuration"),
        any('"level":"error"' in m for m in logged)), (False, True, True))


for _step302 in (_s1_bind, _s1_refusals, _s2_start, _s2_plain_errors):
    _step302()
