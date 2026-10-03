"""Part 32 of the unit suite: the panel publishes itself over Tailscale Serve at ONE mount (ws2-serve).

A live debug report showed Serve with two routes to the panel: "/" on http (a 502: the panel
serves TLS) and the configured /lgsm on https+insecure. Each check here fails on the code before
the fix:
  * the boot re-point wrote only tailscale_mount and said "ok"; nothing re-pointed or removed a
    panel route at any other mount, so it 502'd from the next flip of the panel's scheme. Boot now
    removes the panel's own :443 routes at other mounts (Serve re-read right before each `off`,
    always with --set-path, nothing when Serve is unreadable), records that apart from BOOT_SERVE,
    and re-points on the scheme the process REALLY serves (BOOT_TLS);
  * the setup wizard published the panel twice: the finish read the Serve step's own "/" (or a
    README route to the panel's port) as another app's and added /lgsm beside it, on the scheme the
    NEXT start serves; and the Serve step published at "/" over another app's route;
  * Enable at a new mount left the old route; Disable removed one route and cleared the mount; and
    nothing could remove a leftover alone;
  * the banner, the setup-complete link, the wizard's status and Recommended Access named the root
    or the first route listed — on that host, the 502;
  * the debug report said "a route has the wrong scheme" with no word on which or what to do, and
    nothing for a leftover whose scheme happened to match;
  * uninstall.sh ran `tailscale serve --bg --remove <mount>`, which exits 2 on every Tailscale;
  * install.sh printed "This panel now serves HTTPS. Open it at https://<public ip>:5000" after
    EVERY update of a panel serving its own TLS, firewalled or behind Serve;
  * README's `tailscale serve --bg --https 443 http://127.0.0.1:5000` 502s on the default panel.

And, from the review of that fix: a "/lgsm/" twin of the configured "/lgsm" read as the managed
route (Serve answers /lgsm/* from the twin first), so nothing removed it; Remove never made the
panel the Tailscale operator, so on a host where it was not one the route listed and its `off` was
refused; Enable or Remove that took down the route the page came through left the page refreshing
into Serve's 404; the report called "no route reaches the panel at all" a warn; and the uninstall's
re-read before each `off`, and when the report may say "a panel restart also removes it", had no
check that failed without them.

The VPS proof of that fix found the fake stored both "/lgsm" and "/lgsm/" where the real CLI cannot:
every Serve write drops the mount that differs from the one written by a trailing "/" (Tailscale's
SetWebHandler), so the boot check tested a state no write leaves. The fake now writes as the CLI
does, and the twin checks seed a twin the one way it can exist, `tailscale serve set-raw`: the boot's
own write replaces it, and the report and the Tailscale page, which only read Serve, name it.

HOW IT RUNS. A stateful fake `tailscale` (tests/unit/fake_tailscale.py; its overwrite and `off`
semantics are the real CLI's) is put FIRST on PATH for the whole part, so the panel's code reaches
it through tailscale_integration._run_ts, and the scripts through `timeout tailscale`, exactly as
they would the real binary — nothing here reaches this machine's own tailscale. ensure_operator,
allow_tailscale_ufw and system_ops._run_verb (the root fallback) are replaced for the part; the
last records what reached it, and a check reads that. The stand-in ensure_operator ends as the real
one does, with this account the operator (the fake's `set --operator=`), so a host seeded as one
where it is not yet the operator refuses every change until something calls it. Routes run through part12's Flask app as its
signed-in superadmin, on part12's throwaway config.json. The shell parts run as `bash -c` over the
functions and regions lifted out of the scripts, in a scratch directory. All is put back at the end.
"""
import json
import os
import re
import shutil
import subprocess  # nosec B404 - bash over the scripts' own text, in a scratch dir
import sys
import tempfile

from unit.part01 import check
from unit.part12 import P9_ADMIN, _P9_CFG_PATH, _p9, _p9_audit, _p9_client, _p9_json
import app as _app32
from panel.core import config as _cfg32
from panel.core.middleware import PrefixMiddleware as _Prefix32
from panel.ops import serve_upkeep as _su32
from panel.ops import tailscale_integration as ts
from panel.ops.debug_report import network as _nw32
from panel.ops.debug_report import process as _pr32
from panel.ops.debug_report._base import Ctx as _Ctx32, Result as _Result32
from panel.routes import route_helpers as _rh32
from panel.security import privileged as _priv32

_ROOT32 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMP32 = tempfile.mkdtemp(prefix="lgsm-unit-p32-")
_BIN32 = os.path.join(_TMP32, "bin")
_STATE32 = os.path.join(_TMP32, "ts-state.json")
_LOG32 = os.path.join(_TMP32, "ts-calls.jsonl")
_FAKE32 = os.path.join(_ROOT32, "tests", "unit", "fake_tailscale.py")
_HOST32 = "https://fakehost.tail0000.ts.net"
_P = "http://127.0.0.1:5000"
_PS = "https+insecure://127.0.0.1:5000"
_OTHER = "http://127.0.0.1:9180"
_ALL_IFACES = ".".join(["0"] * 4)    # the stored bind the wizard and the live host have
_LIVE = {"443": {"/": _P, "/lgsm": _PS}}
_LIVE_CFG = {"tailscale_setup_done": True, "tailscale_mount": "/lgsm", "bind_host": _ALL_IFACES,
             "use_https": True}

_SAVED32 = []
_ENV_KEYS32 = ("PATH", "FAKE_TS_STATE", "FAKE_TS_LOG", "FAKE_TS_SERVE_UNREADABLE",
               "FAKE_TS_OFF_FAIL", "FAKE_TS_WRITE_FAIL")
_ENV_SAVED32 = {k: os.environ.get(k) for k in _ENV_KEYS32}
_CFG_SNAPSHOT32 = _P9_CFG_PATH.read_bytes() if _P9_CFG_PATH.exists() else None
_CONF_KEYS32 = ("BOOT_TLS", "BOOT_TLS_ERROR", "BOOT_SERVE", "BOOT_SERVE_LEFTOVERS", "BOOT_BIND",
                "BOOT_PORT")
_CONF_SAVED32 = {k: _p9.config[k] for k in _CONF_KEYS32 if k in _p9.config}
_VERBS32 = []


def _patch32(owner, name, value):
    _SAVED32.append((owner, name, getattr(owner, name)))
    setattr(owner, name, value)


def _restore32():
    while _SAVED32:
        owner, name, value = _SAVED32.pop()
        setattr(owner, name, value)


def _seed(web, funnel=(), http=(), **extra):
    """Serve as the fake CLI will report it, an empty call log, and no cached reading.

    `extra` goes into the fake's state as it is: operator_required=True is a host where this
    account is not yet the Tailscale operator (it reads Serve, and may not change it).
    """
    with open(_STATE32, "w", encoding="utf-8") as fh:
        json.dump(dict({"web": web, "funnel": list(funnel), "http": list(http)}, **extra), fh)
    open(_LOG32, "w", encoding="utf-8").close()
    ts._cache["info"] = None


def _ts_cli(args, stdin=""):
    """Run the fake `tailscale` directly, as a script would, with `stdin`; -> its exit code."""
    r = subprocess.run([os.path.join(_BIN32, "tailscale")] + list(args),  # nosec B603 - the fake this part wrote
                       input=stdin, capture_output=True, text=True, timeout=60, check=False)
    return r.returncode


def _raw_config(web):
    """`web` ({listener: {mount: backend}}) as the ipn.ServeConfig JSON `serve set-raw` reads."""
    host = _HOST32.split("://", 1)[1]
    return {"TCP": {p: {"HTTPS": True} for p in web},
            "Web": {"%s:%s" % (host, p): {"Handlers": {m: {"Proxy": b} for m, b in h.items()}}
                    for p, h in web.items()}}


def _seed_raw(web):
    """Serve as only `tailscale serve set-raw` can leave it; -> set-raw's exit code.

    Every other write drops the mount that differs from the one written by a trailing "/"
    (Tailscale's SetWebHandler, and the fake's), so a "/lgsm/" twin beside "/lgsm" exists only in a
    config set raw — by hand, or by a tool that posts the whole config. Then an empty call log.
    """
    _seed({})
    rc = _ts_cli(["serve", "set-raw"], json.dumps(_raw_config(web)))
    open(_LOG32, "w", encoding="utf-8").close()
    ts._cache["info"] = None
    return rc


def _table():
    with open(_STATE32, encoding="utf-8") as fh:
        return {p: h for p, h in json.load(fh).get("web", {}).items() if h}


def _calls():
    with open(_LOG32, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _offs():
    return [c for c in _calls() if c[-1:] == ["off"]]


def _writes():
    return [c for c in _calls() if c[:1] in (["serve"], ["funnel"]) and c[-1:] != ["off"]
            and c[1:2] != ["status"]]


def _all_named(calls):
    """Every `off` in `calls` names its path, and none of them is a `reset`."""
    return all([any(a.startswith("--set-path=") for a in c) for c in calls]
               + [not any("reset" in c for c in _calls())])


class _Env32(object):
    """FAKE_TS_* switches for one block, taken away after it."""

    def __init__(self, **flags):
        self.flags = flags

    def __enter__(self):
        os.environ.update(self.flags)
        ts._cache["info"] = None
        return self

    def __exit__(self, *exc):
        for k in self.flags:
            os.environ.pop(k, None)
        ts._cache["info"] = None
        return False


def _save_cfg(**over):
    cfg = dict(_cfg32.DEFAULT_CONFIG, port=5000, setup_complete=True)
    cfg.update(over)
    _cfg32.save_config(cfg)
    return cfg


def _stored(*keys):
    cfg = _cfg32.load_config()
    return tuple(cfg.get(k) for k in keys)


def _panel_mounts():
    """{listener: [mounts]} of the routes that proxy the panel, from the fake's state."""
    out = {}
    for port, handlers in _table().items():
        mounts = sorted(m for m, b in handlers.items() if ts.route_targets_port(b, 5000))
        if mounts:
            out[port] = mounts
    return out


def _bash(script, args=(), env=None):
    full = dict(os.environ)
    full.update(env or {})
    return subprocess.run(["bash", "-c", script, "p32"] + list(args),  # nosec B603 B607 - see top
                          capture_output=True, text=True, env=full, cwd=_TMP32, timeout=120)


def _script_text(name):
    with open(os.path.join(_ROOT32, name), encoding="utf-8") as fh:
        return fh.read()


def _sh_fn(text, name):
    """One shell function of a script, verbatim (from its `name() {` line to its closing brace).

    A function that is not there comes back as a line that says so and fails, so every check that
    runs it fails BY NAME instead of the whole part raising at import.
    """
    i = text.find("\n%s() {" % name) + 1
    if i == 0:
        return '%s() { echo "MISSING FUNCTION %s"; return 1; }\n' % (name, name)
    return text[i:text.index("\n}\n", i) + 3]


def _region(text, start, end):
    """The text from `start` up to `end`, or a line that fails and says what is missing."""
    i, j = text.find(start), text.find(end)
    if i < 0 or j < i:
        return 'echo "MISSING REGION %s"; exit 1\n' % start.strip()
    return text[i:j]


def _code(text):
    """A script's text with comment-only lines dropped: gates read code, not the prose about it."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _code_js(text):
    """A script's text with comment-only `//` lines dropped."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("//"))


def _js_fn(text, name):
    """One top-level JS function's text, from `function name(` to the next top-level function."""
    i = text.find("function %s(" % name)
    if i < 0:
        return ""
    j = text.find("\nfunction ", i + 1)
    return text[i:j if j > 0 else len(text)]


def _not_refused(values):
    """The values off_mount ACCEPTS of `values` (it should refuse every one)."""
    out = []
    for v in values:
        try:
            ts.off_mount(v)
        except _priv32.VerbError:
            continue
        out.append(v)
    return out


def _set_conf(**conf):
    for k in _CONF_KEYS32:
        _p9.config.pop(k, None)
    _p9.config.update(conf)


def _finish():
    """The wizard's finish (_auto_tailscale_serve) on the stored config, as the finish runs it."""
    with _p9.test_request_context("/setup"):
        _rh32._auto_tailscale_serve(_cfg32.load_config())


def _exe(name, body):
    path = os.path.join(_BIN32, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/sh\n" + body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
    os.chmod(path, 0o700)


# ═══ 1. boot: the configured mount, then the panel's own routes at any other ════════════════════
def _boot(web, conf, funnel=(), **over):
    _seed(web, funnel=funnel)
    cfg = _save_cfg(**dict(_LIVE_CFG, **over))
    _set_conf(**conf)
    _app32._boot_serve(_p9, cfg, 5000)
    return _p9.config.get("BOOT_SERVE"), _p9.config.get("BOOT_SERVE_LEFTOVERS")


def _p32_boot_live():
    b = _boot(_LIVE, {"BOOT_TLS": True})
    check("boot: on the live host's table the panel's '/' leftover is removed, and only the "
          "configured /lgsm remains, on the scheme the process serves",
          (_table(), b) == ({"443": {"/lgsm": _PS}}, ("ok", "removed:/")), repr((b, _table())))
    check("boot: ...each removal names its path (--set-path), and nothing ran `reset` or a bare "
          "`off`", all([bool(_offs()), _all_named(_offs())]), repr(_offs()))
    row = _p9_audit("tailscale_serve_leftover_removed")
    check("boot: ...and the removal is on record",
          all([row.success is True, "at / on :443" in row.detail, row.detail.startswith("at boot")]),
          repr(row))


def _p32_boot_scope():
    b = _boot({"443": {"/": _OTHER, "/lgsm": _PS, "/old": _P}, "8447": {"/": _P}}, {"BOOT_TLS": True})
    check("boot: another app's '/' and a panel route on another listener (made by hand) survive; "
          "only the panel's :443 leftover goes",
          (_table(), b) == ({"443": {"/": _OTHER, "/lgsm": _PS}, "8447": {"/": _P}},
                            ("ok", "removed:/old")), repr((b, _table())))
    b = _boot({"443": {"/lgsm": _PS, "/old/": _P}}, {"BOOT_TLS": True})
    check("boot: a leftover whose mount ends in '/' is removed under that exact path",
          (_table(), b) == ({"443": {"/lgsm": _PS}}, ("ok", "removed:/old/")),
          repr((b, _table(), _offs())))
    b = _boot(_LIVE, {"BOOT_TLS": True}, tailscale_setup_done=False)
    check("boot: with Serve not set up nothing is written or removed (the panel does not manage it)",
          (b, _calls()) == (("not attempted", "not attempted"), []), repr((b, _calls())))


def _p32_fake_writes():
    """The fake writes as the real CLI does: no write but `set-raw` leaves "/x" beside "/x/"."""
    _seed({"443": {"/": _OTHER, "/lgsm": _PS}})
    got = []
    for path in ("/lgsm/", "/lgsm"):
        rc = _ts_cli(["serve", "--bg", "--https=443", "--set-path=" + path, _P])
        got.append((rc, sorted(_table().get("443", {}))))
    check("fake tailscale: a write at '/lgsm/' replaces '/lgsm' and one at '/lgsm' replaces "
          "'/lgsm/', as the real CLI did on the test VPS (1.102.4: ['/', '/lgsm'] -> ['/', "
          "'/lgsm/'] -> ['/', '/lgsm']); another app's '/' is left alone",
          got == [(0, ["/", "/lgsm/"]), (0, ["/", "/lgsm"])], repr(got))
    rc = _seed_raw({"443": {"/lgsm": _PS, "/lgsm/": _P}})
    check("fake tailscale: ...and `serve set-raw` stores a config as given, the one write that can "
          "leave both spellings", (rc, _table()) == (0, {"443": {"/lgsm": _PS, "/lgsm/": _P}}),
          repr((rc, _table())))


def _p32_boot_twin():
    # Serve keeps "/lgsm/" apart from "/lgsm" and answers every /lgsm/* request from "/lgsm/" FIRST
    # (ipnlocal getServeHandler tries pth+"/" before pth). But no Serve WRITE leaves the two side by
    # side: SetWebHandler drops the other spelling (the VPS proof of #393 measured it). Only a config
    # set with `serve set-raw` holds a twin, and the boot's own write of /lgsm then replaces it.
    rc = _seed_raw({"443": {"/lgsm": _PS, "/lgsm/": _P}})
    cfg = _save_cfg(**_LIVE_CFG)
    _set_conf(BOOT_TLS=True)
    _app32._boot_serve(_p9, cfg, 5000)
    b = (_p9.config.get("BOOT_SERVE"), _p9.config.get("BOOT_SERVE_LEFTOVERS"))
    check("boot: a '/lgsm/' twin of the configured /lgsm (only `serve set-raw` leaves one) is "
          "replaced by the boot's own write of /lgsm, as Tailscale replaces it: the panel answers "
          "at /lgsm on the scheme it serves, nothing is left to remove, and no `off` runs",
          (rc, _table(), b, _offs()) == (0, {"443": {"/lgsm": _PS}}, ("ok", "none"), []),
          repr((rc, b, _table(), _calls())))
    _seed_raw({"443": {"/lgsm": _PS, "/lgsm/": _P}})
    stale = [r["mount"] for r in ts.stale_panel_routes(
        ts.get_tailscale_info(force_refresh=True).serve_config, 5000, "/lgsm")]
    check("stale routes: in a config set raw with a '/lgsm/' twin, the twin is stale and /lgsm is "
          "not — exact, as the panel writes it (the removal after a write meets a twin only if "
          "set-raw ran in between)", stale == ["/lgsm/"], repr(stale))
    check("managed route: the exact spelling the panel writes, nothing else (control: '/' and an "
          "unwritable stored mount)",
          (ts.is_managed_route({"url": _HOST32, "mount": "/lgsm"}, _LIVE_CFG),
           ts.is_managed_route({"url": _HOST32, "mount": "/lgsm/"}, _LIVE_CFG),
           ts.is_managed_route({"url": _HOST32, "mount": "/"},
                               dict(_LIVE_CFG, tailscale_mount="")),
           ts.is_managed_route({"url": _HOST32, "mount": "/lgsm/"},
                               dict(_LIVE_CFG, tailscale_mount="/lgsm/")))
          == (True, False, True, False), "")


def _p32_boot_failures():
    with _Env32(FAKE_TS_SERVE_UNREADABLE="1"):
        b = _boot(_LIVE, {"BOOT_TLS": True})
    check("boot: with Serve's status unreadable nothing is removed, and the outcome says 'unread' "
          "(an unread table is not an empty one)",
          (b, _offs(), _table()) == (("ok", "unread"), [], _LIVE), repr((b, _table())))
    with _Env32(FAKE_TS_OFF_FAIL="1"):
        b = _boot(_LIVE, {"BOOT_TLS": True})
    row = _p9_audit("tailscale_serve_leftover_removed")
    check("boot: an `off` the CLI refuses is recorded as failed, with its class, and audited — not "
          "swallowed", (b, row.success, _table()) == (("ok", "failed:permission"), False, _LIVE),
          repr((b, row)))
    with _Env32(FAKE_TS_WRITE_FAIL="1"):
        b = _boot(_LIVE, {"BOOT_TLS": True})
    check("boot: when the configured mapping itself could not be written, no other route is touched",
          (str(b[0])[:7], b[1], _offs(), _table()) == ("failed:", "not attempted", [], _LIVE),
          repr((b, _table())))
    # A refused write goes on to the root fallback (setup_tailscale_serve's own design); that one
    # is expected here, and the check at the end is about every OTHER path.
    del _VERBS32[:]
    b = _boot({"443": {"/lgsm": _PS}}, {"BOOT_TLS": False, "BOOT_TLS_ERROR": "OSError"})
    check("boot: a TLS start that FAILED re-points Serve at http, the scheme really served (the "
          "stored config still says https)", (_table(), b[0]) == ({"443": {"/lgsm": _P}}, "ok"),
          repr((b, _table())))


def _p32_reread():
    # The re-read right before each `off`: another app takes "/" after the first read.
    _seed(_LIVE)
    real, reads = ts.get_tailscale_info, []

    def takeover(force_refresh=False):
        reads.append(force_refresh)
        if len(reads) == 2:
            with open(_STATE32, "w", encoding="utf-8") as fh:
                json.dump({"web": {"443": {"/": _OTHER, "/lgsm": _PS}}}, fh)
        return real(force_refresh=force_refresh)
    ts.get_tailscale_info = takeover
    try:
        rs = ts.remove_stale_panel_routes(5000, "/lgsm")
    finally:
        ts.get_tailscale_info = real
    check("removal re-reads Serve right before each `off`: a mount another app took after the first "
          "read is left alone", (rs, _table()["443"].get("/"), _offs(), len(reads))
          == (("none", [], ""), _OTHER, [], 2), repr((rs, _table(), reads)))
    check("off_mount keeps a trailing '/' exactly (Tailscale stores '/x/' apart from '/x'), and "
          "still refuses an option-shaped, doubled or spaced path",
          (ts.off_mount("/old/"), ts.off_mount("/"), _not_refused(("-x", "//", "/a//", "/x y", "")))
          == ("/old/", "/", []), repr(_not_refused(("-x", "//", "/a//", "/x y", ""))))


def _p32_free_mount():
    other_root = {"url": _HOST32, "routes": [{"mount": "/", "target": _OTHER}]}
    other_8443 = {"url": _HOST32 + ":8443", "routes": [{"mount": "/lgsm", "target": _OTHER}]}
    own_root = {"url": _HOST32, "routes": [{"mount": "/", "target": _P}]}
    both = {"url": _HOST32, "routes": [{"mount": "/", "target": _OTHER},
                                       {"mount": "/lgsm", "target": _OTHER}]}
    got = tuple(ts.free_panel_mount({"services": s}, 5000, "/")
                for s in ([other_root, other_8443], [other_8443], [own_root], [both]))
    check("free_panel_mount: another app's '/' on :443 moves the panel to /lgsm; another listener "
          "does not count; the panel's own '/' is free; both taken is None",
          got == ("/lgsm", "/", "/", None), repr(got))


# ═══ 2. the setup wizard ═════════════════════════════════════════════════════════════════════════
def _wizard_cfg(**over):
    return _save_cfg(**dict(dict(setup_complete=False, tailscale_setup_done=False,
                                 tailscale_mount="/", bind_host=_ALL_IFACES), **over))


def _p32_wizard_walk():
    _set_conf(BOOT_TLS=True)
    _seed({})
    _wizard_cfg()
    r = _A32.post("/api/setup/tailscale/serve")
    _finish()
    check("wizard: the Serve step then the finish leave ONE route to the panel, at the configured "
          "mount", (r.status_code, _p9_json(r).get("success"), _panel_mounts(),
                    _stored("tailscale_mount", "tailscale_setup_done"))
          == (200, True, {"443": ["/"]}, ("/", True)),
          repr((r.status_code, _p9_json(r), _table())))
    check("wizard: ...and the finish writes nothing more once the Serve step has published",
          len(_writes()) == 1, repr(_writes()))
    r = _A32.post("/api/setup/tailscale/serve")
    check("wizard: a Serve step POSTed again (after it stored the loopback bind the NEXT start "
          "uses) still writes the scheme this process serves",
          (r.status_code, _table()) == (200, {"443": {"/": _PS}}), repr(_table()))


def _p32_wizard_adopt():
    _seed({"443": {"/": _P}})
    _wizard_cfg()
    _finish()
    check("wizard: a '/' that already proxies the panel (the README's command) is the panel's own: "
          "the finish adopts it — ONE route, at the configured mount, on the served scheme",
          (_table(), _stored("tailscale_mount")) == ({"443": {"/": _PS}}, ("/",)),
          repr((_table(), _stored("tailscale_mount"))))
    _seed({"443": {"/": _OTHER}})
    _wizard_cfg()
    _finish()
    check("wizard: with ANOTHER app at '/', the finish publishes at /lgsm and leaves that app alone",
          (_table(), _stored("tailscale_mount")) == ({"443": {"/": _OTHER, "/lgsm": _PS}}, ("/lgsm",)),
          repr(_table()))
    _seed({"443": {"/": _OTHER}})
    _wizard_cfg()
    r = _A32.post("/api/setup/tailscale/serve")
    check("wizard: ...and so does its Serve step: never over another app's '/' (the CLI replaces a "
          "mount without asking)",
          (_table(), _stored("tailscale_mount")) == ({"443": {"/": _OTHER, "/lgsm": _PS}}, ("/lgsm",)),
          repr((_table(), _p9_json(r))))


def _p32_wizard_unread():
    _seed({"443": {"/": _OTHER}})
    _wizard_cfg()
    with _Env32(FAKE_TS_SERVE_UNREADABLE="1"):
        r = _A32.post("/api/setup/tailscale/serve")
    check("wizard: with Serve's status unreadable the Serve step publishes nothing — it cannot tell "
          "whose '/' it would replace",
          (_p9_json(r).get("success"), _writes(), _table(), _stored("tailscale_setup_done"))
          == (False, [], {"443": {"/": _OTHER}}, (False,)), repr((_p9_json(r), _writes())))
    _seed({"443": {"/": _OTHER}})
    _wizard_cfg()
    s1 = _p9_json(_A32.get("/api/setup/tailscale/status"))
    _seed({"443": {"/": _OTHER, "/lgsm": _PS}})
    _wizard_cfg(tailscale_setup_done=True, tailscale_mount="/lgsm")
    s2 = _p9_json(_A32.get("/api/setup/tailscale/status"))
    check("wizard status: another app's route is not the panel being served; the panel's own route "
          "is named with its mount",
          (s1.get("serve_url"), s1.get("https_url"), s2.get("serve_url"), s2.get("https_url"))
          == (None, None, _HOST32 + "/lgsm", _HOST32 + "/lgsm"), repr((s1, s2)))


# ═══ 3. the Tailscale page: Enable, Disable, Remove, and what it links to ════════════════════════
def _serve_api(**body):
    return _A32.post("/api/tailscale/serve", json=body)


def _p32_enable():
    _set_conf(BOOT_TLS=True)
    _seed({"443": {"/": _PS, "/x": _OTHER}})
    _save_cfg(tailscale_setup_done=True, tailscale_mount="/", bind_host=_ALL_IFACES)
    r = _serve_api(action="enable", mount="/lgsm")
    check("Enable at a new mount takes the panel's route at the old one down: ONE route, another "
          "app's untouched", (r.status_code, _table(), _stored("tailscale_mount"))
          == (200, {"443": {"/lgsm": _PS, "/x": _OTHER}}, ("/lgsm",)), repr((_p9_json(r), _table())))
    check("Enable: ...says so, and the removal is on record",
          all(["old route at / was removed" in (_p9_json(r).get("message") or ""),
               "Enable on the Tailscale page" in _p9_audit("tailscale_serve_leftover_removed").detail]),
          repr(_p9_json(r)))
    _seed({"443": {"/lgsm": _PS}})
    _save_cfg(tailscale_setup_done=True, tailscale_mount="/lgsm", bind_host="127.0.0.1")
    _serve_api(action="enable", mount="/lgsm")
    check("Enable while a loopback bind waits for a restart writes the scheme this process serves, "
          "not the next start's", _table() == {"443": {"/lgsm": _PS}}, repr(_table()))


def _p32_page():
    _seed(_LIVE)
    _save_cfg(**_LIVE_CFG)
    html = _A32.get("/tailscale").get_data(as_text=True)
    removes = re.findall(r'data-action="removeServeRoute"\s+data-args=\'\["@self"\]\'\s+'
                         r'data-mount="([^"]*)"', html)
    check("tailscale page: the route to the panel it does not manage (the leftover '/') has its own "
          "Remove, and the configured /lgsm has none", removes == ["/"], repr(removes))
    check("tailscale page: Recommended Access links the panel's configured route (/lgsm), not the "
          "first route listed", (('href="%s/lgsm"' % _HOST32) in html, ('href="%s"' % _HOST32) in html)
          == (True, False), repr(re.findall(r'href="https://[^"]*"', html)))


def _p32_remove_route():
    _seed(_LIVE)
    _save_cfg(**_LIVE_CFG)
    r = _serve_api(action="remove-route", mount="/", url=_HOST32)
    check("Remove on a leftover takes down that route alone; the panel's mount and Serve setting "
          "stay, so the page in use keeps its prefix",
          (r.status_code, _table(), _stored("tailscale_mount", "tailscale_setup_done"))
          == (200, {"443": {"/lgsm": _PS}}, ("/lgsm", True)), repr((_p9_json(r), _table())))
    _seed(_LIVE)
    r = _serve_api(action="remove-route", mount="/lgsm", url=_HOST32)
    check("Remove refuses the panel's own configured route (Disable is for that) and runs nothing",
          (r.status_code, _table(), _offs()) == (400, _LIVE, []), repr(_p9_json(r)))
    _seed({"443": {"/": _OTHER, "/lgsm": _PS}})
    r = _serve_api(action="remove-route", mount="/", url=_HOST32)
    check("Remove refuses another app's route: only a route to the panel's port is ever removed",
          (r.status_code, _table()) == (404, {"443": {"/": _OTHER, "/lgsm": _PS}}), repr(_p9_json(r)))
    _seed({"443": {"/": _P}})
    _save_cfg(tailscale_setup_done=False, tailscale_mount="", bind_host="127.0.0.1")
    r = _serve_api(action="remove-route", mount="/", url=_HOST32)
    check("Remove refuses the LAST route to a panel bound to localhost (it is the only way in), "
          "as Disable does", (r.status_code, _table(), _ALL_IFACES in (_p9_json(r).get("message") or ""))
          == (400, {"443": {"/": _P}}, True), repr(_p9_json(r)))


def _p32_remove_operator():
    _seed({"443": {"/lgsm": _PS}}, operator_required=True)
    denied = ts._run_ts(["serve", "--https=443", "--set-path=/lgsm", "off"], timeout=10)[2]
    readable = not ts.get_tailscale_info(force_refresh=True).serve_unreadable
    check("p32 harness: a host where this account is not the operator READS Serve and may not change "
          "it (Tailscale's own split, which the fake models)", (denied, readable, _table())
          == (1, True, {"443": {"/lgsm": _PS}}), repr((denied, readable)))
    _seed(_LIVE, operator_required=True)
    _save_cfg(**_LIVE_CFG)
    r = _serve_api(action="remove-route", mount="/", url=_HOST32)
    check("Remove makes the panel the Tailscale operator first, as Enable and Disable do: a host "
          "that lists the route (reading needs no privilege) can also remove it",
          (r.status_code, _table(), ["set", "--operator=p32"] in _calls())
          == (200, {"443": {"/lgsm": _PS}}, True), repr((_p9_json(r), _calls())))


def _p32_page_follows():
    # part12's app is not create_app's, so nothing sets the script root a page's links are built
    # for. These requests go through the real PrefixMiddleware, wrapped as create_app wraps it.
    real = _p9.wsgi_app
    _p9.wsgi_app = _Prefix32(real)
    try:
        _page_follows_checks()
    finally:
        _p9.wsgi_app = real


def _page_follows_checks():
    _set_conf(BOOT_TLS=True)
    gone = []
    for page in (_HOST32 + "/tailscale", "https://100.64.0.9:5000/tailscale"):
        _seed({"443": {"/": _PS}})
        _save_cfg(tailscale_setup_done=False, tailscale_mount="", bind_host=_ALL_IFACES)
        r = _serve_api(action="enable", mount="/lgsm", page=page)
        gone.append((r.status_code, _p9_json(r).get("go", "absent"), _table()))
    check("Enable at a new mount, from a page that came through the route it took down, answers the "
          "panel's new address to go to; a page reached another way (the tailnet IP) stays",
          gone == [(200, _HOST32 + "/lgsm/tailscale", {"443": {"/lgsm": _PS}}),
                   (200, "absent", {"443": {"/lgsm": _PS}})], repr(gone))
    gone = []
    for page in (_HOST32 + "/tailscale", _HOST32 + "/lgsm/tailscale", "http://[x"):
        _seed(_LIVE)
        _save_cfg(**_LIVE_CFG)
        r = _serve_api(action="remove-route", mount="/", url=_HOST32, page=page)
        gone.append((r.status_code, _p9_json(r).get("go", "absent")))
    check("Remove of the route the page came through answers the panel's own address; from the "
          "panel's own route, or with a page address that is not one, it refreshes in place",
          gone == [(200, _HOST32 + "/lgsm/tailscale"), (200, "absent"), (200, "absent")], repr(gone))
    js = _code_js(_script_text(os.path.join("static", "js", "tailscale.js")))
    bodies = [_js_fn(js, n) for n in ("enableServe", "removeServeRoute", "_tsAfterServeChange")]
    check("tailscale.js: Enable and Remove send the page's address and follow `go`; the in-place "
          "refresh is only the fallback",
          all(["page: location.href" in bodies[0], "_tsAfterServeChange(data.go)" in bodies[0],
               "refreshSection" not in bodies[0], "page: location.href" in bodies[1],
               "_tsAfterServeChange(data.go)" in bodies[1], "refreshSection" not in bodies[1],
               "window.location.assign(go)" in bodies[2], "refreshSection" in bodies[2]]),
          repr(bodies))


def _p32_disable():
    _seed({"443": {"/": _P, "/lgsm": _PS}, "8443": {"/x": _OTHER}}, funnel=["443"])
    _save_cfg(tailscale_use_funnel=True, **_LIVE_CFG)
    r = _serve_api(action="disable", mount="/")
    check("Disable takes down EVERY route to the panel (a second one stayed published, on a Funnel "
          "listener too) and nothing else",
          (r.status_code, _table(), _stored("tailscale_setup_done"))
          == (200, {"8443": {"/x": _OTHER}}, (False,)), repr((_p9_json(r), _table())))


# ═══ 4. the addresses the panel hands out ════════════════════════════════════════════════════════
_UP32 = {"BOOT_TLS": True, "BOOT_BIND": _ALL_IFACES}


def _banner(conf):
    cfg = dict(_cfg32.DEFAULT_CONFIG, port=5000, **_LIVE_CFG)
    return _su32._tailscale_banner(cfg, 5000, conf, ts.get_tailscale_info(force_refresh=True),
                                   _app32._serve_scheme_now)


def _p32_banner():
    _seed({"443": {"/": _OTHER, "/lgsm": _PS}})
    lines = _banner(_UP32)
    check("banner: the Tailscale address is the panel's own route, with its mount (it printed the "
          "root — another app's here)", lines == ["\n  🌐 Tailscale: %s/lgsm" % _HOST32], repr(lines))
    _seed({"443": {"/lgsm": _P}})
    lines = _banner(_UP32)
    check("banner: ...a route on the wrong scheme (a 502) is not offered; the tailnet address is, on "
          "the scheme served", lines == ["\n  🌐 Tailscale IP: https://100.64.0.9:5000"], repr(lines))
    lines = _banner({"BOOT_TLS": True, "BOOT_BIND": "127.0.0.1"})
    check("banner: ...and nothing for a panel bound to loopback with no working route", lines == [],
          repr(lines))


def _p32_banner_funnel():
    _seed({"443": {"/lgsm": _PS}, "8443": {"/": _OTHER}}, funnel=["8443"])
    lines = _banner(_UP32)
    check("banner: Funnel follows the panel's own route, not 'any app is funnelled'",
          not any("Funnel" in ln for ln in lines), repr(lines))
    _seed({"443": {"/lgsm": _PS}}, funnel=["443"])
    lines = _banner(_UP32)
    check("banner: ...and is named when the panel's route IS funnelled",
          "  🌍 Funnel (public): %s/lgsm" % _HOST32 in lines, repr(lines))
    main = _code(_script_text("app.py").split('if __name__ == "__main__":', 1)[1])
    check("banner: __main__ prints it AFTER the boot re-point (it read Serve as boot found it, before "
          "boot repaired it), and the root-URL line is gone",
          all([-1 < main.find("_boot_serve(app, cfg, port)") < main.find("_tailscale_banner("),
               "Tailscale: https://{ts_info.dns_name}" not in main]), main[-900:])


def _p32_links():
    _set_conf(BOOT_TLS=True)
    _seed({"443": {"/": _OTHER, "/lgsm": _PS}})
    _save_cfg(**_LIVE_CFG)
    inject = next(f for f in _p9.template_context_processors[None] if f.__name__ == "inject_globals")
    with _p9.test_request_context("/setup"):
        url1 = inject().get("tailscale_url")
    _seed({"443": {"/": _OTHER}})
    with _p9.test_request_context("/setup"):
        url2 = inject().get("tailscale_url", "missing")
    check("setup-complete link: the panel's own route with its mount, and none when no route reaches "
          "the panel (it was https://<name>, the root, either way)",
          (url1, url2) == (_HOST32 + "/lgsm", None), repr((url1, url2)))
    _seed(_LIVE)
    s1 = ts.suggest_best_bind(5000, scheme="https", mount="/lgsm")
    s2 = ts.suggest_best_bind(5000, scheme="https")
    check("Recommended Access: the panel's route at its configured mount, not the first one listed "
          "(control: with no mount, the first)", (s1["url"], s2["url"]) == (_HOST32 + "/lgsm", _HOST32),
          repr((s1, s2)))


# ═══ 5. the debug report ═════════════════════════════════════════════════════════════════════════
def _report(web, conf=None, seed=None, **cfg_over):
    (seed or _seed)(web)
    services = ts.get_tailscale_info(force_refresh=True).serve_config.get("services") or []
    cfg = dict(_cfg32.DEFAULT_CONFIG, port=5000, **dict(_LIVE_CFG, **cfg_over))
    view = {"version": "1.102.4", "backend_state": "Running", "magic_dns": True, "key_expiry": None,
            "operator_user": None, "health": [], "serve_unreadable": False,
            "funnel_enabled": False, "serve_services": services}
    res = _Result32()
    app = type("A", (), {"config": dict({"BOOT_TLS": True, "BOOT_SERVE": "ok"}, **(conf or {}))})()
    real = _nw32._load_cfg
    _nw32._load_cfg = lambda: (cfg, True)
    try:
        _nw32._tailscale_lines(_Ctx32(app=app), res, {}, ("ok", ("ok", view)))
    finally:
        _nw32._load_cfg = real
    return [(f["level"], f["text"]) for f in res.findings], "\n".join(res.lines)


def _has(found, level, *needles):
    return any(lv == level and all([n in t for n in needles]) for lv, t in found)


def _p32_report_live():
    found, text = _report(_LIVE)
    check("report: the live table's leftover is named as a route the panel does not manage, with "
          "the wrong scheme — a warn, the configured route being fine",
          (_has(found, "warn", "does not manage", "wrong scheme"),
           any(lv == "fail" for lv, _t in found)) == (True, False), repr(found))
    check("report: ...and its body gives the exact command that removes it, and that a restart does "
          "too — never the URL", ("`sudo tailscale serve --https=443 --set-path=/ off`" in text,
                                  "a panel restart also removes it" in text, "https://" in text)
          == (True, True, False), text)
    found, text = _report({"443": {"/": _PS, "/lgsm": _PS}})
    check("report: a leftover on the RIGHT scheme is reported too (it was silent until the next "
          "scheme flip made it a 502)", _has(found, "warn", "does not manage"), repr(found))
    found, text = _report({"443": {"/": _PS, "/lgsm": _PS}}, tailscale_mount="/")
    check("report: ...whichever of the two is the leftover (config '/', stale /lgsm)",
          ("--set-path=/lgsm off" in text, "--set-path=/ off" in text) == (True, False), text)


def _p32_report_shapes():
    found, text = _report({"443": {"/": _OTHER}, "8443": {"/": _PS}})
    check("report: a panel route on another listener gets that listener's flag in its command — "
          "--https=443 would remove ANOTHER app's '/'",
          ("--https=8443 --set-path=/ off" in text, "--https=443 --set-path=/ off" in text,
           _has(found, "warn", "configured tailscale_mount")) == (True, False, True), text)
    found, text = _report({"443": {"/": _PS}}, tailscale_setup_done=False, tailscale_mount="")
    check("report: with Serve not set up, every route to the panel is one it does not manage",
          _has(found, "warn", "does not manage"), repr(found))
    found, text = _report({"443": {"/lgsm": _PS}})
    check("report: the configured route alone, on the right scheme, is no finding (control)",
          not any("Serve" in t for _lv, t in found), repr(found))
    found, text = _report({"443": {"/lgsm": _P}})
    check("report: the CONFIGURED route on the wrong scheme stays a fail, and says a restart "
          "re-points it", _has(found, "fail", "configured Tailscale Serve route",
                               "restart re-points it"), repr(found))
    found, text = _report({"443": {"/a/b": _P, "/lgsm": _PS}})
    check("report: a leftover at a mount the report does not print says the command cannot be shown",
          ("cannot be shown" in text, "/a/b" in text) == (True, False), text)


def _p32_report_dead():
    found, _t = _report({"443": {"/": _P}})
    check("report: no managed route and EVERY route to the panel on the wrong scheme is a fail — "
          "Tailscale has no way in at all (the split had made it a warn)",
          _has(found, "fail", "every Tailscale Serve route", "wrong scheme"), repr(found))
    found, _t = _report({"443": {"/": _P}}, tailscale_setup_done=False, tailscale_mount="")
    check("report: ...with Serve not set up, too", _has(found, "fail", "every Tailscale Serve route"),
          repr(found))
    found, _t = _report({"443": {"/": _P, "/x": _PS}}, tailscale_setup_done=False, tailscale_mount="")
    check("report: ...but a 502 beside a route that works stays a warn (control)",
          (any(lv == "fail" for lv, _x in found), _has(found, "warn", "does not manage",
                                                      "wrong scheme")) == (False, True), repr(found))


def _p32_report_twin():
    # Seeded the one way a twin can exist (`serve set-raw`; every other write drops it). The report
    # and the page only READ Serve, so they meet it as it was set.
    found, text = _report({"443": {"/lgsm": _PS, "/lgsm/": _P}}, seed=_seed_raw)
    check("report: a '/lgsm/' twin set with `serve set-raw` is a route the panel does not manage, "
          "named with its exact path (it read as the configured route, so nothing named it)",
          (_has(found, "warn", "does not manage", "wrong scheme"),
           "`sudo tailscale serve --https=443 --set-path=/lgsm/ off`" in text) == (True, True), text)
    _seed_raw({"443": {"/lgsm": _PS, "/lgsm/": _P}})
    _save_cfg(**_LIVE_CFG)
    html = _A32.get("/tailscale").get_data(as_text=True)
    removes = re.findall(r'data-action="removeServeRoute"\s+data-args=\'\["@self"\]\'\s+'
                         r'data-mount="([^"]*)"', html)
    check("tailscale page: ...and it has its own Remove", removes == ["/lgsm/"], repr(removes))
    shown = (_pr32._leftovers_text("removed:/lgsm/"), _nw32._mount("/lgsm/"), _nw32._mount("//"),
             _pr32._leftovers_text("removed://"))
    check("report: the boot's line and the route's command print '/lgsm/' as itself (it is a safe "
          "shape); '//' is still 'custom'",
          shown == ("removed /lgsm/ (on :443)", "/lgsm/", "custom", "removed custom (on :443)"),
          repr(shown))


def _p32_report_restart_claim():
    shapes = (({"443": {"/lgsm": _PS}, "8443": {"/": _PS}}, None, {}),
              ({"443": {"/": _PS, "/x": _PS}}, None,
               {"tailscale_setup_done": False, "tailscale_mount": ""}),
              (_LIVE, {"BOOT_SERVE_LEFTOVERS": "failed:permission"}, {}),
              (_LIVE, {"BOOT_SERVE": "failed:permission"}, {}))
    said = [("a panel restart also removes it" in _report(web, conf, **over)[1])
            for web, conf, over in shapes]
    check("report: 'a panel restart also removes it' is not said for a route on another listener, "
          "with Serve not set up, or after a boot whose removal or re-point failed (it is false "
          "there)", said == [False, False, False, False], repr(said))


def _p32_report_boot():
    res, res2 = _Result32(), _Result32()
    app = type("A", (), {"config": {"BOOT_TLS": True, "BOOT_SERVE": "ok",
                                    "BOOT_SERVE_LEFTOVERS": "failed:permission"}})()
    _pr32._boot_lines(_Ctx32(app=app), res, {})
    app2 = type("A", (), {"config": {"BOOT_TLS": True, "BOOT_SERVE": "ok",
                                     "BOOT_SERVE_LEFTOVERS": "removed:/,/a b"}})()
    _pr32._boot_lines(_Ctx32(app=app2), res2, {})
    check("report: the boot's leftover outcome prints beside the re-point, a failure is a warn, and "
          "an unprintable mount is 'custom'",
          all(["removal FAILED (permission)" in "\n".join(res.lines),
               any("could not remove a Tailscale Serve route" in f["text"] for f in res.findings),
               "removed /, custom (on :443)" in "\n".join(res2.lines)]), repr((res.lines, res2.lines)))


# ═══ 6. uninstall.sh ═════════════════════════════════════════════════════════════════════════════
_UN32 = _script_text("uninstall.sh")
# From the routes reader to the end of the teardown. Before the fix the region began at the
# `if command -v tailscale` block (there was no reader), so the fallback start keeps that runnable.
_UN_REGION32 = (_region(_UN32, "_TS_ROUTES_PY='", "\n# ── Remove the panel files")
                if "_TS_ROUTES_PY='" in _UN32 else
                _region(_UN32, "if command -v tailscale", "\n# ── Remove the panel files"))


def _uninst(web, port="5000", ts_done="1", funnel=(), http=(), env=None):
    _seed(web, funnel, http)
    script = ("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\nok() { echo \"OK $*\"; }\n"
              "PANEL_PORT=%s\nTS_DONE=%s\nTS_CONF_UNREAD=0\nTS_MOUNT=/\n" % (port, ts_done)
              + _UN_REGION32)
    return _bash(script, env=env)


def _p32_uninstall():
    r = _uninst({"443": {"/": _OTHER, "/lgsm": _P}, "8443": {"/": _PS}})
    check("uninstall: every route to the panel's port comes off, on its own listener, and another "
          "app's '/' stays", (r.returncode, _table(), "Removed the panel's Tailscale Serve route at "
                              "/lgsm" in r.stdout) == (0, {"443": {"/": _OTHER}}, True),
          repr((r.returncode, r.stdout, r.stderr[-300:], _table())))
    check("uninstall: ...with the CLI's own removal, path always named — never `--remove` (exit 2 on "
          "every Tailscale) or `reset`",
          (sorted(_offs()), any("--remove" in c for c in _calls()), _all_named(_offs()))
          == ([["serve", "--https=443", "--set-path=/lgsm", "off"],
               ["serve", "--https=8443", "--set-path=/", "off"]], False, True), repr(_calls()))
    r = _uninst({"443": {"/": _P}}, ts_done="0")
    check("uninstall: a route to the panel's port made by hand (the README's) comes off too, "
          "tailscale_setup_done or not", (_table(), r.returncode) == ({}, 0), repr(r.stdout))
    r = _uninst({"8080": {"/": _P}}, http=["8080"])
    check("uninstall: an HTTP listener is named with --http=",
          _offs() == [["serve", "--http=8080", "--set-path=/", "off"]], repr(_calls()))


def _p32_uninstall_refusals():
    r = _uninst(_LIVE, env={"FAKE_TS_SERVE_UNREADABLE": "1"})
    check("uninstall: with Serve's status unreadable nothing is removed, and it says so",
          (_offs(), _table(), "Couldn't read this node's Tailscale Serve config" in r.stdout,
           r.returncode) == ([], _LIVE, True, 0), repr(r.stdout))
    r = _uninst({"443": {"/lgsm": _P}}, env={"FAKE_TS_OFF_FAIL": "1"})
    check("uninstall: a removal the CLI refuses is said, with the command that removes it, and the "
          "uninstall goes on", (r.returncode, "sudo tailscale serve --https=443 --set-path=/lgsm off"
                                in r.stdout) == (0, True), repr(r.stdout))
    r = _uninst({"443": {"/": _OTHER, "/lgsm": _P}}, funnel=["443"])
    check("uninstall: Funnel left on a listener that still serves another app is named",
          ("Funnel is still ON for the https=443 listener" in r.stdout, _table())
          == (True, {"443": {"/": _OTHER}}), repr(r.stdout))
    took = json.dumps({"web": {"443": {"/lgsm": _OTHER}}})
    r = _uninst({"443": {"/lgsm": _P}}, env={"FAKE_TS_TAKEOVER": took})
    check("uninstall: Serve is read again right before each `off`: a mount another app took after "
          "the first read is left alone", (_offs(), _table(), r.returncode)
          == ([], {"443": {"/lgsm": _OTHER}}, 0), repr((r.stdout, _calls())))
    r = _uninst(_LIVE, port="")
    check("uninstall: without the panel's port nothing is read or removed, and it says so",
          (_calls(), _table(), "Leaving this node's Tailscale Serve config alone" in r.stdout)
          == ([], _LIVE, True), repr((r.stdout, _calls())))


# ═══ 7. install.sh's HTTPS hint after an update ══════════════════════════════════════════════════
_INS32 = _script_text("install.sh")
_HINT_STUBS32 = ('panel_port() { echo 5000; }\npanel_serve_url() { printf "%s" "${TSURL:-}"; }\n'
                 'ufw_port_state() { echo "${UFW:-open}"; }\ncurl() { echo 203.0.113.7; }\n'
                 'YELLOW=""; CYAN=""; NC=""\n')


def _hint(pre, post, ufw="open", tsurl=""):
    script = ("set -euo pipefail\n" + _HINT_STUBS32 + _sh_fn(_INS32, "_post_update_scheme_hint")
              + '\n_post_update_scheme_hint "$1" "$2"\n')
    r = _bash(script, (pre, post), env={"UFW": ufw, "TSURL": tsurl})
    return r.stdout + r.stderr


def _p32_install_hint():
    check("install hint: nothing when the panel already served HTTPS before the update (it printed "
          "on EVERY update)", _hint("https", "https") == "", repr(_hint("https", "https")))
    out = _hint("http", "https")
    check("install hint: ...said when it really switched, with the direct address and the advice",
          all(["now serves HTTPS" in out, "https://203.0.113.7:5000" in out,
               "Set up Tailscale Serve" in out]), out)
    check("install hint: ...and said when the panel was not answering before (unknown is not "
          "'unchanged')", "serves HTTPS" in _hint("unknown", "https"), _hint("unknown", "https"))
    out = _hint("http", "https", ufw="closed", tsurl=_HOST32 + "/lgsm")
    check("install hint: behind Serve with the port closed in UFW: the Serve address, no public "
          "address the firewall drops, no 'set up Tailscale'",
          ((_HOST32 + "/lgsm") in out, "203.0.113.7" in out, "Set up Tailscale" in out)
          == (True, False, False), out)
    check("install hint: ...an unknown firewall state is said, and plain HTTP prints nothing",
          ("firewall state unknown" in _hint("http", "https", ufw="unknown"), _hint("http", "http"))
          == (True, ""), _hint("http", "https", ufw="unknown"))
    upd = _code(_INS32[_INS32.index("\n# UPDATE PATH"):_INS32.index("\n# FRESH INSTALL PATH")])
    pre_at = upd.find('PRE_SCHEME="$(panel_scheme_now)"')
    check("install hint: the update reads the scheme BEFORE it stops the panel, and hands it to the "
          "hint; the unconditional block is gone",
          all([-1 < pre_at < upd.find("svc stop linuxgsm-panel.service || true", pre_at),
               '_post_update_scheme_hint "${PRE_SCHEME:-unknown}" "${PANEL_SCHEME}"' in upd,
               "This panel now serves HTTPS.${NC} Open it at" not in upd]), repr(pre_at))


def _p32_install_readers():
    pdir = os.path.join(_TMP32, "panel")
    os.makedirs(os.path.join(pdir, "data"), exist_ok=True)
    with open(os.path.join(pdir, "data", "config.json"), "w", encoding="utf-8") as fh:
        json.dump({"port": 5000, "tailscale_mount": "/lgsm"}, fh)
    readers = "".join(_sh_fn(_INS32, n) for n in ("_owner_read", "panel_port", "panel_serve_url"))
    script = "set -euo pipefail\nPANEL_DIR=%s\n%s\npanel_serve_url\n" % (pdir, readers)
    _seed({"443": {"/": _OTHER, "/lgsm": _PS}})
    u1 = _bash(script).stdout.strip()
    _seed({"443": {"/": _OTHER, "/lgsm": _P}})
    u2 = _bash(script).stdout.strip()
    check("install hint: the Serve address is read from the HOST — the panel's route at its mount on "
          "an https backend — and none for a route that would 502",
          (u1, u2) == (_HOST32 + "/lgsm", ""), repr((u1, u2)))


def _p32_install_ufw():
    # A fake ufw and sudo on PATH: the reader runs `timeout … [sudo -n] ufw status`.
    _exe("ufw", 'printf "%b" "${FAKE_UFW_OUT:-}"\n')
    _exe("sudo", 'echo "$*" >> "${FAKE_SUDO_LOG}"\n[ "$1" = "-n" ] && shift\nexec "$@"\n')
    sudo_log = os.path.join(_TMP32, "sudo.log")
    fn = "set -euo pipefail\n" + _sh_fn(_INS32, "ufw_port_state") + '\nufw_port_state 5000\n'
    states = [_bash(fn, env={"FAKE_UFW_OUT": out, "FAKE_SUDO_LOG": sudo_log}).stdout.strip()
              for out in ("Status: active\\n\\nTo   Action  From\\n5000/tcp   ALLOW   Anywhere\\n",
                          "Status: active\\n\\n22/tcp   ALLOW   Anywhere\\n"
                          "5000/tcp on tailscale0   ALLOW   Anywhere\\n",
                          "Status: inactive\\n", "")]
    sudo_calls = ""
    if os.path.exists(sudo_log):
        with open(sudo_log, encoding="utf-8") as fh:
            sudo_calls = fh.read()
    for name in ("ufw", "sudo"):
        os.unlink(os.path.join(_BIN32, name))
    check("install hint: UFW reads open / closed (a tailscale0-only rule is not public) / inactive / "
          "unknown, and a non-root run asks `sudo -n`, never a prompt",
          (states, os.geteuid() == 0 or sudo_calls.count("-n ufw status") == 4)
          == (["open", "closed", "inactive", "unknown"], True), repr((states, sudo_calls)))


# ═══ 8. the docs: no hand-written Serve line with an upstream ════════════════════════════════════
def _p32_docs():
    bad = []
    for rel in ("README.md", os.path.join("docs", "https.md")):
        for n, line in enumerate(_script_text(rel).splitlines(), 1):
            if re.search(r"tailscale\s+(?:serve|funnel)\b[^`\n]*\b(?:https?|https\+insecure)://", line):
                bad.append("%s:%d" % (rel, n))
    check("docs: no `tailscale serve`/`funnel` command with an upstream to copy (the README's http:// "
          "one 502s against the default HTTPS panel and makes the wizard publish a second route)",
          bad == [], repr(bad))


def _fake_operator():
    """ensure_operator as the real one ends on a host: this account becomes the Tailscale operator.

    The real one runs the helper's tailscale-set-operator verb, as root; here the fake CLI's own
    `set --operator=` records it, so a host seeded operator_required lets this account change
    Serve from then on, and not before.
    """
    ts._run_ts(["set", "--operator=p32"], timeout=10)
    return True, "p32"


def _p32_harness():
    os.makedirs(_BIN32)
    _exe("tailscale", 'exec "%s" "%s" "$@"\n' % (sys.executable, _FAKE32))
    os.environ["PATH"] = _BIN32 + os.pathsep + os.environ.get("PATH", "")
    os.environ["FAKE_TS_STATE"] = _STATE32
    os.environ["FAKE_TS_LOG"] = _LOG32
    _patch32(ts, "ensure_operator", _fake_operator)
    _patch32(ts, "allow_tailscale_ufw", lambda: (True, ""))
    _patch32(ts._so, "_run_verb",
             lambda verb, args, **kw: (_VERBS32.append((verb, list(args))),
                                       ("", "refused by part32", 1))[1])
    _patch32(_rh32, "_setup_ts_ok", lambda: True)
    _seed({"443": {"/": _OTHER}})
    check("p32 harness: the panel's own code reaches the FAKE tailscale on PATH (never this host's)",
          (ts.get_tailscale_info(force_refresh=True).dns_name, ["serve", "status"] in _calls())
          == ("fakehost.tail0000.ts.net", True), repr(_calls()[:6]))


def _p32_cleanup():
    _restore32()
    for key, value in _ENV_SAVED32.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    _set_conf(**_CONF_SAVED32)
    if _CFG_SNAPSHOT32 is not None:
        _P9_CFG_PATH.write_bytes(_CFG_SNAPSHOT32)
    elif _P9_CFG_PATH.exists():
        _P9_CFG_PATH.unlink()
    ts._cache["info"] = None
    shutil.rmtree(_TMP32, ignore_errors=True)


try:
    _p32_harness()
    _A32 = _p9_client(P9_ADMIN)
    for _step32 in (_p32_fake_writes, _p32_boot_live, _p32_boot_scope, _p32_boot_twin,
                    _p32_boot_failures,
                    _p32_reread, _p32_free_mount, _p32_wizard_walk, _p32_wizard_adopt,
                    _p32_wizard_unread, _p32_enable, _p32_page, _p32_remove_route,
                    _p32_remove_operator, _p32_page_follows, _p32_disable, _p32_banner,
                    _p32_banner_funnel, _p32_links, _p32_report_live, _p32_report_shapes,
                    _p32_report_dead, _p32_report_twin, _p32_report_restart_claim,
                    _p32_report_boot, _p32_uninstall, _p32_uninstall_refusals, _p32_install_hint,
                    _p32_install_readers, _p32_install_ufw, _p32_docs):
        _step32()
    check("p32 harness: nothing reached the root fallback (every Serve command ran as the fake "
          "operator would)", _VERBS32 == [], repr(_VERBS32))
finally:
    _p32_cleanup()
