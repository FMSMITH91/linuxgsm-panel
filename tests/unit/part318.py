"""Part 318 of the unit suite: the web proxy's CDN presets, trusted proxies and an allow list read from an address.

1. CDN presets: the signed catalog carries Fastly's networks beside Cloudflare's (sites.presets), and its daily
   job (.github/scripts/cdn_ranges.py, .github/workflows/cdn-ranges.yml) reads both CDNs' official lists; the
   proxy reads a CDN's own header only for requests from that CDN's networks; the card has one button per
   CDN, each with its folded list, source and date.

HOW IT RUNS. part12's app and its database. ssh_manager.websites' seams answer for the host and record what the
routes ask of it; nothing reaches a host (part12's tripwire is armed). The card runs in node over part301's
harness; the ranges script is loaded by path and given stand-in fetchers and a scratch catalog.
"""
import importlib.util as _ilu318
import io as _io318
import json as _json318
import os
import shutil as _shutil318
import sys as _sys318
import tempfile as _tf318
from types import SimpleNamespace as _NS318

from flask import g as _g318

from unit.part01 import _root, check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part301 import _COMMON301, _LIST301, _list_sa301, _node301
from panel.core import config as _cfg318
from panel.db.models import (RemoteServer as _Remote318, User as _User318, Website as _Site318,
                             WebsiteDomain as _Dom318, WebsiteProxy as _Proxy318, db as _db318)
from panel.ops.ssh_manager import websites as _sw318
from panel.routes import websites as _w318
from panel.services import websites_catalog as _wc318
from panel.services import websites_proxy as _wp318

_FLOOR318 = os.path.join(_root, "panel", "addon_images", "catalog.json")
with open(_FLOOR318, encoding="utf-8") as _fh318:
    _FLOOR_DOC318 = _json318.load(_fh318)
_SITES318 = _FLOOR_DOC318["sites"]
_SPEC318 = _ilu318.spec_from_file_location("cdn_ranges_p318", os.path.join(_root, ".github", "scripts", "cdn_ranges.py"))
_CDN318 = _ilu318.module_from_spec(_SPEC318)
_SPEC318.loader.exec_module(_CDN318)
_TOKEN318 = "t" * 40
_ROWS318 = {"sites": [], "remotes": [], "users": []}
_REC318 = {"apply": [], "ports": []}
_CF_URLS318 = _CDN318.PROVIDERS["cloudflare"][1]
_FASTLY_URL318 = _CDN318.PROVIDERS["fastly"][1][0]


def _copy318(value):
    return _json318.loads(_json318.dumps(value))


class _Client318:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g318.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g318.pop("_login_user", None)
        return self.c.get(*a, **k)


def _j(resp):
    return resp.get_json(silent=True) or {}


def _rows318():
    r = _Remote318(name="p318-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.78")
    su = _User318(username="p318-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db318.session.add_all([r, su])
    _db318.session.commit()
    _ROWS318["remotes"].append(r.id)
    _ROWS318["users"].append(su.id)
    return _NS318(host=r, su=su)


def _site318(st, name):
    s = _Site318(remote_id=st.host.id, name=name, kind="static", state="running", enabled=True,
                 proxy_secret=_cfg318.encrypt_secret(_TOKEN318))
    _db318.session.add(s)
    _db318.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    from panel.core.clock import utcnow
    _db318.session.add(_Dom318(website_id=s.id, domain="%s.example.org" % name, is_primary=True, verified_at=utcnow(),
                               dns_state="matching"))
    _db318.session.commit()
    _ROWS318["sites"].append(s.id)
    return s


def _seams318():
    """The host at ssh_manager.websites' seams: the proxy's text and the firewall rules it would get are recorded."""
    def apply(remote, text, sites=(), proxy=None, start_it=False):
        _REC318["apply"].append(text)
        return True, _sw318.OK_APPLIED

    def ports(remote, proxy, enabled):
        _REC318["ports"].append(_sw318.wanted_rules(proxy, enabled))
        return True, _sw318.OK_PORTS
    _p9_patch(_sw318, "proxy_apply", apply)
    _p9_patch(_sw318, "ports_apply", ports)
    _p9_patch(_sw318, "proxy_stop", lambda *a, **k: (True, "stopped"))
    _p9_patch(_sw318, "tunnel_apply", lambda *a, **k: (True, _sw318.OK_TUNNEL))
    _p9_patch(_sw318, "proxy_status", lambda remote, proxy=None: (True, "installed=yes\nversion=2.11.9\nactive=active\n"
                                                                  "cache=no\n"))


def _reset318():
    _REC318["apply"], _REC318["ports"] = [], []


def _trust318(text):
    """(the trusted networks, the client-address lines) of the proxy configuration `text`."""
    lines = [ln.strip() for ln in text.split("\n")]
    nets = next((ln.split()[2:] for ln in lines if ln.startswith("trusted_proxies static")), [])
    return nets, [ln for ln in lines if ln.startswith(("client_ip_headers", "trusted_proxies_strict"))]


def _save318(su, st, exposure):
    """POST the card's exposure form for the test host: (status, the applied proxy text, the firewall's sources)."""
    _reset318()
    r = su.post("/websites/proxy/settings", json={"host_id": st.host.id, "exposure": exposure})
    text = (_REC318["apply"] or [""])[-1]
    froms = sorted({f for f, _p in (_REC318["ports"] or [[]])[-1] if f})
    return r.status_code, text, froms


# ── 1. CDN presets ────────────────────────────────────────────────────────────────────────────────
def _bad318(path, value):
    doc = _copy318(_SITES318)
    node = doc
    for key in path[:-1]:
        node = node[key]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return doc


def _s1_catalog():
    fastly = _SITES318["presets"].get("fastly") or []
    eq("CDN presets (catalog): the floor carries Fastly's networks beside Cloudflare's, both families, and passes the "
       "panel's own check; the origin-pull certificate stays Cloudflare's alone",
       (sorted(_SITES318["presets"]), {_wc318._canonical_net(n) is not None for n in fastly},
        {4, 6} <= {6 if ":" in n else 4 for n in fastly}, sorted(_SITES318["origin_pull"]), _wc318.sites_problems(_SITES318)),
       (["cloudflare", "fastly"], {True}, True, ["cloudflare"], []))
    bad = {"no Fastly preset": _bad318(("presets", "fastly"), KeyError),
           "Fastly with a private network": _bad318(("presets", "fastly"), ["10.0.0.0/8", "2a04:4e40::/32"]),
           "Fastly IPv4 only": _bad318(("presets", "fastly"), ["151.101.0.0/16"]),
           "an origin-pull certificate for Fastly": _bad318(("origin_pull", "fastly"), _SITES318["origin_pull"]["cloudflare"])}
    eq("CDN presets (catalog): a section without Fastly's preset, with a private or a one-family Fastly list, or with "
       "an origin-pull certificate the panel has no use for, is refused whole",
       sorted(k for k, d in bad.items() if not _wc318.sites_problems(d)), [])


_CF_LISTS318 = {_CF_URLS318[0]: "173.245.48.0/20\n103.21.244.0/22\n", _CF_URLS318[1]: "2400:cb00::/32\n"}
_FASTLY_OK318 = '{"addresses": ["151.101.0.0/16"], "ipv6_addresses": ["2a04:4e42::/31"]}'


def _ranges_run318(answers, start=None):
    """cdn_ranges.main over a scratch catalog: (exit status, stdout, the presets after)."""
    d = _tf318.mkdtemp(prefix="p318-cdn-")
    path = os.path.join(d, "catalog.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_json318.dumps(start or _FLOOR_DOC318, indent=2, sort_keys=True) + "\n")
        out, real = _io318.StringIO(), _sys318.stdout
        _sys318.stdout, err = out, _sys318.stderr
        _sys318.stderr = _io318.StringIO()
        try:
            rc = _CDN318.main(["x", "check"], fetcher=lambda u: answers[u], catalog=path)
        finally:
            _sys318.stdout, _sys318.stderr = real, err
        with open(path, encoding="utf-8") as fh:
            return rc, out.getvalue(), _json318.load(fh)["sites"]["presets"]
    finally:
        _shutil318.rmtree(d, ignore_errors=True)


def _s1_script():
    good = dict(_CF_LISTS318, **{_FASTLY_URL318: _FASTLY_OK318})
    rc, out, presets = _ranges_run318(good)
    eq("CDN ranges (main): both CDNs' published lists that pass replace the catalog's presets (and the result passes "
       "the panel's own check)",
       (rc, out, presets, _wc318.sites_problems(dict(_SITES318, presets=presets))),
       (0, "changed=true\n", {"cloudflare": ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"],
                              "fastly": ["151.101.0.0/16", "2a04:4e42::/31"]}, []))
    hostile = ['{"addresses": ["10.0.0.0/8"], "ipv6_addresses": ["2a04:4e42::/31"]}', "151.101.0.0/16",
               '{"addresses": ["151.101.0.0/16"]}', '{"addresses": ["151.101.1.0/16"], "ipv6_addresses": ["2a04:4e42::/31"]}',
               '{"addresses": [7], "ipv6_addresses": ["2a04:4e42::/31"]}', '{"addresses": ["151.101.0.0/16"], "ipv6_addresses": []}']
    got = [_ranges_run318(dict(_CF_LISTS318, **{_FASTLY_URL318: h})) for h in hostile]
    eq("CDN ranges (main): a Fastly answer with a private network, not JSON, without its IPv6 list, with host bits, "
       "a non-string or one family only is refused: Fastly keeps the catalog's networks, Cloudflare's are still "
       "updated, and the run says which CDN was refused and fails",
       [(rc, out, p["fastly"] == _SITES318["presets"]["fastly"], p["cloudflare"][0]) for rc, out, p in got],
       [(1, "changed=true\nrefused=fastly\n", True, "173.245.48.0/20")] * len(hostile))
    seen = []

    class _Resp:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return self.body[:n]

    class _Opener:
        def open(self, req, timeout=None):
            seen.append((req.full_url, req.get_header("User-agent"), timeout))
            return _Resp(b"151.101.0.0/16\n")
    text = _CDN318.fetch(_CF_URLS318[0], _Opener())
    eq("CDN ranges (fetch): only the fixed https URLs are fetched, under the script's own user agent (Cloudflare's list "
       "host answers urllib's default one with 403 Forbidden), with a timeout",
       (text, seen, _refused318(_CDN318.fetch, "https://evil.example/ips"), all(u.startswith("https://") for u in _CDN318.URLS)),
       ("151.101.0.0/16\n", [(_CF_URLS318[0], "linuxgsm-panel-cdn-ranges", 30)], True, True))


def _refused318(fn, *args):
    try:
        fn(*args)
    except (ValueError, KeyError, TypeError):
        return True
    return False


def _s1_workflow():
    with open(os.path.join(_root, ".github", "workflows", "cdn-ranges.yml"), encoding="utf-8") as fh:
        text = fh.read()
    steps = text.split("\n      - ")
    check_step = next((s for s in steps if "id: check" in s), "")
    pr_step = next((s for s in steps if "gh pr create" in s), "")
    eq("CDN ranges (workflow): egress allows Fastly's list host beside Cloudflare's; the check step runs bash with "
       "pipefail, so a refused list fails it through the tee; the pull request is still opened for the CDNs that "
       "passed",
       ("api.fastly.com:443" in text, "www.cloudflare.com:443" in text, "shell: bash" in check_step,
        "cdn_ranges.py check" in check_step, "!cancelled()" in pr_step, "steps.check.outputs.changed == 'true'" in pr_step),
       (True, True, True, True, True, True))


def _s1_render(st):
    su = _Client318(st.su.id)
    _site318(st, "p318-cdn")
    cf, fastly = _SITES318["presets"]["cloudflare"], _SITES318["presets"]["fastly"]
    got = {}
    for name, presets in (("fastly", ["fastly"]), ("cloudflare", ["cloudflare"]), ("both", ["cloudflare", "fastly"])):
        got[name] = _save318(su, st, {"exposure_mode": "restricted", "allow_presets": presets, "allow_cidrs": []})
    nets, lines = _trust318(got["fastly"][1])
    eq("CDN presets (POST /websites/proxy/settings, Fastly): the firewall admits Fastly's networks, the proxy trusts "
       "exactly them and reads the visitor's address from X-Forwarded-For right to left (Fastly-Client-IP keeps a "
       "visitor's own value, so it is never read)",
       (got["fastly"][0], sorted(nets) == sorted(_wp318._canonical(fastly)), lines, got["fastly"][2] == sorted(nets),
        "Fastly-Client-IP" in got["fastly"][1]),
       (200, True, ["client_ip_headers X-Forwarded-For", "trusted_proxies_strict"], True, False))
    eq("CDN presets: Cloudflare alone reads CF-Connecting-IP, which Cloudflare sets on every request (control)",
       _trust318(got["cloudflare"][1])[1], ["client_ip_headers CF-Connecting-IP"])
    nets, lines = _trust318(got["both"][1])
    eq("CDN presets: with Cloudflare's and Fastly's networks both trusted, CF-Connecting-IP is not read (a request "
       "through Fastly could carry a made-up one); X-Forwarded-For right to left serves both",
       (sorted(nets) == sorted(_wp318._canonical(cf + fastly)), lines),
       (True, ["client_ip_headers X-Forwarded-For", "trusted_proxies_strict"]))
    row = _Proxy318.query.filter_by(remote_id=st.host.id).first()
    _save318(su, st, {"exposure_mode": "restricted", "allow_presets": ["fastly", "akamai"], "allow_cidrs": []})
    _db318.session.refresh(row)
    info = _j(su.get("/websites/proxy/status?host_id=%d" % st.host.id)).get("preset_info") or {}
    eq("CDN presets: a preset name the panel does not have is dropped; the card gets each preset's networks from the "
       "catalog", (row.presets(), sorted(info), (info.get("fastly") or {}).get("ranges") == fastly),
       (["fastly"], ["cloudflare", "fastly"], True))


def _s1_card():
    info = {"cloudflare": {"ranges": ["173.245.48.0/20", "2400:cb00::/32"], "issued": "2026-11-20"},
            "fastly": {"ranges": ["151.101.0.0/16", "199.232.0.0/16", "2a04:4e42::/31"], "issued": "2026-11-20"}}
    answer = dict(_LIST301, proxies=[{"host_id": 1, "host_name": "h", "installed": True, "version": "2.11.9",
                                      "exposure_mode": "restricted", "allow_cidrs": [], "allow_presets": ["cloudflare"],
                                      "preset_info": info, "tunnel_service": "http://localhost:19080"}], options={})
    got = _node301(_list_sa301, _COMMON301 + ["websites.js", "websites_proxy.js"], r"""
  for (let i = 0; i < 4; i++) await tick();
  const before = [$('wp-cf').getAttribute('aria-pressed'), $('wp-fastly').getAttribute('aria-pressed')];
  const wired = [$('wp-cf').getAttribute('data-args'), $('wp-fastly').getAttribute('data-args'), $('wp-fastly').getAttribute('data-action')];
  window.wsPreset('fastly');
  const after = [$('wp-cf').getAttribute('aria-pressed'), $('wp-fastly').getAttribute('aria-pressed')];
  const body = WS.exposureBody();
  return {wired: wired, before: before, after: after, presets: body.allow_presets, state: $('wp-preset-state').textContent,
          sum: $('wp-fastly-sum').textContent, ranges: $('wp-fastly-ranges').children.length,
          src: $('wp-fastly-src').textContent, folded: [$('wp-cf-list').hasAttribute('open'), $('wp-fastly-list').hasAttribute('open')]};
""", routes={"/api/websites": answer})
    eq("CDN presets (card): one button per CDN, each pressed by its own tap and sent with the form; each CDN's list "
       "folded under the buttons with its count, every network, the catalog's date and its source (Fastly's with "
       "the Force TLS note)",
       (got.get("wired"), got.get("before"), got.get("after"), sorted(got.get("presets") or []), got.get("state"), got.get("sum"),
        got.get("ranges"), "2026-11-20" in (got.get("src") or ""), "api.fastly.com/public-ip-list" in (got.get("src") or ""),
        "Force TLS" in (got.get("src") or ""), got.get("folded")),
       (['["cloudflare"]', '["fastly"]', "wsPreset"], ["true", "false"], ["true", "true"], ["cloudflare", "fastly"],
        "On the list: Cloudflare, Fastly. Tap a button again to remove its networks.", "Fastly's networks (3)", 3,
        True, True, True, [False, False]))


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _cleanup318():
    _db318.session.rollback()
    sites = set(_ROWS318["sites"]) | {s.id for s in _Site318.query.filter(
        _Site318.remote_id.in_(_ROWS318["remotes"] or [0])).all()}
    for d in _Dom318.query.filter(_Dom318.website_id.in_(sorted(sites) or [0])).all():
        _db318.session.delete(d)
    for p in _Proxy318.query.filter(_Proxy318.remote_id.in_(_ROWS318["remotes"] or [0])).all():
        _db318.session.delete(p)
    for model, ids in ((_Site318, sorted(sites)), (_User318, _ROWS318["users"]), (_Remote318, _ROWS318["remotes"])):
        for i in ids:
            row = _db318.session.get(model, i)
            if row is not None:
                _db318.session.delete(row)
    _db318.session.commit()


def _ran318(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran318.last)."""
    import traceback
    try:
        step(*args)
        _ran318.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db318.session.rollback()
        _ran318.last = traceback.format_exc()[-1500:]
        return False


_ran318.last = ""
_trips318 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part318")
        _seams318()
        _st318 = _rows318()
        for _sec318 in (_s1_render,):
            check("part318: %s ran to the end" % _sec318.__name__, _ran318(_sec318, _st318), _ran318.last)
        for _sec318 in (_s1_catalog, _s1_script, _s1_workflow, _s1_card):
            check("part318: %s ran to the end" % _sec318.__name__, _ran318(_sec318), _ran318.last)
        eq("part318: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips318:], [])
    finally:
        _p9_restore_all()
        _w318._STATUS.clear()
        _cleanup318()
