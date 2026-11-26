"""Part 299 of the unit suite: the websites' runtime (builder W2).

1. The signed catalog's `sites` section: the floor's pins are whole and checked, a signed catalog's
   section is used only when it passes and only under the add-on rule (issued after this panel), a
   refused one leaves the floor's, and the signing tool refuses a catalog without a valid section.
2. The web proxy's configuration (websites_proxy.render) as text: the catch-all abort, the admin API
   off, HTTP/3 off, headers, timeouts, body limits, the per-site token, the three exposure modes and
   the forwarded-header trust they allow, the page cache and the custom rules.
3. The containers (websites.py): Quadlet units, the in-container server configs that refuse a request
   without the proxy's token, php.ini with the forced hardening, the app runtime, the object cache and
   the tunnel connector, and the shell the panel runs as a site's account.
4. The helper verbs and their remote forms: accounts, the proxy, the egress guard, quotas and the
   ws<id>_ database names.
5. The SSH layer and the firewall label; 6. the recipe engine.

HOW IT RUNS. Pure functions and the helper's own validators; no host is reached and nothing is
installed. Section 4 loads tools/panel-helper by path, as part05 does.
"""
import contextlib as _ctx299
import hashlib as _hashlib299
import importlib.machinery as _mach299
import importlib.util as _ilu299
import io as _io299
import json as _json299
import os
import re as _re299
import stat as _stat299
import subprocess as _sp299  # nosec B404 - python3 -I over this part's own scratch archives
import sys as _sys299
import tarfile as _tar299
import tempfile as _tf299
import zipfile as _zip299
from datetime import datetime as _dt299
from types import SimpleNamespace as _NS299

from unit.part01 import eq, _root
from panel.ops.ssh_manager import firewall as _fw299
from panel.ops.ssh_manager import websites as _smw299
from panel.security import privileged as _priv299
from panel.security import privileged_websites as _pws299
from panel.services import addons_catalog as _cat299
from panel.services import websites as _ws299
from panel.services import websites_catalog as _wc299
from panel.services import websites_egress as _eg299
from panel.services import websites_proxy as _wp299
from panel.services import websites_recipes as _wr299

_FLOOR_PATH299 = os.path.join(_root, "panel", "addon_images", "catalog.json")
with open(_FLOOR_PATH299, encoding="utf-8") as _fh299:
    _FLOOR_DOC299 = _json299.load(_fh299)
_SITES299 = _FLOOR_DOC299["sites"]


def _copy299(value):
    return _json299.loads(_json299.dumps(value))


# ── 1. the catalog's sites section ──────────────────────────────────────────────────────────────
def _s299_floor():
    digests = [_SITES299["static"]["image"], _SITES299["wpcli"]["image"], _SITES299["object_cache"]["image"],
               _SITES299["tunnel"]["cloudflare"]["image"]]
    digests += [e["image"] for e in _SITES299["php"].values()]
    digests += [e["image"] for e in _SITES299["wordpress"]["php"].values()]
    digests += [e["image"] for r in _SITES299["runtimes"].values() for e in r["versions"].values()]
    eq("sites catalog: the floor's section passes the panel's own check, every image is pinned by a full sha256 "
       "digest, and it is what addons_catalog carries as the floor's section",
       (_wc299.sites_problems(_SITES299), all(_re299.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", d) for d in digests),
        _cat299.FLOOR_SECTIONS.get("sites") == _SITES299, len(digests) >= 12),
       ([], True, True, True))
    eq("sites catalog: the shipped recipes are WordPress, phpBB, Drupal, MyBB and SMF, each release downloaded "
       "from an allowed https host with its sha256 (WordPress comes in its pinned image)",
       (sorted(_SITES299["recipes"]),
        [bool(_re299.fullmatch(r"[0-9a-f]{64}", r.get("sha256", ""))) for k, r in sorted(_SITES299["recipes"].items())
         if k != "wordpress"]),
       (["drupal", "mybb", "phpbb", "smf", "wordpress"], [True, True, True, True]))
    eq("sites catalog: the panel's digest shape is the add-on catalog's (one rule for both)",
       _wc299._DIGEST, _cat299._DIGEST)


def _bad299(path, value):
    """The floor's section with the field at `path` (a tuple of keys) set to `value`."""
    doc = _copy299(_SITES299)
    node = doc
    for key in path[:-1]:
        node = node[key]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return doc


def _s299_refusals():
    caddy_url = _SITES299["caddy"]["assets"]["amd64"]["url"]
    cases = {
        "image by tag": _bad299(("static", "image"), "docker.io/nginxinc/nginx-unprivileged:stable"),
        "caddy from another host": _bad299(("caddy", "assets", "amd64", "url"),
                                           caddy_url.replace("github.com", "example.com")),
        "caddy asset of another version": _bad299(("caddy", "assets", "amd64", "url"),
                                                  caddy_url.replace("2.11.9", "2.11.8")),
        "short sha256": _bad299(("caddy", "assets", "amd64", "sha256"), "abc"),
        "php without eol": _bad299(("php", "8.4", "eol"), KeyError),
        "preset with a private net": _bad299(("presets", "cloudflare"), ["10.0.0.0/8", "2606:4700::/32"]),
        "preset IPv4 only": _bad299(("presets", "cloudflare"), ["173.245.48.0/20"]),
        "preset not canonical": _bad299(("presets", "cloudflare"), ["173.245.48.1/20", "2606:4700::/32"]),
        "recipe url with a query": _bad299(("recipes", "phpbb", "url"), _SITES299["recipes"]["phpbb"]["url"] + "?x=1"),
        "recipe url on a port": _bad299(("recipes", "mybb", "url"), "https://github.com:8443/mybb/x.zip"),
        "recipe step of an unknown type": _bad299(("recipes", "phpbb", "steps", 0), {"type": "run-shell"}),
        "secret on a command line": _bad299(("recipes", "wordpress", "steps", 3, "argv", 5),
                                            "--admin_password={admin_password}"),
        "config written outside the site": _bad299(("recipes", "phpbb", "steps", 2, "dest"), "../../.bashrc"),
        "unknown placeholder": _bad299(("recipes", "drupal", "steps", 3, "template"), "{panel_secret_key}"),
        "egress to any host": _bad299(("recipes", "wordpress", "egress"), ["example.com"]),
        "database step without database": _bad299(("recipes", "mybb", "database"), False),
        "no recipes": _bad299(("recipes",), KeyError),
    }
    let = sorted(k for k, doc in cases.items() if not _wc299.sites_problems(doc))
    eq("sites catalog: a tag instead of a digest, a proxy binary from another host or version, a short hash, a "
       "PHP version without its end of support, a private or one-family preset, a download URL with a query or "
       "port, an unknown step type, a secret on a command line, a path outside the site, an unknown value, egress "
       "to an unlisted host, a database mismatch and a missing key are each refused", let, [])


def _with_stored299(sites, issued="2099-01-01T00:00:00Z", floor_time=1):
    """websites_catalog.section() with a stored catalog holding `sites`; the module state put back after."""
    saved = dict(_cat299._state)
    stored = {"schema": 1, "seq": 7, "issued": issued, "expires": "2099-02-01T00:00:00Z",
              "addons": _copy299(_cat299.FLOOR)}
    if sites is not None:
        stored["sites"] = sites
    _cat299._state.update(loaded=True, stored=stored, floor_time=floor_time)
    try:
        return _wc299.section(), _wc299.pins("static"), _wc299.preset_ranges("cloudflare")
    finally:
        _cat299._state.clear()
        _cat299._state.update(saved)


def _s299_stored():
    newer = _copy299(_SITES299)
    newer["static"]["image"] = "docker.io/nginxinc/nginx-unprivileged@sha256:" + "1" * 64
    newer["presets"]["cloudflare"] = ["198.41.128.0/17", "2606:4700::/32"]
    (sites, src), static, preset = _with_stored299(newer)
    eq("sites catalog (pins, through section()): a signed catalog's valid section issued after this panel is the "
       "one installs and the allow list use, with its source",
       (static["image"], preset, src.get("kind"), src.get("seq"), sites is not None),
       (newer["static"]["image"], ["198.41.128.0/17", "2606:4700::/32"], "catalog", 7, True))
    broken = _bad299(("static", "image"), "docker.io/nginxinc/nginx-unprivileged:latest")
    (_sites, src), static, _p = _with_stored299(broken)
    eq("sites catalog (pins): a signed catalog whose section is refused changes nothing: the floor's pins stay",
       (static["image"], src), (_SITES299["static"]["image"], {"kind": "floor"}))
    (_sites, src), static, _p = _with_stored299(newer, floor_time=4102444800)
    eq("sites catalog (pins): a catalog issued before this panel's own commit is not used (the floor is newer)",
       (static["image"], src), (_SITES299["static"]["image"], {"kind": "floor"}))
    (_sites, src), static, _p = _with_stored299(None)
    eq("sites catalog (pins): a catalog signed before the section existed leaves the floor's (control)",
       (static["image"], src), (_SITES299["static"]["image"], {"kind": "floor"}))


def _s299_versions():
    from datetime import date as _date299
    eq("sites catalog: a PHP version past its upstream security support is not offered; today's supported ones are",
       (_wc299.php_versions(_date299(2026, 11, 26)), _wc299.php_versions(_date299(2028, 1, 1)),
        _wc299.php_image("php", "8.3", _date299(2028, 1, 1)), _wc299.php_image("wordpress", "8.4", _date299(2026, 11, 26))),
       (["8.3", "8.4", "8.5"], ["8.4", "8.5"], None, _SITES299["wordpress"]["php"]["8.4"]["image"]))
    rt = _wc299.runtimes(_date299(2027, 6, 1))
    eq("sites catalog: Node's versions are offered only while supported upstream, with the runtime's defaults",
       (sorted(rt["node"]["versions"]), rt["node"]["port"], rt["node"]["start"], rt["node"]["egress"]),
       (["24", "26"], 3000, "npm start", ["registry.npmjs.org"]))


def _s299_generator():
    spec = _ilu299.spec_from_file_location("addon_catalog_p299", os.path.join(_root, "tools", "addon_catalog.py"))
    gen = _ilu299.module_from_spec(spec)
    spec.loader.exec_module(gen)
    src = _copy299(_FLOOR_DOC299)
    no_sites = {k: v for k, v in src.items() if k != "sites"}
    bad_sites = dict(src, sites=_bad299(("php", "8.4", "image"), "docker.io/library/php:8.4-apache"))
    got = [gen.build(_json299.dumps(o), "", 1800000000, "auto")[0] for o in (no_sites, bad_sites, src)]
    old_published = dict(no_sites, seq=3, issued="2026-11-01T00:00:00Z", expires="2026-12-01T00:00:00Z")
    rc, out, _msg = gen.build(_json299.dumps(src), _json299.dumps(old_published), 1800000000, "auto")
    eq("sites catalog (signing tool): a catalog without `sites` or with a refused one is not signed; today's builds, "
       "and builds on a published catalog from before the section, carrying the section into the next seq",
       (got, rc, _json299.loads(out).get("seq") if out else None, "sites" in (_json299.loads(out) if out else {})),
       ([1, 1, 0], 0, 4, True))


# ── 2. the web proxy's configuration ────────────────────────────────────────────────────────────


_TOKEN299 = "t" * 40


def _dom299(name, primary=True, verified=True, mode="acme", did=1):
    return _NS299(domain=name, is_primary=primary, id=did, verified_at=_dt299(2026, 1, 1) if verified else None,
                  cert_mode=mode)


def _site299(**kw):
    base = dict(id=5, name="blog", kind="php", account="ws5", port=20005, enabled=True, proxy_secret="enc",
                domains=[_dom299("blog.example.org")], max_body_mb=64, static_cache=True, custom_rules="[]",
                page_cache=False, page_cache_ttl=300, access_log=False, raw_proxy_snippet="", php_version="8.4",
                mem_mb=512, cpu_milli=1500, pids=256, php_settings="{}", php_ini_custom="", opcache=True,
                object_cache=False, full_egress=False, app_port=None, runtime="", runtime_version="",
                build_command="", start_command="", env_enc="")
    base.update(kw)
    return _NS299(**base)


def _proxy299(mode="public", cidrs=(), presets=(), mtls=False, provider=""):
    return _NS299(exposure_mode=mode, cidrs=lambda: list(cidrs), presets=lambda: list(presets),
                  origin_pull_mtls=mtls, tunnel_provider=provider)


def _render299(sites, proxy=None, opts=None):
    return _wp299.render(sites, proxy, opts, secret_of=lambda s: _TOKEN299)


def _block299(text, head):
    """The lines of the block that starts with `head` up to its closing brace at column 0."""
    lines = text.split("\n")
    i = lines.index(head)
    j = lines.index("}", i)
    return lines[i:j + 1]


def _s299_proxy_base():
    text = _render299([_site299()])
    glob = _block299(text, "{")
    site = _block299(text, "blog.example.org {")
    eq("proxy config: no admin API, nothing persisted, HTTP/1.1 and HTTP/2 only (no UDP 443), server timeouts "
       "against slow clients, no trusted proxy in public mode",
       [ln.strip() for ln in glob if ln.strip() in ("admin off", "persist_config off", "protocols h1 h2", "read_header 10s",
                                                    "idle 2m")] + [any("trusted_proxies" in ln for ln in glob)],
       ["admin off", "persist_config off", "protocols h1 h2", "read_header 10s", "idle 2m", False])
    eq("proxy config: any other name and the bare address are aborted (the catch-all closes the connection)",
       text.rstrip("\n").split("\n")[-3:], ["http:// {", "\tabort", "}"])
    eq("proxy config: a site forwards to its own loopback port with its token, a body limit, compression, HSTS, "
       "nosniff, Referrer-Policy and the server's own headers removed",
       [ln.strip() for ln in site if ln.strip().startswith(("reverse_proxy", "header_up", "max_size", "encode",
                                                            "Strict-Transport", "X-Content", "Referrer", "-Server",
                                                            "-X-Powered"))],
       ["encode zstd gzip", "max_size 64MB", 'Strict-Transport-Security "max-age=63072000"',
        "X-Content-Type-Options nosniff", "Referrer-Policy strict-origin-when-cross-origin", "-Server", "-X-Powered-By",
        "reverse_proxy 127.0.0.1:20005 {", 'header_up X-Panel-Proxy-Token "%s"' % _TOKEN299])
    eq("proxy config: TLS 1.2 and 1.3 by default (OWASP: TLS 1.3 first, 1.2 for compatibility), 1.3 alone when set",
       ([ln.strip() for ln in site if "protocols tls" in ln],
        [ln.strip() for ln in _render299([_site299()], None, {"tls_min": "1.3"}).split("\n") if "protocols tls" in ln]),
       (["protocols tls1.2 tls1.3"], ["protocols tls1.3"]))


def _names299(text, *names):
    """Which of `names` the rendered text holds as a whole host name (sorted); never a substring match."""
    return sorted(set(_re299.split(r"[^a-z0-9.-]+", text)) & set(names))


def _s299_proxy_base2():
    text = _render299([_site299()])
    hidden = [_site299(id=6, name="off", enabled=False, port=20006, domains=[_dom299("off.example.org", did=2)]),
              _site299(id=7, name="new", port=20007, domains=[_dom299("new.example.org", verified=False, did=3)])]
    t2 = _render299(hidden)
    eq("proxy config: a disabled site and a domain not verified are not served (never on demand); an enabled "
       "site with a verified domain is (control)",
       (_names299(t2, "off.example.org", "new.example.org"), "on_demand" in text,
        [ln for ln in text.split("\n") if ln.strip() == "blog.example.org {"] != []),
       ([], False, True))
    bad_token = _wp299.render([_site299()], None, None, secret_of=lambda s: "short")
    eq("proxy config: a site whose token cannot be read is left out, never served without one",
       (_names299(bad_token, "blog.example.org"), _names299(text, "blog.example.org")), ([], ["blog.example.org"]))
    hsts = _render299([_site299()], None, {"hsts_subdomains": True, "hsts_preload": True})
    eq("proxy config: includeSubDomains and preload only when the operator turns them on (OWASP's recommended value "
       "is shown beside the setting, with a note when outside it)",
       ([ln.strip() for ln in hsts.split("\n") if "Strict-Transport" in ln],
        sorted(_wp299.owasp_notes(_wp299.options({"hsts_max_age": 86400}))), _wp299.owasp_notes(_wp299.options(
            {"hsts_subdomains": True}))),
       (['Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"'], ["hsts_max_age", "hsts_subdomains"],
        {}))


def _s299_proxy_modes():
    restricted = _render299([_site299()], _proxy299("restricted", ["203.0.113.0/24", "203.0.113.7/32"]))
    glob = _block299(restricted, "{")
    eq("proxy config (restricted, custom networks): trusted_proxies is exactly the allow list (a network inside "
       "another dropped) and the client address is read from X-Forwarded-For right to left, only from it",
       [ln.strip() for ln in glob if "trusted" in ln or "client_ip" in ln],
       ["trusted_proxies static 203.0.113.0/24", "client_ip_headers X-Forwarded-For", "trusted_proxies_strict"])
    cf = _render299([_site299()], _proxy299("restricted", [], ["cloudflare"], mtls=True))
    trusted = [ln.strip() for ln in cf.split("\n") if "trusted_proxies static" in ln][0].split()[2:]
    eq("proxy config (restricted, Cloudflare preset): the catalog's ranges, CF-Connecting-IP read only from them, "
       "and with origin pulls on, the CDN's client certificate required",
       (trusted == _SITES299["presets"]["cloudflare"] or sorted(trusted) == sorted(_SITES299["presets"]["cloudflare"]),
        "client_ip_headers CF-Connecting-IP" in cf, "mode require_and_verify" in cf,
        "trust_pool file %s" % _wp299.ORIGIN_PULL_CA in cf),
       (True, True, True, True))
    tunnel = _render299([_site299()], _proxy299("tunnel", provider="cloudflare"))
    eq("proxy config (tunnel): plain HTTP on the loopback port the connector reaches, no automatic HTTPS, no HSTS, "
       "only loopback trusted",
       ([ln.strip() for ln in _block299(tunnel, "{") if ln.strip().startswith(("auto_https", "default_bind",
                                                                                "http_port", "trusted_proxies"))],
        "http://blog.example.org {" in tunnel, "Strict-Transport" in tunnel),
       (["auto_https off", "default_bind 127.0.0.1", "http_port %d" % _wp299.TUNNEL_PORT,
         "trusted_proxies static 127.0.0.1/32 ::1/128"], True, False))
    eq("proxy config: allow_list merges the row's networks and its presets, canonical, without duplicates",
       _wp299.allow_list(_proxy299("restricted", ["198.41.128.0/17", "203.0.113.0/24"], ["cloudflare"]))[:2],
       ["103.21.244.0/22", "103.22.200.0/22"])


def _s299_proxy_rules():
    rules = [{"type": "redirect", "from": "/old", "to": "/new", "code": 301},
             {"type": "header", "name": "Content-Security-Policy", "value": "default-src 'self'"},
             {"type": "deny", "path": "/backup*"}]
    text = _render299([_site299(custom_rules=_json299.dumps(rules), page_cache=True, access_log=True)], None,
                      {"cache_build": True})
    site = [ln.strip() for ln in _block299(text, "blog.example.org {")]
    eq("proxy config: custom rules render as a redirect, an extra header and a 404 for a denied path",
       [ln for ln in site if ln.startswith(("redir", "Content-Security", "@deny", "respond"))],
       ['Content-Security-Policy "default-src \'self\'"', 'redir /old "/new" 301', "@deny2 path /backup*",
        "respond @deny2 404"])
    eq("proxy config: the page cache skips logged-in cookies, writes and admin paths; access logs mask addresses "
       "(/24, /48) and drop headers",
       ("method GET HEAD" in site, any(ln.startswith("not header_regexp Cookie") and "wordpress_logged_in_" in ln
                                       and "phpbb" in ln for ln in site),
        any(ln.startswith("not path /wp-admin*") and "/adm*" in ln for ln in site), "ipv4 24" in site, "ipv6 48" in site,
        "request>headers delete" in site),
       (True, True, True, True, True, True))
    eq("proxy config: no page cache unless the catalog's cache build is installed (control)",
       "cache @pagecache" in _render299([_site299(page_cache=True)]), False)


def _s299_proxy_rules2():
    rules = [{"type": "redirect", "from": "/old", "to": "/new", "code": 301},
             {"type": "header", "name": "Content-Security-Policy", "value": "default-src 'self'"},
             {"type": "deny", "path": "/backup*"}]
    hostile = [
        [{"type": "header", "name": "Set-Cookie", "value": "x=1"}],
        [{"type": "header", "name": "X-Panel-Proxy-Token", "value": "x"}],
        [{"type": "header", "name": "X-A", "value": 'a" }\nhttp:// {'}],
        [{"type": "header", "name": "X-A", "value": "{env.PANEL_SECRET}"}],
        [{"type": "redirect", "from": "/a", "to": "javascript:alert(1)", "code": 301}],
        [{"type": "redirect", "from": "a", "to": "/b", "code": 301}],
        [{"type": "redirect", "from": "/a", "to": "/b", "code": 200}],
        [{"type": "deny", "path": "/x {\n}"}],
        [{"type": "exec", "cmd": "id"}],
        [{"type": "deny", "path": "/a"}] * 51,
    ]
    let = [r for r in hostile if not _wp299.rules_problems(r)]
    eq("proxy rules: a protected header, the token header, quotes, braces or a newline in a value, a non-https "
       "redirect, a bad path, a bad code, an unknown rule and too many rules are each refused; the form's own "
       "rules pass (control)", (let, _wp299.rules_problems(rules)), ([], []))
    broken = _render299([_site299(custom_rules=_json299.dumps(hostile[2]))])
    eq("proxy config: a stored rule that fails the check is never rendered (the site is served without it)",
       ("http:// {\n\tabort" in broken, broken.count("http:// {")), (True, 1))
    eq("proxy snippet (superadmin): unbalanced braces and reads of the environment or files are refused",
       [bool(_wp299.snippet_problems(t)) for t in ("}\nexample.com {", "header X {env.SECRET}", "import /etc/x",
                                                    "respond /health 200")],
       [True, True, True, False])


# ── 3. the containers ───────────────────────────────────────────────────────────────────────────


def _lines299(text, prefix):
    return [ln for ln in text.split("\n") if ln.startswith(prefix)]


def _s299_quadlet():
    site = _site299(kind="php")
    net = _ws299.network(site, db_port=3306)
    q = _ws299.quadlet(site, (1005, 1006), net, image="docker.io/library/php@sha256:" + "a" * 64)
    eq("site container: rootless with the account's own uid and gid, every capability dropped, no new privileges, "
       "read-only root, pids and open files limited, published on 127.0.0.1 only, image by digest, never pulled",
       [ln for ln in q.split("\n") if ln.split("=")[0] in (
           "UserNS", "User", "Group", "ReadOnly", "DropCapability", "NoNewPrivileges", "PidsLimit", "Ulimit",
           "PublishPort", "Pull")],
       ["Pull=never", "PublishPort=127.0.0.1:20005:8080", "UserNS=keep-id", "User=1005", "Group=1006", "ReadOnly=true",
        "DropCapability=all", "NoNewPrivileges=true", "PidsLimit=256", "Ulimit=nofile=4096:4096"])
    eq("site container: memory without swap, CPU and no DNS; no route out but the database forward",
       (_lines299(q, "PodmanArgs="), net),
       (["PodmanArgs=--memory=512m --memory-swap=512m --cpus=1.50 --stop-timeout=20 --dns=none"],
        "pasta:-4,-o,127.0.0.1,-T,3306:3306"))
    wp = _ws299.network(_site299(kind="wordpress"), db_port=3306)
    full = _ws299.network(_site299(kind="php", full_egress=True), db_port=3306)
    eq("site network: WordPress reaches its egress proxy (3128 inside) and nothing else; the superadmin's full "
       "egress switch drops the loopback lock and DNS block (the egress guard still applies)",
       (wp, full, "--dns=none" in _ws299.quadlet(_site299(full_egress=True), (1, 1), full, image="x/y@sha256:" + "b" * 64)),
       ("pasta:-4,-o,127.0.0.1,-T,3306:3306,-T,3128:22005", "pasta:-4,-T,3306:3306", False))
    static = _ws299.quadlet(_site299(kind="static"), (1005, 1005), "pasta:-4,-o,127.0.0.1", image="x/y@sha256:" + "c" * 64)
    eq("static site: its files mounted read-only, no interpreter (nginx), tmpfs for nginx's own temp files",
       _lines299(static, ("Volume=", "Tmpfs=")),
       ["Volume=/home/ws5/site/html:/usr/share/nginx/html:ro",
        "Volume=/home/ws5/site/conf/nginx.conf:/etc/nginx/conf.d/default.conf:ro", "Tmpfs=/tmp:rw,mode=1777,size=64m"])
    refused = []
    for acct in ("root", "ubuntu", "ws0", "ws1;id", "../ws1", "lgsmpanel"):
        try:
            _ws299.quadlet(_site299(account=acct), (1, 1), "pasta:-4", image="x/y@sha256:" + "d" * 64)
        except ValueError:
            refused.append(acct)
    eq("site container: only a ws<N> account the panel names is ever written into a unit", len(refused), 6)


def _s299_servers():
    n = _ws299.nginx_conf(_TOKEN299)
    a = _ws299.apache_conf(_TOKEN299)
    eq("site servers: nginx and Apache answer 403 without the web proxy's token; Apache checks it after every "
       ".htaccess (Location/If) and removes the header before PHP sees it",
       ('if ($http_x_panel_proxy_token != "%s") {' % _TOKEN299 in n, "return 403;" in n,
        "<If \"%%{HTTP:X-Panel-Proxy-Token} != '%s'\">" % _TOKEN299 in a, "Require all denied" in a,
        a.index("<Location") < a.index("<If \"") < a.index("</Location>"), "RequestHeader unset X-Panel-Proxy-Token" in a,
        "Listen 8080" in a, "ServerTokens Prod" in a, "Options -Indexes +SymLinksIfOwnerMatch" in a),
       (True, True, True, True, True, True, True, True, True))
    gate = _ws299.nginx_conf(_TOKEN299, 3000)
    eq("app gate: the token checked, then forwarded to the app's own port with the token header emptied",
       ("proxy_pass http://127.0.0.1:3000;" in gate, 'proxy_set_header X-Panel-Proxy-Token "";' in gate, "return 403;" in gate),
       (True, True, True))
    bad = []
    for tok in ("", "short", 'x" ; }', "a" * 31, "a b" * 20):
        for fn in (_ws299.nginx_conf, _ws299.apache_conf):
            try:
                fn(tok)
            except ValueError:
                bad.append(fn.__name__)
    eq("site servers: a token that is too short or holds anything but URL-safe characters is refused (it is "
       "written into a config)", len(bad), 10)


def _s299_php():
    site = _site299(php_settings=_json299.dumps({"memory_limit": "512M", "display_errors": "On", "max_input_vars": "9e9"}),
                    php_ini_custom="max_file_uploads = 5\nexpose_php = On\n")
    ini = _ws299.php_ini(site)
    last = [ln for ln in ini.strip().split("\n")][-2:]
    eq("php.ini: the form's values written (a bad one falls back to the default), the panel's hardening always last "
       "(expose_php Off, allow_url_include Off), and an Advanced text that fails its check is not written at all",
       ("memory_limit = 512M" in ini, "display_errors = On" in ini, "max_input_vars = 3000" in ini, last,
        "max_file_uploads = 5" in ini),
       (True, True, True, ["expose_php = Off", "allow_url_include = Off"], False))
    hostile = ["extension=/tmp/evil.so", "zend_extension = xdebug", "auto_prepend_file = /etc/passwd",
               "open_basedir = /var/www/html:/home", "sendmail_path = /bin/sh -c id", "allow_url_include = On",
               "include_path = ../../etc", "error_log = /home/ws5/.bashrc", "memory_limit = ${PANEL_KEY}",
               "[HOST=example.org]", "opcache.preload = /var/www/html/x.php", "ffi.enable = 1"]
    eq("php.ini (Advanced): code loading, paths outside the site, a program to run, the forced keys, environment "
       "reads and sections are each refused, line by line; plain settings and comments pass (control)",
       ([h for h in hostile if not _ws299.php_ini_problems(h)],
        _ws299.php_ini_problems("; comment\nmax_file_uploads = 5\nauto_prepend_file = /var/www/html/prepend.php\n")),
       ([], []))
    www, tmp = _ws299.PHP_PATH_ROOTS       # the site's files and its container's own temporary folder
    paths = {tmp: True, www: True, www + "/a.b/c_d-e": True, tmp + "/" + "x" * 64: True, ".:%s:%s/lib" % (tmp, www): True,
             tmp + "/" + "x" * 65: False, tmp + "/": False, tmp + "x": False, www + "x/a": False, tmp + "//a": False,
             tmp + "/a b": False, tmp + "/../etc": False, www.rsplit("/", 1)[0]: False, tmp * 255 + "!": False}
    got = {p: not _ws299.php_ini_problems("open_basedir = " + p) for p in paths}
    eq("php.ini (Advanced): a path is one of the two roots plus folders of 1-64 plain characters; an empty, too long "
       "or spaced folder, a look-alike root and '..' are refused, and a long hostile value is answered (the check "
       "is string operations, not a backtracking regex)", got, paths)
    eq("php form: sizes, numbers, a time zone and On/Off are checked against their ranges",
       _ws299.php_settings_problems({"memory_limit": "8M", "upload_max_filesize": "64M", "date.timezone": "Mars/Base",
                                     "display_errors": "yes", "max_execution_time": "60", "evil": "1"}),
       ["evil is not a setting of this form.", "memory_limit must be a size like 256M, from 16M to 4096M.",
        "date.timezone must be a time zone like Europe/Paris.", "display_errors must be On or Off."])
    eq("php.ini: OPcache on by default with its settings; off writes opcache.enable = 0",
       ("opcache.enable = 1" in ini, "opcache.enable = 0" in _ws299.php_ini(_site299(opcache=False))), (True, True))


def _s299_app_cache_tunnel():
    app = _site299(kind="app", runtime="node", runtime_version="24", app_port=3000, start_command="node server.js",
                   build_command="npm ci --omit=dev")
    q = _ws299.app_quadlet(app, (1005, 1005), "pasta:-4,-o,127.0.0.1", image="x/node@sha256:" + "e" * 64)
    eq("app container: the start command from a mounted script (never a unit's command line), its variables from "
       "a 0600 file, published through the gate's port",
       (_lines299(q, ("Exec=", "EnvironmentFile=", "PublishPort=")), "node server.js" in q),
       (["PublishPort=127.0.0.1:20005:8080", "EnvironmentFile=/home/ws5/site/conf/app.env",
         "Exec=/bin/sh /panel/start.sh"], False))
    try:
        _ws299.app_quadlet(_site299(kind="app", app_port=8080), (1, 1), "pasta:-4", image="x/y@sha256:" + "f" * 64)
        gate_clash = False
    except ValueError:
        gate_clash = True
    eq("app container: an app port equal to the gate's own (8080) is refused", gate_clash, True)
    eq("app variables: names checked, reserved ones and multi-line values refused; a good set renders as KEY=value",
       (_ws299.env_problems({"PORT": "1", "bad-name": "x", "OK": "a\nb"}), _ws299.env_file(app, {"B": "2", "A": "x y"})),
       (["The value of OK must be one line of at most 4096 characters.", "PORT is not a variable name an app may set.",
         "bad-name is not a variable name an app may set."], "A=x y\nB=2\n"))
    build = _ws299.build_sh("ws5", app, (1005, 1005), image="x/node@sha256:" + "e" * 64)
    eq("app build: a one-off hardened container with the build-time egress proxy only, started for the build and "
       "stopped after it",
       ("--cap-drop=all" in build, "--read-only" in build, "HTTPS_PROXY=http://127.0.0.1:3128" in build,
        build.index("systemctl --user start lgsm-site-egress.service") < build.index("podman run")
        < build.index("systemctl --user stop lgsm-site-egress.service")),
       (True, True, True, True))
    cache = _ws299.object_cache_quadlet(_site299(object_cache=True), (1005, 1005), image="x/valkey@sha256:" + "9" * 64)
    conf = _ws299.valkey_conf("p" * 40)
    eq("object cache: in the site's own network namespace (private to it), its password in a read-only config "
       "file, no persistence, memory capped",
       ("Network=container:lgsm-site" in cache, "PublishPort" in cache, "requirepass " + "p" * 40 in conf,
        'save ""' in conf, "appendonly no" in conf, "maxmemory 64mb" in conf, "p" * 40 in cache),
       (True, False, True, True, True, True, False))
    tun = _ws299.tunnel_quadlet(_proxy299("tunnel", provider="cloudflare"), (1100, 1100), image="x/cfd@sha256:" + "8" * 64)
    eq("tunnel connector: its own account, the token read from a mounted file (never argv or environment), "
       "reaching only the proxy's loopback port forwarded in",
       (_lines299(tun, ("Exec=", "Network=", "Volume=")), "Environment=" in tun),
       (["Network=pasta:-T,%d" % _wp299.TUNNEL_PORT, "Volume=/home/lgsmtunnel/tunnel/token:/etc/cloudflared/token:ro",
         "Exec=tunnel --no-autoupdate run --token-file /etc/cloudflared/token"], False))


def _s299_shell():
    site = _site299(kind="static")
    files = _ws299.site_files(site, (1005, 1005), "pasta:-4,-o,127.0.0.1", _TOKEN299, image="x/n@sha256:" + "7" * 64)
    inst = _ws299.install_sh("ws5", site, image="x/n@sha256:" + "7" * 64)
    stdin = _ws299.bundle(files)
    eq("site install: the token travels in the stdin bundle, never in the shell text; the writer accepts only the "
       "panel's own file names; the image is pulled by digest",
       (_TOKEN299 in inst, _TOKEN299 in "".join(__import__("base64").b64decode(ln.split()[1]).decode()
                                                 for ln in stdin.splitlines()),
        "SITE_FILES_REFUSED" in inst, "podman pull -q x/n@sha256:" + "7" * 64 in inst),
       (False, True, True, True))
    try:
        _ws299.bundle({"../../.ssh/authorized_keys": "x"})
        stray = False
    except ValueError:
        stray = True
    eq("site install: a file outside the panel's list is refused before anything is sent", stray, True)
    out = ("os=24.04\npodman=podman version 4.9.3\nuid=1005\ngid=1005\nstate=active\nresult=success\n"
           "image=x/n@sha256:" + "7" * 64 + "\nmem=12MB / 512MB\ndisk_mb=42\ninstalled=1\n")
    eq("site probe: read back as state, ids, disk and image",
       {k: v for k, v in _ws299.parse_probe(out).items() if k in ("state", "uid", "disk_mb", "installed", "result")},
       {"state": "running", "uid": 1005, "disk_mb": 42, "installed": True, "result": "success"})
    eq("site disk: warn at 80 %, refuse uploads at 100 %, stop at 120 % (du mode)",
       [_ws299.disk_state(u, 100) for u in (10, 80, 100, 119, 120, None)], ["ok", "warn", "full", "full", "over", "ok"])
    start = _ws299.start_sh("ws5", _site299(kind="wordpress", object_cache=True))
    eq("site start: the start limit cleared first, the cache and egress proxy started with it, a start-limit hit named",
       ("reset-failed lgsm-site.service lgsm-site-cache.service" in start, "enable --now lgsm-site-egress.service" in start,
        "SITE_START_LIMIT" in start), (True, True, True))


# ── 4. the helper verbs ─────────────────────────────────────────────────────────────────────────


_HELPER_PATH299 = os.path.join(_root, "tools", "panel-helper")
_hspec299 = _ilu299.spec_from_loader("panel_helper_p299", _mach299.SourceFileLoader("panel_helper_p299", _HELPER_PATH299))
_H299 = _ilu299.module_from_spec(_hspec299)
_hspec299.loader.exec_module(_H299)
_H299.NSSWITCH_FILE = os.path.join(_root, "tests", "no-such-nsswitch.conf")


def _refused299(fn, *args):
    try:
        fn(*args)
    except (ValueError, _priv299.VerbError):
        return True
    return False


def _s299_helper_validators():
    bad_accounts = ["root", "ubuntu", "ws0", "ws01", "ws1;id", "ws1 ", "../ws1", "lgsmpanel", "ws1234567890", "WS1", ""]
    eq("helper verbs: a website account is ws<digits> (no leading zero) or the tunnel's own, in both tables; "
       "anything else is refused before any tool runs",
       ([a for a in bad_accounts if not _refused299(_H299.v_website_account, a)],
        [a for a in bad_accounts if not _refused299(_priv299.check_args, "website-account-remove", [a])],
        _H299.v_website_account("ws12"), _H299.v_website_account("lgsmtunnel")),
       ([], [], "ws12", "lgsmtunnel"))
    eq("helper verbs: the proxy's release is x.y.z and its sha256 64 hex digits; the URL is never an argument",
       ([v for v in ("2.11", "v2.11.9", "2.11.9;id", "../2") if not _refused299(_H299.v_caddy_version, v)],
        _refused299(_H299.v_sha256, "A" * 64), _refused299(_priv299.check_args, "website-proxy-install",
                                                           ["2.11.9", "amd64", "a" * 64, "https://evil.example/c"]),
        _H299.WEB_CADDY_URL % ("2.11.9", "2.11.9", "amd64") == _SITES299["caddy"]["assets"]["amd64"]["url"]),
       ([], True, True, True))
    eq("helper verbs: website database names are ws<id>_<slug> in the helper's and the panel's allow lists, with "
       "game databases unchanged and other names still refused",
       [bool(_re299.fullmatch(_H299.DB_NAME_RE, n)) and bool(_re299.fullmatch(_priv299.DB_NAME_RE, n))
        for n in ("ws12_wordpress", "gs3_luckperms", "ws0_x", "wsx_y", "mysql", "ws12_Bad")],
       [True, True, False, False, False, False])


class _Pw299:
    def __init__(self, names):
        self.names = names

    def getpwnam(self, name):
        if name not in self.names:
            raise KeyError(name)
        return __import__("types").SimpleNamespace(pw_name=name, pw_uid=self.names[name], pw_gid=self.names[name],
                                                   pw_dir="/home/" + name)


class _Sub299:
    """A stand-in for the helper's subprocess: records every argv and runs nothing."""
    TimeoutExpired = __import__("subprocess").TimeoutExpired

    def __init__(self):
        self.calls = []

    def run(self, argv, **_kw):
        self.calls.append(list(argv))
        return __import__("types").SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


def _with_helper299(fn, pw_names, mark_names=()):
    saved = (_H299.pwd, _H299.subprocess, _H299.WEB_MARK_DIR, _H299._addon_forget_account, _H299._forget_account_tmp)
    sub = _Sub299()
    d = _tf299.mkdtemp(prefix="ww2-p299-")
    for name in mark_names:
        open(os.path.join(d, name), "w").close()
    _H299.pwd, _H299.subprocess, _H299.WEB_MARK_DIR = _Pw299(pw_names), sub, d
    _H299._addon_forget_account = _H299._forget_account_tmp = lambda *_a: 0
    try:
        try:
            rc = fn()
        except Exception as e:  # noqa: BLE001 - a verb that goes further than it should is a result, not a crash
            rc = "raised %s" % type(e).__name__
        return rc, sub.calls
    finally:
        (_H299.pwd, _H299.subprocess, _H299.WEB_MARK_DIR, _H299._addon_forget_account,
         _H299._forget_account_tmp) = saved
        __import__("shutil").rmtree(d, ignore_errors=True)


def _s299_helper_accounts():
    rc, calls = _with_helper299(lambda: _H299.do_website_account_create(["ws7"], ""), {"ws7": 1007})
    eq("website-account-create (verb): an existing account the panel did not make (no mark) is refused and nothing "
       "runs: an operator's own `ws7` is never adopted", (rc, calls), (1, []))
    rc, calls = _with_helper299(lambda: _H299.do_website_account_remove(["ws7"], ""), {"ws7": 1007})
    eq("website-account-remove (verb): an account without the panel's mark is refused and nothing runs",
       (rc, calls), (1, []))
    rc, calls = _with_helper299(lambda: _H299.do_website_quota_set(["ws7", "100"], ""), {"ws7": 1007})
    eq("website-quota-set (verb): an account without the panel's mark is refused", (rc, calls), (1, []))
    if os.geteuid() == 0:
        check_name = "website-account-remove (verb): an account with the mark (owned by root) goes through userdel -r"
        rc, calls = _with_helper299(lambda: _H299.do_website_account_remove(["ws7"], ""), {"ws7": 1007}, ["ws7"])
        eq(check_name, any(c[-2:] == ["-r", "ws7"] for c in calls), True)
    else:
        from unit.part01 import skip
        skip("website-account-remove (verb): an account with the mark (owned by root) goes through userdel -r",
             "the mark must be owned by root, and this run is not root")


def _s299_helper_apply():
    head = _H299.WEB_CONF_HEAD + ": x\n"
    cases = {
        "not the panel's file": '{"caddyfile": "admin localhost:2019\\n"}',
        "a cert name with a path": _json299.dumps({"caddyfile": head, "files": {"../../etc/x.crt": "x"}}),
        "a cert that is not PEM": _json299.dumps({"caddyfile": head, "files": {"a.example.org.crt": "rm -rf /"}}),
        "an extra key": _json299.dumps({"caddyfile": head, "run": "id"}),
        "not JSON": "caddyfile",
    }
    let = [k for k, doc in cases.items() if not _refused299(_H299._web_apply_doc, doc)]
    pem = "-----BEGIN CERTIFICATE-----\n" + "A" * 64 + "\n-----END CERTIFICATE-----\n"
    good = _H299._web_apply_doc(_json299.dumps({"caddyfile": head, "files": {"a.example.org.crt": pem}}))
    eq("website-proxy-apply (verb): a configuration the panel did not write, a certificate name with a path, a "
       "file that is not PEM, an unknown key and a non-JSON document are refused; the panel's own passes",
       (let, sorted(good[1])), ([], ["a.example.org.crt"]))
    doc = _smw299.apply_doc(_wp299.render([_site299()], None, None, secret_of=lambda s: _TOKEN299), [_site299()])
    eq("website-proxy-apply (caller): ssh_manager's document for the renderer's output is one the helper accepts",
       _refused299(_H299._web_apply_doc, doc), False)


def _s299_helper_guard():
    rules = _H299.web_guard_ruleset([1005, 1006])
    lines = [ln.strip() for ln in rules.split("\n")]
    eq("egress guard: only the site accounts' uids, loopback addresses allowed first, then every other address of "
       "this host and the private, link-local, tailnet, mapped and NAT64 ranges dropped (never 'oif lo', which a "
       "packet to the host's own tailnet address leaves by)",
       ("elements = { 1005, 1006 }" in lines, [ln for ln in lines if ln in (
           "meta skuid != @site_uids accept", "ip daddr 127.0.0.0/8 accept", "fib daddr type local counter drop")]
        == ["meta skuid != @site_uids accept", "ip daddr 127.0.0.0/8 accept", "fib daddr type local counter drop"],
        'oif "lo" accept' in lines, any("100.64.0.0/10" in ln and "192.168.0.0/16" in ln for ln in lines),
        any("fc00::/7" in ln and "::ffff:0:0/96" in ln for ln in lines),
        lines[1:3] == ["table inet lgsm_web {}", "delete table inet lgsm_web"]),
       (True, True, False, True, True, True))


def _s299_helper_guard2():
    unit = _H299.WEB_PROXY_UNIT_TEXT
    eq("web proxy unit: its own user, CAP_NET_BIND_SERVICE alone, no new privileges, a read-only system with only "
       "its state writable, the config's admin API off",
       [k for k in ("User=lgsmweb", "AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
                    "NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true",
                    "ReadWritePaths=/var/lib/lgsm-web-proxy", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX")
        if k not in unit.split("\n")],
       [])
    eq("helper verbs: the website verbs are local-only in the panel's table (no shell form reproduces them), and "
       "the apply document travels on the helper's stdin",
       (sorted(v for v in _priv299.verbs() if v.startswith("website-") and v not in _priv299.LOCAL_ONLY_VERBS),
        sorted(_pws299.STDIN_VERBS), "website-proxy-apply" in _H299.STDIN_VERBS),
       ([], ["website-proxy-apply"], True))


# ── 5. the SSH layer and the firewall label ─────────────────────────────────────────────────────


class _Core299:
    """Stands in for ssh_manager._core inside ssh_manager.websites: the local host, a helper, recorded verbs."""

    def __init__(self, ufw_out="", local=True):
        self.calls, self.ufw_out, self.local = [], ufw_out, local

    def is_local_server(self, _remote):
        return self.local

    def helper_present(self):
        return True

    def run_privileged(self, _remote, verb, args=(), **_kw):
        self.calls.append((verb, list(args)))
        return (self.ufw_out, "", 0) if verb == "ufw-status" else ("", "", 0)


def _with_core299(core, fn):
    saved = _smw299._core
    _smw299._core = core
    try:
        return fn()
    finally:
        _smw299._core = saved


_UFW299 = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # lgsmpanel-websites
[ 3] 443/tcp                    ALLOW IN    Anywhere                   # lgsmpanel-websites
[ 4] 80/tcp                     ALLOW IN    Anywhere                   # someone else's
[ 5] 80/tcp (v6)                ALLOW IN    Anywhere (v6)              # lgsmpanel-websites
"""


def _s299_ports():
    core = _Core299(_UFW299)
    ok, _t = _with_core299(core, lambda: _smw299.ports_apply(None, _proxy299("restricted", ["203.0.113.0/24"]), True))
    eq("ports (ports_apply): switching to restricted adds the allow-list rules with the label and removes the open-to-"
       "all ones, IPv4 and IPv6 alike, never touching an unlabelled rule",
       (ok, [c for c in core.calls if c[0] != "ufw-status"]),
       (True, [("ufw-allow-from-port", ["203.0.113.0/24", "443", "tcp", "lgsmpanel-websites"]),
               ("ufw-allow-from-port", ["203.0.113.0/24", "80", "tcp", "lgsmpanel-websites"]),
               ("ufw-delete-allow-proto-port", ["tcp", "443"]), ("ufw-delete-allow-proto-port", ["tcp", "80"])]))


def _s299_ports1b():
    core = _Core299(_UFW299)
    _with_core299(core, lambda: _smw299.ports_apply(None, _proxy299("public"), False))
    eq("ports (ports_apply): the last site disabled removes both labelled rules", [c for c in core.calls if c[0] != "ufw-status"],
       [("ufw-delete-allow-proto-port", ["tcp", "443"]), ("ufw-delete-allow-proto-port", ["tcp", "80"])])
    core = _Core299(_UFW299)
    _with_core299(core, lambda: _smw299.ports_apply(None, _proxy299("tunnel", provider="cloudflare"), True))
    eq("ports (ports_apply): tunnel mode opens nothing and closes what was open",
       len([c for c in core.calls if c[0].startswith("ufw-delete")]) == 2 and not [c for c in core.calls if
                                                                                    c[0].startswith("ufw-allow")], True)
    core = _Core299(_UFW299)
    _with_core299(core, lambda: _smw299.ports_apply(None, _proxy299("public"), True))
    eq("ports (ports_apply): public with the rules already there changes nothing (control)",
       [c for c in core.calls if c[0] != "ufw-status"], [])


def _s299_ports2():
    core = _Core299(_UFW299, local=False)
    eq("ssh layer: a managed host is refused in words before anything is sent",
       (_with_core299(core, lambda: _smw299.ports_apply(None, _proxy299("public"), True)),
        _with_core299(core, lambda: _smw299.egress_guard(None)), core.calls),
       ((False, _smw299.ONLY_LOCAL), (False, _smw299.ONLY_LOCAL), []))
    groups = [{"comment": "lgsmpanel-websites", "port_num": "443", "proto_label": "TCP", "action": "ALLOW"},
              {"comment": "lgsmpanel-websites", "port_num": "22", "proto_label": "TCP", "action": "ALLOW"},
              {"comment": "something", "port_num": "80", "proto_label": "TCP", "action": "ALLOW"}]
    eq("firewall: a labelled 80/443 rule is marked as the websites' on purpose; the label on SSH's port is ignored",
       [g.get("intentional") for g in _fw299.mark_intentional_rules(groups)], ["websites", None, None])


# ── 6. the recipe engine ────────────────────────────────────────────────────────────────────────



def _values299(site):
    return _wr299.values_for(site, db={"name": "ws5_app", "user": "ws5_app", "password": "Dbpass-" + "x" * 20},
                             admin={"user": "admin", "email": "admin@example.org", "password": "Admin-" + "y" * 20,
                                    "site_name": "My site"}, domains=["blog.example.org"])


_RECIPE_OUT299 = {}


def _recipe_out299():
    """(values, {(recipe, step name): (shell, stdin)}) for every step of the four shipped recipes, built once."""
    if not _RECIPE_OUT299:
        vals = dict(_values299(_site299(kind="wordpress")), _uid="1005", _gid="1005",
                    _network="pasta:-4,-o,127.0.0.1,-T,3306:3306")
        out = {}
        for name in ("wordpress", "phpbb", "drupal", "mybb", "smf"):
            recipe = _wc299.recipe(name)
            for step in _ws299.recipe_steps(recipe):
                body, stdin = _wr299.step_sh("ws5", _site299(kind=recipe["kind"]), step, vals, recipe=recipe,
                                             token=_TOKEN299)
                out[(name, step["name"])] = (body, stdin or "")
        _RECIPE_OUT299.update(vals=vals, out=out)
    return _RECIPE_OUT299["vals"], _RECIPE_OUT299["out"]


def _s299_recipe_steps():
    vals, out = _recipe_out299()
    leaks = [k for k, (body, _i) in out.items() if any(sec in body for sec in (vals["db_password"], vals["admin_password"],
                                                                                _TOKEN299))]
    eq("recipes: no step of the five shipped recipes puts the database password, the admin password or the proxy "
       "token in its shell text (they go on stdin)", leaks, [])
    dl_body = out[("phpbb", "download-verify-unpack-1")][0]
    eq("recipes (download): https only with size and time caps, the sha256 checked BEFORE the unpacker runs, a "
       "mismatch deleting the download, and a site with files refused",
       ("--proto =https" in dl_body, "--max-filesize" in dl_body, dl_body.index("sha256sum -c") < dl_body.index("python3 -I"),
        "SITE_SHA_MISMATCH" in dl_body, "SITE_NOT_EMPTY" in dl_body),
       (True, True, True, True, True))
    wp_install = out[("wordpress", "run-in-container-3")]
    eq("recipes (WordPress): wp core install reads the admin password from its prompt on stdin, in a one-off "
       "container with every capability dropped, a read-only root and no DNS",
       ("--prompt=admin_password" in wp_install[0], "--cap-drop=all" in wp_install[0], "--read-only" in wp_install[0],
        "--dns=none" in wp_install[0], any(ln.startswith("in ") for ln in wp_install[1].splitlines())),
       (True, True, True, True, True))


def _s299_recipe_steps2():
    _vals, out = _recipe_out299()
    cfg = _wr299.render_template("define('A','{db_password}'); define('S','{salt}'); define('T','{salt}');",
                                 {"db_password": "a'b\\c"}, "php")
    salts = _re299.findall(r"define\('[ST]','([^']+)'\)", cfg)
    eq("recipes (config): a value is escaped for a PHP string, and every salt is a fresh 64-character value from the "
       "CSPRNG", ("define('A','a\\'b\\\\c');" in cfg, len(salts), len(set(salts)), [len(x) for x in salts]),
       (True, 2, 2, [64, 64]))
    inst = out[("mybb", "drive-web-installer-2")]
    eq("recipes (web installer): every page on the site's loopback port with the proxy token from a file, secret fields "
       "sent from files, each page's expected text checked",
       ("http://127.0.0.1:20005/install/index.php" in inst[0], '-H "@$d/token"' in inst[0],
        '"config[mysqli][dbpass]@$d/db_password"' in inst[0], inst[0].count("grep -qF --") == 10,
        "token " in inst[1]), (True, True, True, True, True))
    perm = out[("phpbb", "set-permissions-4")]
    eq("recipes (hardening): the installer folder removed and checked gone, then its path must answer 404",
       ("rm -rf -- site/html/install" in perm[0], "SITE_INSTALLER_LEFT" in perm[0], '[ "$c" = 404 ]' in perm[0]),
       (True, True, True))


def _s299_recipe_steps3():
    site = _site299(kind="wordpress")
    undo = {s["type"]: _ws299.undo_sh("ws5", site, s) for s in _ws299.recipe_steps(_wc299.recipe("phpbb"))}
    eq("recipes (undo): the download's undo empties the site's files, a config's removes it, the database's is "
       "the job's (Databases code)",
       ("find site/html -mindepth 1 -delete" in undo["download-verify-unpack"], "rm -f -- site/html/install/panel-install.yml"
        in undo["render-config"], undo["create-database"]), (True, True, ""))
    try:
        _wr299.values_for(site, admin={"user": "a b", "email": "x", "password": "short", "site_name": "x"})
        bad_admin = False
    except ValueError:
        bad_admin = True
    eq("recipes: an admin name, email, short password or a site title with shell characters is refused",
       (bad_admin, _refused299(_wr299.values_for, site, None, {"user": "admin", "email": "a@example.org",
                                                               "password": "p" * 16, "site_name": "x$(id)"})),
       (True, True))


def _unpack299(build, strip=""):
    """Run the recipe's unpacker (python3 -I) on an archive `build(path)` writes; (rc, output, files left)."""
    d = _tf299.mkdtemp(prefix="ww2-unpack-")
    try:
        arc, dest = os.path.join(d, "a"), os.path.join(d, "html")
        os.makedirs(dest)
        build(arc)
        r = _sp299.run([_sys299.executable, "-I", "-c", _wr299.UNPACK_PY, arc, dest, strip],  # nosec B603 - fixed argv
                       capture_output=True, text=True, timeout=60, check=False)
        left = sorted(os.path.relpath(os.path.join(dp, f), dest) for dp, _dn, fs in os.walk(dest) for f in fs)
        return r.returncode, r.stdout.strip(), left
    finally:
        __import__("shutil").rmtree(d, ignore_errors=True)


def _zip_with299(entries):
    def build(path):
        with _zip299.ZipFile(path, "w") as z:
            for name, data, mode in entries:
                info = _zip299.ZipInfo(name)
                if mode:
                    info.external_attr = mode << 16
                z.writestr(info, data)
    return build


def _s299_unpacker():
    ok = _unpack299(_zip_with299([("phpBB3/index.php", "<?php", 0), ("phpBB3/inc/a.php", "x", 0), ("docs/x", "y", 0)]),
                    "phpBB3")
    eq("unpacker (real archive): the release's folder is stripped and only its files land in the site (control)",
       (ok[0], ok[2]), (0, ["inc/a.php", "index.php"]))
    slip = _unpack299(_zip_with299([("../../evil.php", "x", 0)]))
    absolute = _unpack299(_zip_with299([("/etc/evil", "x", 0)]))
    link = _unpack299(_zip_with299([("a/link", "/etc/passwd", 0o120777)]), "a")
    eq("unpacker (real archives): a `..` entry, an absolute path and a symbolic link are each refused",
       [(r[0], r[1].split(" ")[0]) for r in (slip, absolute, link)],
       [(26, "SITE_UNPACK_FAILED"), (26, "SITE_UNPACK_FAILED"), (26, "SITE_UNPACK_FAILED")])
    deep = _unpack299(_zip_with299([("/".join(["d"] * 40) + "/f", "x", 0)]))
    eq("unpacker (real archive): a path deeper than the cap is refused", deep[0], 26)


def _s299_egress():
    allowed = frozenset({"api.wordpress.org", "downloads.wordpress.org"})
    eq("egress proxy: only CONNECT to a listed host on 443",
       [_eg299.target(line, allowed) for line in ("CONNECT api.wordpress.org:443 HTTP/1.1", "CONNECT api.wordpress.org:80 HTTP/1.1",
                                                  "CONNECT evil.example:443 HTTP/1.1", "GET http://api.wordpress.org/ HTTP/1.1",
                                                  "CONNECT 127.0.0.1:443 HTTP/1.1", "CONNECT API.WORDPRESS.ORG:443 HTTP/1.1")],
       [("api.wordpress.org", 443), None, None, None, None, ("api.wordpress.org", 443)])

    def fake(addrs):
        return lambda host, port, type=None: [(None, None, None, None, (a, port)) for a in addrs]  # noqa: A002
    eq("egress proxy: a listed name that resolves to a loopback, private, link-local, tailnet, mapped or NAT64 "
       "address is refused (all or nothing); a public one is connected to",
       [_eg299.resolve("h", 443, fake(a)) for a in (["127.0.0.1"], ["10.1.2.3"], ["169.254.169.254"], ["100.100.1.1"],
                                                     ["::ffff:10.0.0.1"], ["64:ff9b::a00:1"], ["198.51.100.7", "10.0.0.1"],
                                                     ["93.184.215.14"])],
       [[], [], [], [], [], [], [], ["93.184.215.14"]])


# ── 7. the page cache build, the CPU fallback, the image scan and the Cloudflare list ────────────
_AI_SPEC299 = _ilu299.spec_from_file_location("addon_images_p299", os.path.join(_root, ".github", "scripts", "addon_images.py"))
_AI299 = _ilu299.module_from_spec(_AI_SPEC299)
_AI_SPEC299.loader.exec_module(_AI299)
_CF_SPEC299 = _ilu299.spec_from_file_location("cloudflare_ranges_p299",
                                              os.path.join(_root, ".github", "scripts", "cloudflare_ranges.py"))
_CF299 = _ilu299.module_from_spec(_CF_SPEC299)
_CF_SPEC299.loader.exec_module(_CF299)
_CACHE_CF299 = os.path.join(_root, "panel", "website_images", "caddy-cache", "Containerfile")


def _s299_cache_build():
    with open(_CACHE_CF299, encoding="utf-8") as fh:
        text = fh.read()
    c = _SITES299["caddy_cache"]
    eq("page cache build: the helper builds from its own copy of the Containerfile (equal to the repository's, which "
       "CI builds and scans), no ARG has a default, every ARG comes from the catalog, the module at an exact version, "
       "Go's checksum database on",
       (_H299.WEB_CACHE_CONTAINERFILE == text, _AI299.defaulted_args(text),
        _AI299.unsupplied_args(text, _AI299.site_build_args("caddy-cache", _SITES299)), c["module"], c["caddy"],
        bool(_re299.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", c["version"])), "GOSUMDB=sum.golang.org" in text),
       (True, [], [], "github.com/caddyserver/cache-handler", _SITES299["caddy"]["version"], True, True))
    bad = {"a tag, not a digest": _bad299(("caddy_cache", "builder"), "docker.io/library/caddy:2-builder"),
           "another module": _bad299(("caddy_cache", "module"), "github.com/example/evil"),
           "a moving version": _bad299(("caddy_cache", "version"), "latest"),
           "another Caddy than the proxy's": _bad299(("caddy_cache", "caddy"), "2.10.0")}
    eq("page cache build (catalog): a builder by tag, another module, a moving version and another Caddy release are "
       "each refused", sorted(k for k, d in bad.items() if not _wc299.sites_problems(d)), [])
    eq("page cache build (verb): images by digest only, the module's version exact, in both tables",
       [_refused299(_H299.validate, "website-proxy-install-cache", a) for a in (
           ["2.11.9", "docker.io/library/caddy:2", c["base"], "v0.17.0"], ["2.11.9", c["builder"], c["base"], "main"])]
       + [_refused299(_priv299.check_args, "website-proxy-install-cache", ["2.11.9", c["builder"], c["base"], "main"])],
       [True, True, True])
    saved = _H299.WEB_PROXY_BIN
    _H299.WEB_PROXY_BIN = os.path.join(_root, "tests", "no-such-proxy-binary")
    try:
        rc, calls = _with_helper299(lambda: _H299.do_website_proxy_install_cache(
            ["2.11.9", c["builder"], c["base"], c["version"]], ""), {"lgsmweb": 990})
    finally:
        _H299.WEB_PROXY_BIN = saved
    eq("page cache build (verb): with no plain proxy installed it refuses before any build runs", (rc, calls), (1, []))


class _OsSpy299:
    """Stand in for the helper's os module, recording owners and the mode a file has while it is written.

    fchown and chown are recorded, not done (they need root); a rename carries the record along.
    """

    def __init__(self):
        self.owners, self.write_modes = {}, []

    def __getattr__(self, name):
        return getattr(os, name)

    def fchown(self, fd, uid, gid):
        self.owners[os.readlink("/proc/self/fd/%d" % fd)] = (uid, gid)

    def chown(self, path, uid, gid):
        self.owners[path] = (uid, gid)

    def replace(self, src, dst):
        os.replace(src, dst)
        if src in self.owners:
            self.owners[dst] = self.owners.pop(src)

    def write(self, fd, data):
        self.write_modes.append(_stat299.S_IMODE(os.fstat(fd).st_mode))
        return os.write(fd, data)


class _CurlSub299(_Sub299):
    """The helper's subprocess with curl writing `archive` to its -o path; everything else succeeds."""

    def __init__(self, archive):
        super().__init__()
        self.archive = archive

    def run(self, argv, *_a, **_kw):
        if "-o" in argv:
            with open(argv[argv.index("-o") + 1], "wb") as fh:
                fh.write(self.archive)
        return super().run(argv)


_WEB_PATHS299 = {"WEB_PROXY_DIR": "lib", "WEB_PROXY_BIN": "lib/caddy", "WEB_PROXY_ETC": "etc",
                 "WEB_PROXY_CONF": "etc/Caddyfile", "WEB_PROXY_CERTS": "etc/certs", "WEB_PROXY_STATE": "state",
                 "WEB_PROXY_UNIT_FILE": "units/proxy.service", "WEB_JOURNAL_CONF": "units/journald.conf",
                 "WEB_GUARD_FILE": "etc/egress-guard.nft", "WEB_GUARD_UNIT_FILE": "units/guard.service",
                 "WEB_MARK_DIR": "marks", "WEB_REBIND_UNIT_FILE": "units/rebind.service",
                 "WEB_REBIND_TIMER_FILE": "units/rebind.timer"}


def _web_files299(verbs):
    """Run the proxy's verbs in a scratch tree: (return codes, {file: (mode, owner)}, modes while written)."""
    d, build = _tf299.mkdtemp(prefix="wsf-p299-"), _tf299.mkdtemp(prefix="wsf-p299b-")
    names = tuple(_WEB_PATHS299) + ("pwd", "subprocess", "os", "resolve", "_web_arch", "_web_cache_build",
                                     "_web_has_cache", "_web_bind", "_web_running")
    saved = {n: getattr(_H299, n) for n in names}
    spy, buf = _OsSpy299(), _io299.BytesIO()
    with _tar299.open(fileobj=buf, mode="w:gz") as tar:
        info = _tar299.TarInfo("caddy")
        info.size = 4
        tar.addfile(info, _io299.BytesIO(b"ELF!"))
    with open(os.path.join(build, "caddy"), "wb") as fh:
        fh.write(b"ELF+cache")
    try:
        for n, rel in _WEB_PATHS299.items():
            setattr(_H299, n, os.path.join(d, rel))
        for sub in ("units", "marks"):
            os.makedirs(os.path.join(d, sub))
        _H299.pwd, _H299.subprocess, _H299.os = _Pw299({"lgsmweb": 990}), _CurlSub299(buf.getvalue()), spy
        _H299.resolve, _H299._web_arch = (lambda prog: "/usr/bin/" + prog), (lambda: "amd64")
        _H299._web_cache_build, _H299._web_has_cache = (lambda _a, _d: os.path.join(build, "caddy")), (lambda _b, _p: True)
        # The host's addresses and the unit's state are part302's to drive: here, one address and a running proxy.
        _H299._web_bind, _H299._web_running = (lambda text: (text, ["192.0.2.10"])), (lambda: True)
        with _ctx299.redirect_stdout(_io299.StringIO()), _ctx299.redirect_stderr(_io299.StringIO()):
            rcs = [fn(_hashlib299.sha256(buf.getvalue()).hexdigest()) for fn in verbs]
        files = {}
        for top, _dirs, found in os.walk(d):
            for f in found:
                path = os.path.join(top, f)
                files[os.path.relpath(path, d)] = (oct(_stat299.S_IMODE(os.stat(path).st_mode)), spy.owners.get(path))
        return rcs, files, sorted(set(spy.write_modes))
    finally:
        for n, v in saved.items():
            setattr(_H299, n, v)
        __import__("shutil").rmtree(d, ignore_errors=True)
        __import__("shutil").rmtree(build, ignore_errors=True)


def _s299_helper_modes():
    pem = "-----BEGIN CERTIFICATE-----\n" + "A" * 64 + "\n-----END CERTIFICATE-----\n"
    doc = _json299.dumps({"caddyfile": _H299.WEB_CONF_HEAD + ": x\n", "files": {"a.example.org.crt": pem}})
    rcs, files, writing = _web_files299([
        lambda sha: _H299.do_website_proxy_install(["2.11.9", "amd64", sha], ""),
        lambda _sha: _H299.do_website_proxy_apply(["start"], doc),
        lambda _sha: _H299.do_website_proxy_install_cache(["2.11.9", "b@sha256:" + "1" * 64, "c@sha256:" + "2" * 64,
                                                           "v0.17.0"], ""),
        lambda _sha: _H299.do_website_egress_guard(["on"], "")])
    proxy, root = ("0o640", (0, 990)), ("0o600", (0, 0))
    eq("web proxy files (install, apply, cache build and egress guard verbs): the binary runs only as root and the "
       "proxy's group (0750), the proxy reads its configuration and certificates through its group but cannot change "
       "them (root-owned 0640), the units (the address re-read's too), journald's drop-in and the guard's ruleset "
       "are root's alone (0600)",
       (rcs, files), ([0, 0, 0, 0], {"lib/caddy": ("0o750", (0, 990)), "etc/Caddyfile": proxy,
                                     "etc/certs/a.example.org.crt": proxy, "etc/egress-guard.nft": root,
                                     "units/proxy.service": root, "units/journald.conf": root,
                                     "units/guard.service": root, "units/rebind.service": root,
                                     "units/rebind.timer": root}))
    eq("web proxy files: every file is owner-only (0600) while its bytes are written; its final mode comes after",
       writing, [0o600])


class _CpuCore299(_Core299):
    def __init__(self, rc):
        super().__init__("")
        self.rc = rc

    def run_privileged(self, _remote, verb, args=(), **_kw):
        self.calls.append((verb, list(args)))
        return "", "", self.rc


def _s299_cpu():
    site = _site299()
    q = _ws299.quadlet(site, (1, 1), "pasta:-4", image="x/y@sha256:" + "a" * 64, cpu=False)
    eq("CPU fallback (unit): without the cpu controller the container's --cpus is left out (it would fail to start)",
       ("--cpus" in q, "--cpus=1.50" in _ws299.quadlet(site, (1, 1), "pasta:-4", image="x/y@sha256:" + "a" * 64)),
       (False, True))
    eq("CPU fallback (probe): the account's delegated controllers are read back",
       (_ws299.parse_probe("cpu_delegated=1\n")["cpu_delegated"], _ws299.parse_probe("uid=5\n")["cpu_delegated"],
        "cgroup.controllers" in _ws299.probe_sh("ws5", site)), (True, False, True))
    results = []
    for delegated, rc in ((True, 0), (False, 0), (False, 1)):
        core = _CpuCore299(rc)
        got = _with_core299(core, lambda: _smw299.cpu_limit(None, site, {"cpu_delegated": delegated}))
        results.append((got, core.calls))
    eq("CPU fallback (cpu_limit): the container's own limit where delegated; else the account's slice through the "
       "helper; and when that fails it says none, never silently unlimited",
       results, [((True, "container"), []), ((True, "account"), [("website-cpu-limit", ["ws5", "1500"])]),
                 ((False, "none"), [("website-cpu-limit", ["ws5", "1500"])])])
    rc, calls = _with_helper299(lambda: _H299.do_website_cpu_limit(["ws7", "1500"], ""), {"ws7": 1007})
    eq("website-cpu-limit (verb): an account without the panel's mark is refused and nothing runs", (rc, calls), (1, []))
    eq("CPU fallback: each mode has a sentence the site card shows (an unknown one reads as none)",
       (sorted(_ws299.CPU_MODES), _smw299.cpu_note("account") == _ws299.CPU_MODES["account"],
        _smw299.cpu_note("?") == _ws299.CPU_MODES["none"]), (["account", "container", "none"], True, True))


def _floor_digests299():
    """Every image of the floor's sites section (the pulled ones; the cache build's images are built from)."""
    out = [_SITES299["static"]["image"], _SITES299["wpcli"]["image"], _SITES299["object_cache"]["image"]]
    out += [e["image"] for e in _SITES299["php"].values()] + [e["image"] for e in _SITES299["wordpress"]["php"].values()]
    out += [e["image"] for e in _SITES299["tunnel"].values()]
    return out + [e["image"] for r in _SITES299["runtimes"].values() for e in r["versions"].values()]


def _s299_image_scan():
    p = _AI299.plan()
    sites_up = p["sites"]["upstream"]
    want = set(_floor_digests299())
    eq("image scan (plan): every image of the catalog's sites section is pulled and scanned, the page cache's proxy is "
       "built from the catalog's values, nothing wrong on this tree",
       (set(sites_up.values()) == want, sorted(p["sites"]["builds"]), [n for n, _v in p["sites"]["builds"]["caddy-cache"]],
        p["problems"]),
       (True, ["caddy-cache"] + sorted("php@" + v for v in _SITES299["php"]),
        ["BUILDER_IMAGE", "BASE_IMAGE", "CADDY_VERSION", "CACHE_MODULE", "CACHE_VERSION"], []))
    seen, real_run = [], _AI299._run
    _AI299._run = lambda argv, **kw: seen.append(argv) or 0
    try:
        _AI299._images(dict(p, upstream={}, builds={}, sites=dict(p["sites"], upstream={})), _tf299.gettempdir(), [])
    finally:
        _AI299._run = real_run
    build = [a for a in seen if a[:2] == ["docker", "build"]]
    eq("image scan (_images): the page cache's proxy is built from panel/website_images with every catalog value as a "
       "--build-arg, and hadolint lints its Containerfile",
       (len(build), sum(1 for f in build[0] if f == "--build-arg") if build else 0,
        any(t.endswith(os.path.join("website_images", "caddy-cache", "Containerfile")) for _l, t in _AI299.lint_targets(p))),
       (1 + len(_SITES299["php"]), 5, True))


def _s299_image_scan2():
    bad_cat = dict(_FLOOR_DOC299, sites=_bad299(("php", "8.4", "image"), "docker.io/library/php:8.4-apache"))
    d = _tf299.mkdtemp(prefix="ww2-scan-")
    try:
        path = os.path.join(d, "catalog.json")
        with open(path, "w", encoding="utf-8") as fh:
            _json299.dump(bad_cat, fh)
        probs = _AI299.plan(path, os.path.join(_root, "panel", "addon_images"))["problems"]
    finally:
        __import__("shutil").rmtree(d, ignore_errors=True)
    eq("image scan (plan): a sites image pinned by tag stops the scan before anything is pulled",
       any("sites-php-8.4" in x for x in probs), True)


def _s299_cloudflare():
    lists = {_CF299.URLS[0]: "173.245.48.0/20\n103.21.244.0/22\n", _CF299.URLS[1]: "2400:cb00::/32\n"}
    hostile = ["10.0.0.0/8\n", "173.245.48.1/20\n", "0.0.0.0/0\n", "173.245.48.0/20; rm -rf /\n", ""]
    eq("cloudflare ranges: a private, non-canonical, too-wide, malformed or empty list is refused",
       [_refused299(_CF299.networks, t) for t in hostile], [True] * 5)
    d = _tf299.mkdtemp(prefix="ww2-cf-")
    try:
        path = os.path.join(d, "catalog.json")
        with open(path, "w", encoding="utf-8") as fh:
            _json299.dump(_FLOOR_DOC299, fh, indent=2, sort_keys=True)
            fh.write("\n")
        rc = _CF299.main(["x", "check"], fetcher=lists.get, catalog=path)
        with open(path, encoding="utf-8") as fh:
            got = _json299.load(fh)["sites"]["presets"]["cloudflare"]
        rc2 = _CF299.main(["x", "check"], fetcher=lambda u: "10.0.0.0/8\n", catalog=path)
        with open(path, encoding="utf-8") as fh:
            after = _json299.load(fh)["sites"]["presets"]["cloudflare"]
    finally:
        __import__("shutil").rmtree(d, ignore_errors=True)
    eq("cloudflare ranges (main): published lists that pass replace the catalog's preset (and the result passes the "
       "panel's own check); a bad list changes nothing",
       (rc, got, rc2, after, _wc299.sites_problems(dict(_SITES299, presets={"cloudflare": got}))),
       (0, ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"], 1, got, []))
    eq("cloudflare ranges: only the two fixed https URLs are ever fetched", _refused299(_CF299.fetch, "https://evil.example/ips"),
       True)


def _unb64_299(word):
    """`word` decoded from base64 when it is valid base64, else ""."""
    import binascii
    try:
        return __import__("base64").b64decode(word, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return ""


def _s299_w3_calls():
    sent = []
    saved = (_smw299._as_site, _smw299._ids, _smw299._secret, _smw299._core)
    _smw299._as_site = lambda remote, acct, body, timeout=0, stdin_text=None: sent.append((body, stdin_text or "")) or (True, "")
    _smw299._ids = lambda remote, site: ((1005, 1005), {"splice": False})
    _smw299._secret = lambda value: _TOKEN299
    _smw299._core = _Core299("")
    secrets = {"admin_user": "siteowner", "admin_email": "owner@example.org", "admin_password": "Gen-" + "z" * 20,
               "db_name": "ws5_app", "db_user": "ws5_app", "db_password": "Db-" + "q" * 24}
    site = _site299(kind="wordpress", app_recipe="wordpress")
    try:
        steps = _ws299.recipe_steps("wordpress")
        results = [_smw299.app_install_step(None, site, dict(st, secrets=dict(secrets))) for st in steps]
        mybb = [st for st in _ws299.recipe_steps("mybb") if st["type"] == "drive-web-installer"][0]
        results.append(_smw299.app_install_step(None, _site299(kind="php", app_recipe="mybb"), dict(mybb, secrets=dict(secrets))))
        logs = _smw299.site_logs(None, site)
    finally:
        _smw299._as_site, _smw299._ids, _smw299._secret, _smw299._core = saved
    _w3_checks299(sent, secrets, results, logs)


def _w3_checks299(sent, secrets, results, logs):
    bodies = "".join(b for b, _i in sent)
    stdins = "".join(i for _b, i in sent)
    decoded = "".join(_unb64_299(w) for ln in stdins.splitlines() for w in ln.split()[1:])
    eq("install job (app_install_step, as W3 calls it with the step's secrets): every step runs, the admin and database "
       "passwords and the token never reach a shell command line, and they do reach the steps' stdin",
       (all(r[0] for r in results), any(x in bodies for x in (secrets["admin_password"], secrets["db_password"], _TOKEN299)),
        secrets["admin_password"] in decoded or secrets["admin_password"] in stdins,
        secrets["db_password"] in decoded or secrets["db_password"] in stdins),
       (True, False, True, True))
    eq("site logs (site_logs, the routes' log view): the site's containers' own journal lines, read as its account",
       (logs[0], "CONTAINER_NAME=lgsm-site" in sent[-1][0], "-n 500" in sent[-1][0], "sudo" in sent[-1][0]),
       (True, True, True, False))
    eq("recipe_steps by name (the routes pass the site's recipe name): the catalog's steps; an unknown name has none",
       (len(_ws299.recipe_steps("smf")), _ws299.recipe_steps("no-such-app")), (5, []))


for _step299 in (_s299_floor, _s299_refusals, _s299_stored, _s299_versions, _s299_generator, _s299_proxy_base,
                 _s299_proxy_modes, _s299_proxy_rules, _s299_quadlet, _s299_servers, _s299_php, _s299_app_cache_tunnel,
                 _s299_shell, _s299_helper_validators, _s299_helper_accounts, _s299_helper_apply, _s299_helper_guard,
                 _s299_ports, _s299_recipe_steps, _s299_unpacker, _s299_egress, _s299_proxy_base2, _s299_proxy_rules2,
                 _s299_helper_guard2, _s299_ports1b, _s299_ports2, _s299_recipe_steps2, _s299_recipe_steps3,
                 _s299_cache_build, _s299_helper_modes, _s299_cpu, _s299_image_scan, _s299_cloudflare, _s299_w3_calls, _s299_image_scan2):
    _step299()
