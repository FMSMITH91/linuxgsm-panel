"""Part 311 of the unit suite: fixes the websites' fifth proof round on the test host (P5) turned up.

1. Name lookups fail at once in every site container: each gets a read-only /etc/resolv.conf of the panel's that
   names no server (one try of one second). Podman's --dns=none had left the image's own file (WordPress's names
   1.1.1.1 and 1.0.0.1, unreachable from a site), and every lookup waited about 20 seconds. The site's network
   and its --dns=none stay as they were; an app's build and an app's install steps get the same file, and a site
   with full egress keeps Podman's name servers.
2. WordPress's scheduled tasks run from a timer of the site's account, in its running container, every 5 minutes;
   the recipe's wp-config turns off the run a visitor's request started (a request to the site's own name, which
   the visitor waited for, a 504 behind the page cache). The timer is written and started with the site and
   removed with it, by a delete and by an install's undo.
3. Re-applying tunnel mode clears the connector's start limit first, and a failure names the tunnel.
4. An app's build turns npm's update notice off, so the build log's last lines are the build's own.

HOW IT RUNS. part12's app and its database for the routes. ssh_manager.websites' seams answer for the host (Podman
ready, the helper, the account's ids), and every shell it would run as a site's account runs in real bash over a
scratch home, with stand-in podman and systemctl first on PATH that record their argv (systemctl models a unit's
start limit). Nothing reaches a host (part12's tripwire is armed).
"""
import json as _json311
import os
import shutil as _shutil311
import subprocess as _sp311  # nosec B404 - bash over the panel's own account shells, in a scratch home
import sys as _sys311
import tempfile as _tf311
from types import SimpleNamespace as _NS311

from flask import g as _g311

from unit.part01 import check, eq
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from panel.core import config as _cfg311
from panel.db.models import (RemoteServer as _Remote311, User as _User311, Website as _Site311,
                             WebsiteDomain as _Dom311, WebsiteProxy as _Proxy311, db as _db311)
from panel.ops.ssh_manager import websites as _sw311
from panel.routes import websites as _w311
from panel.routes import websites_apps as _wapps311
from panel.services import websites as _ws311

_TREE311 = _tf311.mkdtemp(prefix="lgsm-unit-p311-")
_BIN311 = os.path.join(_TREE311, "bin")
_CALLS311 = os.path.join(_TREE311, "calls.jsonl")
_TOKEN311 = "p" * 40
_REAL311 = {n: getattr(_sw311, n) for n in ("install", "remove", "tunnel_apply", "app_rebuild", "stop")}

# The stand-in tools. Each records its argv (one JSON line). systemctl models a unit's start limit: a unit with
# "$HOME/.limit-<unit>" is refused by start/restart until `reset-failed <unit>` removes it; FAKE_RESTART_RC fails
# every start. podman answers `image exists` with FAKE_IMAGE_EXISTS, a build with FAKE_BUILD_RC, and a run prints
# npm's update notice unless the run turns it off (as npm does at the end of a build).
_FAKE311 = r'''
import json, os, sys
argv = sys.argv[1:]
tool = os.path.basename(sys.argv[0])
home = os.environ.get("HOME", "")
rc = 0
if tool == "systemctl":
    units = [a for a in argv if a.endswith((".service", ".timer", ".socket"))]
    if "reset-failed" in argv:
        for u in units:
            p = os.path.join(home, ".limit-" + u)
            if os.path.exists(p):
                os.unlink(p)
    elif "start" in argv or "restart" in argv:
        if int(os.environ.get("FAKE_RESTART_RC", "0")) or any(os.path.exists(os.path.join(home, ".limit-" + u))
                                                              for u in units):
            rc = 1
    elif "show" in argv:
        sys.stdout.write("success\n")
elif tool == "podman":
    if argv[:2] == ["image", "exists"]:
        rc = int(os.environ.get("FAKE_IMAGE_EXISTS", "0"))
    elif argv[:1] == ["build"]:
        rc = int(os.environ.get("FAKE_BUILD_RC", "0"))
    elif argv[:1] == ["run"]:
        sys.stdout.write("added 12 packages\n")
        if "npm_config_update_notifier=false" not in argv:
            sys.stdout.write("npm notice To update run: npm install -g npm@99.0.0\n")
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps({"tool": tool, "argv": argv}) + "\n")
sys.exit(rc)
'''


def _tools311():
    os.makedirs(_BIN311, exist_ok=True)
    for name in ("podman", "systemctl", "journalctl"):
        path = os.path.join(_BIN311, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!%s\n%s" % (_sys311.executable, _FAKE311))
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
        os.chmod(path, 0o700)


def _home311(account):
    return os.path.join(_TREE311, "home", account)


_RUN311 = {"env": {}, "shells": []}


def _as_site311(remote, account, sh, timeout=120, stdin_text=None):
    """ssh_manager.websites._as_site over a scratch home: the panel's account shell in real bash."""
    _RUN311["shells"].append((account, sh))
    if not sh.startswith(_ws311._ENV):
        return False, "part311: not an account shell"
    home = _home311(account)
    os.makedirs(home, exist_ok=True)
    text = 'cd "$HOME" || exit 1; ' + sh[len(_ws311._ENV):].replace("/home/%s" % account, home)
    env = dict(os.environ, HOME=home, PATH=_BIN311 + os.pathsep + os.environ.get("PATH", ""), FAKE_CALLS=_CALLS311,
               **_RUN311["env"])
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp311.run(["bash", "-c", text], input=(stdin_text or "").encode(), capture_output=True, timeout=120,  # nosec B603 B607
                   env=env, check=False)
    return r.returncode == 0, r.stdout.decode("utf-8", "replace")


def _calls311(tool=None):
    if not os.path.exists(_CALLS311):
        return []
    with open(_CALLS311, encoding="utf-8") as fh:
        got = [_json311.loads(ln) for ln in fh if ln.strip()]
    return [c["argv"] for c in got if tool is None or c["tool"] == tool]


def _reset311(**env):
    if os.path.exists(_CALLS311):
        os.unlink(_CALLS311)
    _RUN311["env"] = {k: str(v) for k, v in env.items()}
    _RUN311["shells"] = []


def _read311(account, rel):
    path = os.path.join(_home311(account), rel)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _seams311():
    """The host's answers at ssh_manager.websites' own seams; every account shell runs in bash (_as_site311)."""
    for name in ("install", "remove", "app_rebuild", "stop"):
        _p9_patch(_sw311, name, _REAL311[name])
    _p9_patch(_sw311, "runtime_ready", lambda remote: "")
    _p9_patch(_sw311, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (True, "account=exists"))
    _p9_patch(_sw311, "_ids", lambda remote, site: ((1005, 1005), {"splice": True, "cpu_delegated": True, "os": "24.04",
                                                                   "podman": "podman version 4.9.3"}))
    _p9_patch(_sw311, "_as_site", _as_site311)


class _Client311:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g311.pop("_login_user", None)
        return self.c.post(*a, **k)


_ROWS311 = {"sites": [], "remotes": [], "users": []}


def _rows311():
    r = _Remote311(name="p311-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.77")
    su = _User311(username="p311-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db311.session.add_all([r, su])
    _db311.session.commit()
    _ROWS311["remotes"].append(r.id)
    _ROWS311["users"].append(su.id)
    return _NS311(host=r, su=su)


def _site311(st, name, kind="php", **kw):
    extra = {"php_version": "8.4"} if kind in _ws311.KINDS_PHP else {}
    s = _Site311(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg311.encrypt_secret(_TOKEN311), **dict(extra, **kw))
    _db311.session.add(s)
    _db311.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db311.session.add(_Dom311(website_id=s.id, domain="%s.example.org" % name, is_primary=True))
    _db311.session.commit()
    _ROWS311["sites"].append(s.id)
    return s


def _quadlet_lines311(account, prefix):
    text = _read311(account, ".config/containers/systemd/lgsm-site.container") or ""
    return [ln for ln in text.split("\n") if ln.startswith(prefix)]


# ── 1. Name lookups fail at once ──────────────────────────────────────────────────────────────────
def _s1_resolv(st):
    _seams311()
    su = _Client311(st.su.id)
    got = {}
    for kind, kw in (("php", {}), ("static", {}), ("wordpress", {"app_recipe": "wordpress"}),
                     ("app", {"runtime": "node", "runtime_version": "24", "app_port": 3000})):
        site = _site311(st, "p311-dns-%s" % kind, kind=kind, **kw)
        _reset311()
        r = su.post("/websites/%d/update-image" % site.id)
        mount = "Volume=/home/%s/site/conf/resolv.conf:/etc/resolv.conf:ro" % site.account
        got[kind] = (r.status_code, _quadlet_lines311(site.account, "Volume=/").count(mount),
                     _read311(site.account, "site/conf/resolv.conf") == _ws311.RESOLV_CONF,
                     "--dns=none" in " ".join(_quadlet_lines311(site.account, "PodmanArgs=")))
        if kind == "wordpress":
            net = _quadlet_lines311(site.account, "Network=")
            got["wordpress network"] = net == ["Network=pasta:--splice-only,-T,3128:%d" % (22000 + site.port - 20000)]
    eq("F34 (POST /websites/<id>/update-image, every kind): the site's container gets the panel's no-name-server file "
       "read-only over /etc/resolv.conf (Podman's --dns=none had left the image's own file: WordPress's 1.1.1.1 and "
       "1.0.0.1, unreachable from a site, so every lookup waited about 20 s and one visit a minute stalled), and "
       "keeps --dns=none", got,
       {"php": (200, 1, True, True), "static": (200, 1, True, True), "wordpress": (200, 1, True, True),
        "app": (200, 1, True, True), "wordpress network": True})
    lines = [ln for ln in _ws311.RESOLV_CONF.split("\n") if ln and not ln.startswith("#")]
    eq("F34 (the file): it names no server (the resolver then asks 127.0.0.1:53 in the container's own namespace, "
       "where nothing listens, and is refused at once) and allows one try of one second",
       lines, ["options timeout:1 attempts:1"])
    full = _site311(st, "p311-dns-full", kind="php", full_egress=True)
    _reset311()
    r = su.post("/websites/%d/update-image" % full.id)
    eq("F34 control (a site with full egress, the superadmin's switch): its network and name servers are Podman's, as "
       "before: no file mounted, no --dns=none", (r.status_code, _quadlet_lines311(full.account, "Volume=/etc"),
                                                 [ln for ln in _quadlet_lines311(full.account, "Volume=")
                                                  if "resolv" in ln], "--dns=none" in " ".join(
                                                      _quadlet_lines311(full.account, "PodmanArgs="))),
       (200, [], [], False))
    _s1_steps(st)


def _s1_steps(st):
    steps = _ws311.recipe_steps("wordpress")
    copy = next(s for s in steps if s["type"] == "run-in-container" and s["image"] == "site")
    got = {}
    for name, kw in (("p311-step", {}), ("p311-step-full", {"full_egress": True})):
        site = _site311(st, name, kind="wordpress", app_recipe="wordpress", **kw)
        os.makedirs(os.path.join(_home311(site.account), "site"), exist_ok=True)
        _reset311()
        ok, _said = _sw311.app_install_step(st.host, site, copy, values={})
        run = next((a for a in _calls311("podman") if a[:1] == ["run"]), [])
        got[name] = (ok, any(a.endswith("/site/conf/resolv.conf:/etc/resolv.conf:ro") for a in run), "--dns=none" in run)
    eq("F34 (ssh_manager.websites.app_install_step, a container step): an app's install step gets the same file; one "
       "for a site with full egress does not (control: its --dns=none as before)", got,
       {"p311-step": (True, True, True), "p311-step-full": (True, False, True)})
    _s1_build(st)


def _s1_build(st):
    _seams311()
    app = _site311(st, "p311-build", kind="app", runtime="node", runtime_version="24", app_port=3000)
    html = os.path.join(_home311(app.account), "site", "html")
    os.makedirs(os.path.join(_home311(app.account), "site", "conf"), exist_ok=True)
    os.makedirs(html, exist_ok=True)
    with open(os.path.join(html, "package.json"), "w", encoding="utf-8") as fh:
        fh.write("{}")
    _reset311()
    r = _Client311(st.su.id).post("/websites/%d/app/build" % app.id)
    run = next((a for a in _calls311("podman") if a[:1] == ["run"]), [])
    eq("F34 (POST /websites/<id>/app/build, a site installed before the file existed): the build writes the "
       "no-name-server file first and mounts it read-only; the build ran (control)",
       (r.status_code, _read311(app.account, "site/conf/resolv.conf") == _ws311.RESOLV_CONF,
        any(a.endswith("/site/conf/resolv.conf:/etc/resolv.conf:ro") for a in run)), (200, True, True))
    _s4_npm(r, run, _read311(app.account, "site/conf/build.log") or "")


# ── 2. WordPress's scheduled tasks ────────────────────────────────────────────────────────────────
_CRON_DIR311 = ".config/systemd/user/"


def _s2_cron(st):
    _seams311()
    su = _Client311(st.su.id)
    wp = _site311(st, "p311-cron", kind="wordpress", app_recipe="wordpress")
    _reset311()
    r = su.post("/websites/%d/update-image" % wp.id)
    calls = _calls311("systemctl")
    timer, service = (_read311(wp.account, _CRON_DIR311 + "lgsm-site-cron." + x) or "" for x in ("timer", "service"))
    started = next((i for i, a in enumerate(calls) if "restart" in a and "lgsm-site.service" in a), None)
    enabled = next((i for i, a in enumerate(calls) if a[-3:] == ["enable", "--now", "lgsm-site-cron.timer"]), None)
    eq("F34 (POST /websites/<id>/update-image, WordPress): its scheduled tasks get a timer of the site's account, "
       "every 5 minutes at a fixed offset per site, started once the site runs",
       (r.status_code, "OnCalendar=*:0/5" in timer, "FixedRandomDelay=true" in timer, "WantedBy=timers.target" in timer,
        started is not None and enabled is not None and enabled > started),
       (200, True, True, True, True))
    eq("F34 (the timer's service): WordPress's cron in the site's running container as its account, skipped while the "
       "site is stopped or WordPress is not installed, its page output thrown away and no secret in the unit",
       ("ExecStart=/usr/bin/podman exec lgsm-site php /var/www/html/wp-cron.php" in service,
        "ExecCondition=/usr/bin/systemctl --user -q is-active lgsm-site.service" in service,
        "ExecCondition=/usr/bin/test -f %h/site/html/wp-config.php" in service, "StandardOutput=null" in service,
        _TOKEN311 in service + timer), (True, True, True, True, False))
    php = _site311(st, "p311-nocron", kind="php")
    _reset311()
    su.post("/websites/%d/update-image" % php.id)
    eq("F34 control (a PHP site): no scheduled-task timer is written or started",
       (_read311(php.account, _CRON_DIR311 + "lgsm-site-cron.timer"),
        any("lgsm-site-cron.timer" in a and "enable" in a for a in _calls311("systemctl"))), (None, False))
    _s2_config(st, wp)
    _s2_stop(st, wp)
    _s2_removed(st)


def _s2_config(st, wp):
    render = next(s for s in _ws311.recipe_steps("wordpress") if s["type"] == "render-config")
    secrets = {"db_name": "ws_wp", "db_user": "ws_wp", "db_password": "Db-" + "k" * 30, "admin_user": "p311admin",
               "admin_email": "a@example.org", "admin_password": "Ad-" + "m" * 30}
    os.makedirs(os.path.join(_home311(wp.account), "site", "html"), exist_ok=True)
    ok, _said = _sw311.app_install_step(st.host, wp, dict(render, secrets=secrets))
    conf = _read311(wp.account, "site/html/wp-config.php") or ""
    eq("F34 (ssh_manager.websites.app_install_step, WordPress's wp-config): no visitor's request starts WordPress's "
       "scheduled tasks (DISABLE_WP_CRON), before wp-settings.php is loaded",
       (ok, "define( 'DISABLE_WP_CRON', true );" in conf,
        0 < conf.find("DISABLE_WP_CRON") < conf.find("require_once ABSPATH . 'wp-settings.php';")), (True, True, True))


def _s2_stop(st, wp):
    _reset311()
    r = _Client311(st.su.id).post("/websites/%d/stop" % wp.id)
    eq("F34 (POST /websites/<id>/stop): the timer stops with the site", (r.status_code, any(
        a[-2:] == ["stop", "lgsm-site-cron.timer"] for a in _calls311("systemctl"))), (200, True))


def _s2_removed(st):
    su = _Client311(st.su.id)
    got = {}
    for how in ("undo", "delete"):
        site = _site311(st, "p311-rm-%s" % how, kind="wordpress", app_recipe="wordpress")
        _reset311()
        su.post("/websites/%d/update-image" % site.id)
        written = _read311(site.account, _CRON_DIR311 + "lgsm-site-cron.timer") is not None
        if how == "undo":
            site.state, site.install_steps_done = "creating", '["account"]'
            _db311.session.commit()
        _reset311()
        r = su.post("/websites/%d/install/undo" % site.id if how == "undo" else "/websites/%d/delete" % site.id,
                    json={"confirm": site.name})
        got[how] = (written, r.status_code, any(a[-3:] == ["disable", "--now", "lgsm-site-cron.timer"]
                                                for a in _calls311("systemctl")),
                    [n for n in ("timer", "service") if _read311(site.account, _CRON_DIR311 + "lgsm-site-cron." + n)])
    eq("F34 (POST /websites/<id>/install/undo and /delete): the timer is disabled and its unit files removed with the "
       "site", got, {"undo": (True, 200, True, []), "delete": (True, 200, True, [])})


# ── 3. The tunnel's re-apply ──────────────────────────────────────────────────────────────────────
def _s3_tunnel(st):
    _seams311()
    _p9_patch(_sw311, "_tunnel_ids", lambda remote: (1100, 1100))
    _p9_patch(_sw311, "tunnel_apply", _REAL311["tunnel_apply"])
    proxy = _Proxy311(remote_id=st.host.id, exposure_mode="tunnel", tunnel_provider="cloudflare",
                      tunnel_token_enc=_cfg311.encrypt_secret("tk-p311-" + "x" * 30))
    _db311.session.add(proxy)
    _db311.session.commit()
    su = _Client311(st.su.id)
    home = _home311(_ws311.TUNNEL_ACCOUNT)
    os.makedirs(home, exist_ok=True)
    unit = _ws311.unit_service(_ws311.TUNNEL_UNIT)
    with open(os.path.join(home, ".limit-" + unit), "w", encoding="utf-8") as fh:
        fh.write("5")
    _reset311()
    r = su.post("/websites/proxy/apply", json={"host_id": st.host.id})
    eq("M15 (POST /websites/proxy/apply, tunnel mode, the connector at its start limit after five failures): the "
       "limit is cleared before the restart, so the apply works", (r.status_code, (r.get_json() or {}).get("success")),
       (200, True))
    _reset311(FAKE_RESTART_RC=1)
    r = su.post("/websites/proxy/apply", json={"host_id": st.host.id})
    _db311.session.expire_all()
    said = (r.get_json() or {}).get("message")
    eq("M15 (POST /websites/proxy/apply, the connector does not start): the sentence names the tunnel connector, not "
       "\"the site's log\" (a host's tunnel has none)",
       (r.status_code, said, _db311.session.get(_Proxy311, proxy.id).last_error), (502, _sw311.TUNNEL_FAILED,
                                                                                  _sw311.TUNNEL_FAILED))
    _reset311(FAKE_IMAGE_EXISTS=1, FAKE_BUILD_RC=1)
    r = su.post("/websites/proxy/apply", json={"host_id": st.host.id})
    eq("M15 control (the connector's image build fails): that failure keeps its own sentence",
       (r.status_code, (r.get_json() or {}).get("message")), (502, _ws311.FAIL_MARKS["SITE_BUILD_FAILED"]))


# ── 4. An app's build log ─────────────────────────────────────────────────────────────────────────
def _s4_npm(r, run, log):
    eq("I3 (POST /websites/<id>/app/build): npm's update notice is off, so the build log's last lines (the page shows "
       "them) are the build's own; the build still ran (control)",
       (r.status_code, "npm_config_update_notifier=false" in run, "npm notice" in log, "added 12 packages" in log),
       (200, True, False, True))


# ── running the sections ──────────────────────────────────────────────────────────────────────────
def _cleanup311():
    _db311.session.rollback()
    sites = set(_ROWS311["sites"]) | {s.id for s in _Site311.query.filter(
        _Site311.remote_id.in_(_ROWS311["remotes"] or [0])).all()}
    for d in _Dom311.query.filter(_Dom311.website_id.in_(sorted(sites) or [0])).all():
        _db311.session.delete(d)
    for p in _Proxy311.query.filter(_Proxy311.remote_id.in_(_ROWS311["remotes"] or [0])).all():
        _db311.session.delete(p)
    for model, ids in ((_Site311, sorted(sites)), (_User311, _ROWS311["users"]), (_Remote311, _ROWS311["remotes"])):
        for i in ids:
            row = _db311.session.get(model, i)
            if row is not None:
                _db311.session.delete(row)
    _db311.session.commit()
    _shutil311.rmtree(_TREE311, ignore_errors=True)


def _ran311(step, st):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran311.last)."""
    import traceback
    try:
        step(st)
        _ran311.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db311.session.rollback()
        _ran311.last = traceback.format_exc()[-1500:]
        return False


_ran311.last = ""
_tools311()
_trips311 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part311")
        _p9_patch(_sw311, "ports_apply", lambda *a, **k: (True, _sw311.OK_PORTS))
        _p9_patch(_sw311, "proxy_apply", lambda *a, **k: (True, _sw311.OK_APPLIED))
        _p9_patch(_sw311, "proxy_stop", lambda *a, **k: (True, "stopped"))
        _p9_patch(_sw311, "quota_set", lambda *a, **k: (True, _sw311.OK_QUOTA))
        _p9_patch(_sw311, "cpu_limit", lambda *a, **k: (True, "container"))
        _st311 = _rows311()
        for _sec311 in (_s1_resolv, _s2_cron, _s3_tunnel):
            check("part311: %s ran to the end" % _sec311.__name__, _ran311(_sec311, _st311), _ran311.last)
        eq("part311: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips311:], [])
    finally:
        _p9_restore_all()
        _w311._STATUS.clear()
        _wapps311._JOBS.clear()
        _cleanup311()
