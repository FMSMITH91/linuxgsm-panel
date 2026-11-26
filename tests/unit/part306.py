"""Part 306 of the unit suite: fixes the websites' third proof round on the test host (P3) turned up.

F23. The PHP sites' image builds with the Podman the panel installs: in Docker's image format (Podman's default
     OCI format ignores SHELL), and from RUN lines that are POSIX sh as well as bash.
F24. Drupal's append to the settings.php its installer left read-only works, and the modes are put back; a write
     that fails says why (M4), with the step's own lines in the panel's log.
F25. An app install whose undo could not drop its database says NOT undone and what is left, and keeps the site
     and its database rows (a delete retries them) instead of saying "undone" over a database left behind.
F26. A runtime app's gate and the object cache (Network=container:) carry no DNS option, which Podman refuses beside
     that network mode; the site's own container keeps --dns=none. F26a: turning the object cache on or off on
     the Performance card writes (or removes) its unit and config and starts (or stops) it.
F27. The page cache's proxy builds: its Caddy version ARG no longer clashes with the builder's ENV, xcaddy does not
     setcap, and the root build uses the host's network (the copy-out container none), so netavark never turns on
     the host's IP forwarding or adds its iptables chains; a failed build's last lines reach the panel's log.
     F27 wiring: turning on "Page cache in the web proxy" builds it on every host with a web proxy (and a plain
     proxy install while it is on builds it again); the Performance tab says when a site's page cache waits for it.
F28. A Node.js site made from the page takes the catalog's port and commands, installs without starting while it has
     no files (it says it waits for them, and its install is not undone), and the App tab's Save and rebuild (or
     the build route) builds it and starts it; a real install failure is still undone.
F29. A site's disk use is its own folder (~/site) measured by du with du's own exit status: a partial count is no
     measurement, and the account's container images are not counted (a user quota allows for them).
M3.  website-account-remove deletes the account on its first call even while the account's last processes are
     still ending after its user manager stopped (userdel refuses with exit 8 then).
M5.  A raw proxy snippet the configuration would leave out (it reads the proxy's environment) is refused in plain
     words, not stored and reported as applied.
M6.  A successful image update of a failed site records it running, its old failure reason cleared.
M11. Only a site whose PHP image is built on the host gets the build folder (~/site/image); an empty one an earlier
     install made for another kind is removed.

HOW IT RUNS. part12's app and its database for the routes, with the host stand-ins at ssh_manager.websites' own
seams (its helper, the account's ids). A site's account shells run in real bash over a scratch home, with stand-in
podman and systemctl first on PATH that record their argv (one JSON line each). Nothing reaches a host (part12's
tripwire is armed).
"""
import contextlib as _ctx306
import importlib.machinery as _mach306
import importlib.util as _ilu306
import io as _io306
import json as _json306
import logging as _logging306
import os
import re as _re306
import shutil as _shutil306
import subprocess as _sp306  # nosec B404 - bash over the panel's own account shells, in a scratch home
import sys as _sys306
import tempfile as _tf306
from types import SimpleNamespace as _NS306

from flask import g as _g306

from unit.part01 import _root, eq, skip
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg306
from panel.db.models import (GameDatabase as _GDB306, RemoteServer as _Remote306, User as _User306,
                             Website as _Site306, WebsiteDomain as _Dom306, WebsiteProxy as _Proxy306, db as _db306)
from panel.ops.ssh_manager import _core as _core306
from panel.ops.ssh_manager import files as _files306
from panel.ops.ssh_manager import websites as _sw306
from panel.routes import _shared as _shared306
from panel.routes import websites as _w306
from panel.routes import websites_apps as _wapps306
from panel.routes import websites_files as _wfr306
from panel.routes import websites_proxy as _wproxy306
from panel.routes import websites_settings as _wset306
from panel.services import websites as _ws306
from panel.services import websites_catalog as _wc306

_TREE306 = _tf306.mkdtemp(prefix="lgsm-unit-p306-")
# The real functions a section stands in for, put back by the next section that needs them.
_REAL_NAMES306 = ("install", "_as_site", "remove", "start", "php_apply", "app_install_step", "app_undo_step")
_REAL306 = {n: getattr(_sw306, n) for n in _REAL_NAMES306}
_REAL306["_worker"] = _wapps306._worker
_BIN306 = os.path.join(_TREE306, "bin")
_CALLS306 = os.path.join(_TREE306, "calls.jsonl")
_TOKEN306 = "t" * 40
_SECRET_STEP306 = {"admin_user": "siteowner", "admin_email": "owner@example.org", "admin_password": "Adm1n-" + "q" * 24,
                   "db_name": "ws906_app", "db_user": "ws906_app", "db_password": "Db-" + "z" * 30}

# The stand-in tools: each records its argv (one JSON line) and exits 0, except `podman image exists`
# (FAKE_IMAGE_EXISTS, default 1: not there) and whatever FAKE_RC_<tool> names.
_FAKE306 = r'''
import json, os, sys
argv = sys.argv[1:]
tool = os.path.basename(sys.argv[0])
rc = int(os.environ.get("FAKE_RC_" + tool, "0"))
if tool == "podman" and argv[:2] == ["image", "exists"]:
    rc = int(os.environ.get("FAKE_IMAGE_EXISTS", "1"))
if tool == "du":
    sys.stdout.write(os.environ.get("FAKE_DU_OUT", "4096") + "\t" + argv[-1] + "\n")
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps({"tool": tool, "argv": argv}) + "\n")
sys.exit(rc)
'''


def _tools306():
    os.makedirs(_BIN306, exist_ok=True)
    for name in ("podman", "systemctl", "journalctl", "du"):
        path = os.path.join(_BIN306, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!%s\n%s" % (_sys306.executable, _FAKE306))
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
        os.chmod(path, 0o700)


def _home306(account):
    return os.path.join(_TREE306, "home", account)


_RUN306 = {"env": {}, "shells": []}


def _bash306(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
    """shell_as_game_user over a scratch home: the panel's shell in real bash, the stand-in tools first on PATH."""
    _RUN306["shells"].append(sh)
    if not sh.startswith(_ws306._ENV):
        return "", "part306: not an account shell", 99
    home = _home306(user)
    os.makedirs(home, exist_ok=True)
    text = 'cd "$HOME" || exit 1; ' + sh[len(_ws306._ENV):].replace("/home/%s" % user, home)
    env = dict(os.environ, HOME=home, PATH=_BIN306 + os.pathsep + os.environ.get("PATH", ""), FAKE_CALLS=_CALLS306,
               **_RUN306["env"])
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp306.run(["bash", "-c", text], input=(stdin_text or "").encode(), capture_output=True, timeout=timeout,  # nosec B603 B607
                   env=env, check=False)
    return r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"), r.returncode


def _calls306(tool=None):
    if not os.path.exists(_CALLS306):
        return []
    with open(_CALLS306, encoding="utf-8") as fh:
        got = [_json306.loads(ln) for ln in fh if ln.strip()]
    return [c for c in got if tool is None or c["tool"] == tool]


def _reset306(**env):
    if os.path.exists(_CALLS306):
        os.unlink(_CALLS306)
    _RUN306["env"] = {k: str(v) for k, v in env.items()}
    _RUN306["shells"] = []


def _bash_seams306(helper=None):
    """The account's shell in real bash over its scratch home; Podman ready, the helper answering `helper`."""
    for name in _REAL_NAMES306:
        _p9_patch(_sw306, name, _REAL306[name])
    _p9_patch(_core306, "shell_as_game_user", _bash306)
    _p9_patch(_core306, "is_local_server", lambda server: True)
    _p9_patch(_shared306, "game_account_write_refusal", lambda remote, account: None)
    _p9_patch(_sw306, "runtime_ready", lambda remote: "")
    _p9_patch(_sw306, "_helper", helper or (lambda remote, verb, args=(), timeout=120, doc=None: (True, "account=present")))
    _p9_patch(_sw306, "_ids", lambda remote, site: ((os.getuid(), os.getgid()), {
        "splice": True, "cpu_delegated": True, "os": "24.04", "podman": "podman version 4.9.3"}))


class _Client306:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def get(self, *a, **k):
        _g306.pop("_login_user", None)
        return self.c.get(*a, **k)

    def post(self, *a, **k):
        _g306.pop("_login_user", None)
        return self.c.post(*a, **k)


_ROWS306 = {"sites": [], "remotes": [], "users": [], "dbs": []}


def _rows306():
    r = _Remote306(name="p306-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.76")
    su = _User306(username="p306-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db306.session.add_all([r, su])
    _db306.session.commit()
    _ROWS306["remotes"].append(r.id)
    _ROWS306["users"].append(su.id)
    return _NS306(host=r, su=su)


def _site306(st, name, kind="php", **kw):
    s = _Site306(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg306.encrypt_secret(_TOKEN306), **dict({"php_version": "8.4"}, **kw))
    _db306.session.add(s)
    _db306.session.flush()
    s.account, s.port = "ws%d" % s.id, 20000 + s.id % 900
    _db306.session.add(_Dom306(website_id=s.id, domain="%s.example.org" % name, is_primary=True))
    _db306.session.commit()
    _ROWS306["sites"].append(s.id)
    return s


# ── F23. The PHP image's build ──────────────────────────────────────────────────────────────────
# Syntax only bash (and not POSIX sh, which an OCI-format build runs RUN lines under) understands.
_BASHISMS306 = ("<<<", "[[", "PIPESTATUS", "$'", "function ", "&>", "|&", "=~", "<(", ">(", "${!", "declare ", "local ",
                "source ")


def _run_bodies306(path):
    """The shell text of each RUN instruction (shell form) of the Containerfile at `path`, continuations joined."""
    lines = [ln for ln in _read306(path).split("\n") if not ln.lstrip().startswith("#")]
    text = "\n".join(lines).replace("\\\n", " ")
    return [m.group(1) for m in _re306.finditer(r"^RUN (?!\[)(.*)$", text, _re306.M)]


def _posix_problems306(path):
    """[(bash-only syntax, RUN index)] in the Containerfile at `path`; `dash -n` too where dash is installed."""
    out = []
    for i, body in enumerate(_run_bodies306(path)):
        out += [(b, i) for b in _BASHISMS306 if b in body]
        dash = _shutil306.which("dash")
        if dash:
            # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
            r = _sp306.run([dash, "-n", "-c", body], capture_output=True, timeout=30, check=False)  # nosec B603
            out += [("dash -n: %s" % r.stderr.decode("utf-8", "replace").strip()[:80], i)] if r.returncode else []
    return out


def _read306(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _f23_php_build(st):
    images = os.path.join(_root, "panel", "website_images")
    php_cf, cache_cf = os.path.join(images, "php", "Containerfile"), os.path.join(images, "caddy-cache", "Containerfile")
    eq("F23 (php Containerfile): every RUN line is POSIX sh as well as bash, so an OCI-format build (which ignores "
       "SHELL and runs dash) still builds it (bash's `<<<` failed: `Syntax error: redirection unexpected`)",
       (_posix_problems306(php_cf), len(_run_bodies306(php_cf))), ([], 1))
    eq("F23 (caddy-cache Containerfile): its RUN lines are POSIX sh too, and it sets no SHELL (control: the root "
       "build of the page cache's proxy runs them under the builder's /bin/sh)",
       (_posix_problems306(cache_cf), "\nSHELL " in _read306(cache_cf)), ([], False))
    _bash_seams306()
    site = _site306(st, "p306-php", kind="php")
    _reset306()
    r = _Client306(st.su.id).post("/websites/%d/update-image" % site.id)
    builds = [c["argv"] for c in _calls306("podman") if c["argv"][:1] == ["build"]]
    fmt = builds[0][builds[0].index("--format") + 1] if builds and "--format" in builds[0] else None
    eq("F23 (POST /websites/<id>/update-image): the PHP image is built in Docker's image format, which keeps the "
       "Containerfile's SHELL (bash with pipefail) on Podman 4.9.3", (r.status_code, len(builds), fmt), (200, 1, "docker"))
    _reset306(FAKE_IMAGE_EXISTS=0)
    r2 = _Client306(st.su.id).post("/websites/%d/update-image" % site.id)
    eq("F23 (POST /websites/<id>/update-image): an image already built is not built again (control)",
       (r2.status_code, [c["argv"][:1] for c in _calls306("podman") if c["argv"][:1] == ["build"]]), (200, []))


# ── F24. Drupal's append, and a failed write's reason (M4) ─────────────────────────────────────
class _Records306(_logging306.Handler):
    def __init__(self):
        super().__init__(level=_logging306.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _drupal_home306(site, settings_is_dir=False):
    """A scratch home as Drupal's installer leaves it: sites/default 0555, settings.php 0444 (or a folder there)."""
    _rmtree306(_home306(site.account))
    sd = os.path.join(_home306(site.account), "site", "html", "sites", "default")
    os.makedirs(os.path.join(sd, "settings.php") if settings_is_dir else sd)
    if not settings_is_dir:
        with open(os.path.join(sd, "settings.php"), "w", encoding="utf-8") as fh:
            fh.write("<?php\n$databases = [];\n")
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- read-only, as Drupal leaves it
        os.chmod(os.path.join(sd, "settings.php"), 0o444)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- read-only, as Drupal leaves it
    os.chmod(sd, 0o555)
    return sd


def _f24_append(st):
    _bash_seams306()
    site = _site306(st, "p306-dr", kind="php", app_recipe="drupal")
    step = [s for s in _ws306.recipe_steps("drupal") if s["type"] == "render-config"][0]
    sd = _drupal_home306(site)
    ok, said = _sw306.app_install_step(_NS306(is_local=True), site, dict(step, secrets=dict(_SECRET_STEP306)))
    text = _read306(os.path.join(sd, "settings.php"))
    modes = (oct(os.stat(os.path.join(sd, "settings.php")).st_mode & 0o777), oct(os.stat(sd).st_mode & 0o777))
    name = ("F24 (app_install_step, Drupal's render-config): the trusted host line is appended to the settings.php "
            "its installer left 0444 in a 0555 folder, and both modes are put back (every Drupal install failed here)")
    if os.geteuid() == 0:
        skip(name, "root writes a read-only file anyway, so this run cannot show the refusal")
    else:
        eq(name, (ok, "$settings['trusted_host_patterns'] = ['^p306-dr\\.example\\.org$'];" in text, modes),
           (True, True, ("0o444", "0o555")))
    rec = _Records306()
    _core306._log.addHandler(rec)
    try:
        _drupal_home306(site, settings_is_dir=True)
        ok2, said2 = _sw306.app_install_step(_NS306(is_local=True), site, dict(step, secrets=dict(_SECRET_STEP306)))
    finally:
        _core306._log.removeHandler(rec)
    logged = [ln for ln in rec.lines if "install step render-config-3 failed" in ln]
    eq("F24/M4 (app_install_step): a config write that fails says why on the page (the system's reason and the file), "
       "and the step's own lines reach the panel's log (it was the generic sentence, with nothing kept)",
       (ok2, str(said2).startswith(_ws306.FAIL_MARKS["SITE_WRITE_FAILED"]),
        "The host said: Is a directory: sites/default/settings.php." in str(said2),
        any("SITE_WRITE_FAILED | error=Is a directory" in ln for ln in logged)), (False, True, True, True))


# ── F25. The install's undo and a database it could not drop ────────────────────────────────────
class _Inline306:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)


def _f25_app_job(st, name, drop_ok):
    """An app install (POST /websites/install-app, then its job) that fails at its last step; the site's row."""
    from panel.routes import databases_sites as _ds306
    _p9_patch(_wapps306, "_worker", lambda app, sid, uid, secrets: None)
    _p9_patch(_w306, "threading", _NS306(Thread=_Inline306))
    form = {"app": "wordpress", "name": name, "remote_id": st.host.id, "admin_user": "siteowner",
            "admin_email": "owner@example.org", "domain": "%s.example.org" % name}
    r = _Client306(st.su.id).post("/websites/install-app", json=form)
    sid = _p9_json(r).get("id") or 0
    _ROWS306["sites"].append(sid)

    def create_for(site, slug):
        row = _GDB306(remote_id=site.remote_id, website_id=site.id, name="ws%d_app" % site.id, secret="")
        _db306.session.add(row)
        _db306.session.commit()
        _ROWS306["dbs"].append(row.id)
        return True, "made", row, "Db-" + "z" * 30
    _p9_patch(_ds306, "create_for", create_for)

    def drop(site, row):
        if not drop_ok:
            return False, "The database server did not answer."
        _db306.session.delete(row)
        _db306.session.commit()
        return True, "dropped"
    _p9_patch(_ds306, "drop", drop)
    _p9_patch(_sw306, "install", lambda remote, site, db=None: (True, _sw306.OK_STARTED))
    _p9_patch(_sw306, "remove", lambda remote, site: (True, _sw306.OK_REMOVED))
    _p9_patch(_sw306, "app_undo_step", lambda remote, site, step: (True, _sw306.OK_STEP))
    _p9_patch(_sw306, "app_install_step", lambda remote, site, step: (
        (False, _ws306.FAIL_MARKS["SITE_VERIFY_FAILED"]) if step["type"] == "verify-install" else (True, _sw306.OK_STEP)))
    _REAL306["_worker"](_p9, sid, st.su.id, dict(_SECRET_STEP306))
    _db306.session.expire_all()
    return _db306.session.get(_Site306, sid), sid


def _f25_undo(st):
    site, sid = _f25_app_job(st, "p306-wpleft", drop_ok=False)
    rows = _GDB306.query.filter_by(website_id=sid).all()
    audit = _p9_audit("website_app_install")
    eq("F25 (the app job): when its undo cannot drop the new database, the site stays (failed) saying NOT undone and "
       "which database is still on the server, its database row still belongs to it, and the audit row says NOT "
       "undone (it said \"undone\" and left a database that belonged to no site)",
       (getattr(site, "state", None), "NOT undone" in (getattr(site, "state_reason", "") or ""),
        "ws%d_app" % sid in (getattr(site, "state_reason", "") or ""), [r.name for r in rows],
        "NOT undone" in audit.detail and "still on the database server" in audit.detail),
       ("failed", True, True, ["ws%d_app" % sid], True))
    site2, sid2 = _f25_app_job(st, "p306-wpgone", drop_ok=True)
    eq("F25 (the app job): when every step is undone the site's row goes and the audit row says undone (control)",
       (site2 is None, _GDB306.query.filter_by(website_id=sid2).count(), _p9_audit("website_app_install").detail.endswith(
           "; undone")), (True, 0, True))


# ── F26. The containers that join the site's network namespace ─────────────────────────────────
def _unit306(site, name):
    """The text of Quadlet `name` the install left in the site's scratch home ("" when none)."""
    path = os.path.join(_home306(site.account), _ws306.QUADLET_DIR, name + ".container")
    return _read306(path) if os.path.exists(path) else ""


def _args306(text):
    return [ln for ln in text.split("\n") if ln.startswith(("PodmanArgs=", "Network="))]


def _f26_dns(st):
    _bash_seams306()
    app = _site306(st, "p306-node", kind="app", php_version="", runtime="node", runtime_version="24", app_port=3000,
                   start_command="npm start")
    php = _site306(st, "p306-cache", kind="php", object_cache=True,
                   object_cache_secret=_cfg306.encrypt_secret("c" * 40))
    for site in (app, php):
        os.makedirs(os.path.join(_home306(site.account), "site", "html"), exist_ok=True)
        with open(os.path.join(_home306(site.account), "site", "html", "index.js"), "w", encoding="utf-8") as fh:
            fh.write("// the app\n")
    _reset306(FAKE_IMAGE_EXISTS=0)
    su = _Client306(st.su.id)
    codes = [su.post("/websites/%d/update-image" % s.id).status_code for s in (app, php)]
    gate, cache = _args306(_unit306(app, "lgsm-site-gate")), _args306(_unit306(php, "lgsm-site-cache"))
    eq("F26 (POST /websites/<id>/update-image): the gate in front of a Node.js app and the object cache join the "
       "site's network namespace with no DNS option (Podman refused --dns=none there: neither unit ever started)",
       (codes, gate[0:1], cache[0:1], [a for a in gate + cache if "--dns" in a]),
       ([200, 200], ["Network=container:lgsm-site"], ["Network=container:lgsm-site"], []))
    eq("F26: the site's own container keeps --dns=none and its no-route network, so the units that join it have no "
       "DNS and no way out either (control)",
       ["--dns=none" in a for a in _args306(_unit306(app, "lgsm-site")) + _args306(_unit306(php, "lgsm-site"))
        if a.startswith("PodmanArgs=")], [True, True])


def _f26a_cache_switch(st):
    _bash_seams306()
    site = _site306(st, "p306-obj", kind="wordpress")
    su = _Client306(st.su.id)
    conf = os.path.join(_home306(site.account), "site", "conf", "valkey.conf")
    valkey = _wc306.pins("object_cache")["image"]
    _reset306(FAKE_IMAGE_EXISTS=0)
    r_on = su.post("/websites/%d/performance" % site.id, json={"object_cache": True})
    on_calls = _calls306()
    unit_on, conf_on = _unit306(site, "lgsm-site-cache"), os.path.exists(conf)
    started = any(c["tool"] == "systemctl" and "restart" in c["argv"] and "lgsm-site-cache.service" in c["argv"]
                  for c in on_calls)
    pulled = any(c["tool"] == "podman" and c["argv"][:1] == ["pull"] and valkey in c["argv"] for c in on_calls)
    eq("F26a (POST /websites/<id>/performance, object cache on): its unit and its 0600 config are written, its image "
       "pulled and the unit started with the site (it only rewrote the php.ini: no cache ever ran)",
       (r_on.status_code, "Network=container:lgsm-site" in unit_on, conf_on, pulled, started),
       (200, True, True, True, True))
    _reset306(FAKE_IMAGE_EXISTS=0)
    r_off = su.post("/websites/%d/performance" % site.id, json={"object_cache": False})
    stopped = any(c["tool"] == "systemctl" and "stop" in c["argv"] and "lgsm-site-cache.service" in c["argv"]
                  for c in _calls306())
    eq("F26a (POST /websites/<id>/performance, object cache off): its container is stopped and its unit and config "
       "(with its password) removed", (r_off.status_code, _unit306(site, "lgsm-site-cache"), os.path.exists(conf), stopped),
       (200, "", False, True))
    _reset306()
    r_op = su.post("/websites/%d/performance" % site.id, json={"opcache": False})
    eq("F26a (POST /websites/<id>/performance, OPcache only): the php.ini is rewritten and the site restarted, with "
       "no install (control)", (r_op.status_code, [c["argv"][:1] for c in _calls306("podman")]), (200, []))


# ── F27. The page cache's proxy build ──────────────────────────────────────────────────────────
_hspec306 = _ilu306.spec_from_loader("panel_helper_p306", _mach306.SourceFileLoader(
    "panel_helper_p306", os.path.join(_root, "tools", "panel-helper")))
_H306 = _ilu306.module_from_spec(_hspec306)
_hspec306.loader.exec_module(_H306)
# ENV names the caddy builder image sets (docker-library/caddy's builder Dockerfile): an ARG of one of these names
# is overridden by the ENV inside the build stage.
_BUILDER_ENV306 = ("CADDY_VERSION", "XCADDY_VERSION", "XCADDY_SETCAP", "XCADDY_SKIP_CLEANUP", "GOLANG_VERSION", "GOPATH",
                   "GOTOOLCHAIN", "PATH")


class _Sub306:
    """The helper's subprocess, standing in: records every argv; `podman build` answers build_rc and its lines."""
    PIPE, STDOUT, TimeoutExpired = _sp306.PIPE, _sp306.STDOUT, _sp306.TimeoutExpired

    def __init__(self, build_rc=0, build_out=b""):
        self.calls, self.build_rc, self.build_out = [], build_rc, build_out

    def run(self, argv, **_kw):
        argv = list(argv)
        self.calls.append(argv)
        if argv[1:2] == ["build"]:
            return _NS306(returncode=self.build_rc, stdout=self.build_out, stderr=b"")
        if argv[1:2] == ["create"]:
            return _NS306(returncode=0, stdout=b"c0ffee\n", stderr=b"")
        if argv[1:2] == ["cp"]:
            with open(argv[3], "wb") as fh:
                fh.write(b"caddy")
        return _NS306(returncode=0, stdout=b"inactive\n", stderr=b"")


def _cache_verb306(sub):
    """website-proxy-install-cache run by the helper with `sub` for its subprocess: (rc, stderr, calls)."""
    names = ("subprocess", "resolve", "pwd", "WEB_PROXY_BIN", "_web_has_cache", "_web_write")
    saved = {n: getattr(_H306, n) for n in names}
    binary = os.path.join(_TREE306, "caddy")
    with open(binary, "wb") as fh:
        fh.write(b"plain")
    err = _io306.StringIO()
    try:
        _H306.subprocess, _H306.resolve, _H306.WEB_PROXY_BIN = sub, lambda name: "/usr/bin/" + name, binary
        _H306.pwd = _NS306(getpwnam=lambda name: _NS306(pw_uid=1500, pw_gid=1500, pw_dir="/var/lib/lgsm-web-proxy"))
        _H306._web_has_cache = lambda path, pw: True
        _H306._web_write = lambda *a, **k: None
        c = _wc306.pins("caddy_cache")
        with _ctx306.redirect_stderr(err):
            rc = _H306.do_website_proxy_install_cache([c["caddy"], c["builder"], c["base"], c["version"]], "")
    finally:
        for n, v in saved.items():
            setattr(_H306, n, v)
    return rc, err.getvalue(), sub.calls


def _f27_cache_build(st):
    cf = _H306.WEB_CACHE_CONTAINERFILE
    build_stage = cf[cf.index(" AS build"):cf.index("\nFROM ${BASE_IMAGE}")]
    args = _re306.findall(r"^ARG ([A-Z_]+)$", build_stage, _re306.M)
    env = " ".join(ln for ln in build_stage.split("\n") if ln.startswith("ENV "))
    eq("F27a/b (the helper's Containerfile): no build-stage ARG shares a name with the builder image's ENV (its ENV "
       "CADDY_VERSION won, so xcaddy was asked for `vv2.11.9`), and xcaddy does not setcap (refused under "
       "--cap-drop=ALL)", ([a for a in args if a in _BUILDER_ENV306], "PANEL_CADDY_VERSION" in args,
                           "XCADDY_SETCAP=0" in env.split()), ([], True, True))
    rc, _err, calls = _cache_verb306(_Sub306())
    build = next((c for c in calls if c[1:2] == ["build"]), [])
    create = next((c for c in calls if c[1:2] == ["create"]), [])
    c = _wc306.pins("caddy_cache")
    eq("F27c (website-proxy-install-cache): the root build's RUN steps use the host's network and the container the "
       "binary is copied out of has none, so netavark never sets up a bridge (it turned on ip_forward and added its "
       "iptables chains, which stayed); the version reaches the build as PANEL_CADDY_VERSION",
       (rc, "--network=host" in build, "--network=none" in create, "PANEL_CADDY_VERSION=%s" % c["caddy"] in build,
        [a for a in build if a.startswith("CADDY_VERSION=")]), (0, True, True, True, []))
    lines = "".join("line %d of the build\n" % i for i in range(1, 41)).encode()
    rc2, err2, _calls2 = _cache_verb306(_Sub306(build_rc=1, build_out=lines))
    eq("F27 (website-proxy-install-cache): a failed build says so with its last lines (the helper hid them)",
       (rc2, "build: line 40 of the build" in err2, "build: line 21 of the build" in err2,
        "build: line 20 of the build" in err2), (1, True, True, False))
    rec = _Records306()
    _core306._log.addHandler(rec)
    _p9_patch(_sw306, "_helper", lambda remote, verb, args=(), timeout=120, doc=None: (False, err2))
    try:
        ok, said = _sw306.proxy_install_cache(_NS306(is_local=True))
    finally:
        _core306._log.removeHandler(rec)
    eq("F27 (ssh_manager.websites.proxy_install_cache): the page gets the plain sentence, and the build's last lines "
       "go to the panel's log", (ok, said == _sw306.CACHE_BUILD_FAILED,
                                 any("line 40 of the build" in ln for ln in rec.lines)), (False, True, True))


def _f27_wiring(st):
    built, cache = [], {"have": "no", "ok": True}
    _p9_patch(_wproxy306, "threading", _NS306(Thread=_Inline306))
    _p9_patch(_sw306, "proxy_status", lambda remote: (True, "installed=yes\nversion=v2.11.9\ncache=%s\n" % cache["have"]))
    _p9_patch(_sw306, "proxy_install_cache", lambda remote: built.append(remote.id) or (
        (True, _sw306.OK_CACHE_BUILD) if cache["ok"] else (False, _sw306.CACHE_BUILD_FAILED)))
    _p9_patch(_sw306, "proxy_install", lambda remote: (True, _sw306.OK_PROXY))
    _p9_patch(_sw306, "egress_guard", lambda remote: (True, _sw306.OK_GUARD))
    row = _w306.proxy_row(st.host.id)
    row.installed_version = "2.11.9"
    _db306.session.commit()
    su = _Client306(st.su.id)
    try:
        r = su.post("/websites/proxy/options", json={"options": {"cache_build": True}})
        audit = _p9_audit("remote_website_proxy_cache")
        eq("F27 wiring (POST /websites/proxy/options, page cache turned on): the web proxy with the page cache is "
           "built on the host with a web proxy, the page says so, and the outcome is audited (no route ever called the "
           "build: the option did nothing)",
           (r.status_code, built, _p9_json(r).get("message") == _wproxy306.S_CACHE_BUILDING, audit.success,
            "was built and installed" in audit.detail), (200, [st.host.id], True, True, True))
        del built[:]
        r2 = su.post("/websites/proxy/options", json={"options": {"cache_build": True}})
        eq("F27 wiring: saving the settings again with the page cache already on builds nothing (control)",
           (r2.status_code, built), (200, []))
        r3 = su.post("/websites/proxy/install", json={"host_id": st.host.id})
        eq("F27 wiring (POST /websites/proxy/install with the page cache on): the plain install is followed by the "
           "build, which puts the cache module back", (r3.status_code, built), (200, [st.host.id]))
        _f27_wiring_failure(st, su, built, cache)
    finally:
        _cfg306.update_config(lambda cfg: cfg.pop("websites_cache_build", None))


def _f27_wiring_failure(st, su, built, cache):
    su.post("/websites/proxy/options", json={"options": {"cache_build": False}})
    del built[:]
    cache["ok"] = False
    su.post("/websites/proxy/options", json={"options": {"cache_build": True}})
    _db306.session.expire_all()
    eq("F27 wiring: a build that fails is the proxy row's last error (the Security settings card shows it)",
       (built, _w306.proxy_row(st.host.id).last_error), ([st.host.id], _sw306.CACHE_BUILD_FAILED))
    _bash_seams306()
    site = _site306(st, "p306-pc", kind="php")
    _reset306()
    r = su.post("/websites/%d/performance" % site.id, json={"page_cache": True})
    cache["have"] = "yes"
    r2 = su.post("/websites/%d/performance" % site.id, json={"page_cache": True, "page_cache_ttl": 120})
    eq("F27 wiring (POST /websites/<id>/performance): a page cache turned on while this host's proxy lacks the module "
       "says it waits for it; once the proxy has it, the plain answer (control)",
       (r.status_code, _p9_json(r).get("message"), r2.status_code, _p9_json(r2).get("message") == _w306.i18n.tr(
           _wset306.S_PAGE_CACHE_WAITS)), (200, _wset306.S_PAGE_CACHE_WAITS, 200, False))


# ── F28. A Node.js site from the page ──────────────────────────────────────────────────────────
def _f28_helper(verbs, created=True):
    def helper(remote, verb, args=(), timeout=120, doc=None):
        verbs.append(verb)
        return True, "account=created" if verb == "website-account-create" and created else ""
    return helper


def _f28_node(st):
    verbs = []
    _bash_seams306(helper=_f28_helper(verbs))
    _p9_patch(_w306, "start_install", lambda site: _w306._install_worker(_p9, site.id))
    su = _Client306(st.su.id)
    _reset306(FAKE_IMAGE_EXISTS=0)
    r = su.post("/websites/add", json={"name": "p306-nd", "kind": "app", "runtime": "node", "runtime_version": "24",
                                       "remote_id": st.host.id})
    sid = _p9_json(r).get("id") or 0
    _ROWS306["sites"].append(sid)
    _db306.session.expire_all()
    site = _db306.session.get(_Site306, sid)
    node = _wc306.runtimes()["node"]
    eq("F28a (POST /websites/add, a Node.js site): it gets the catalog's port and start and build commands (it had no "
       "port, and its files could not be built)",
       (r.status_code, getattr(site, "app_port", None), getattr(site, "start_command", None),
        getattr(site, "build_command", None)), (200, node["port"], node["start"], node["build"]))
    starts = [c["argv"] for c in _calls306("systemctl") if "restart" in c["argv"] or "start" in c["argv"]]
    eq("F28b (POST /websites/add): with no files yet the app is installed and not started, says it waits for its "
       "files, and its account is kept (its first start failed and the install was undone, account and all)",
       (getattr(site, "state", None), getattr(site, "state_reason", None), starts, "website-account-remove" in verbs),
       ("stopped", _sw306.OK_WAITING, [], False))
    with open(os.path.join(_home306(site.account), "site", "html", "package.json"), "w", encoding="utf-8") as fh:
        fh.write('{"name": "p306", "scripts": {"start": "node server.js"}}\n')
    _reset306()
    r2 = su.post("/websites/%d/app" % sid, json={})
    _db306.session.expire_all()
    site = _db306.session.get(_Site306, sid)
    built = [c["argv"] for c in _calls306("podman") if c["argv"][:1] == ["run"] and "/panel/build.sh" in c["argv"]]
    restarted = [c["argv"] for c in _calls306("systemctl") if "restart" in c["argv"]]
    eq("F28b (POST /websites/<id>/app, the App tab's Save and rebuild): once its files are there the app is built "
       "(its packages installed) and then started with its gate, and the site reads running",
       (r2.status_code, len(built), [("lgsm-site.service" in a and "lgsm-site-gate.service" in a) for a in restarted],
        site.state, site.state_reason), (200, 1, [True], "running", ""))
    _reset306()
    r3 = su.post("/websites/%d/app/build" % sid)
    eq("F28b (POST /websites/<id>/app/build): the build route builds and starts it too (control)",
       (r3.status_code, _p9_json(r3).get("message")), (200, _sw306.OK_BUILT_STARTED))
    del verbs[:]
    _reset306(FAKE_RC_podman=1)
    r4 = su.post("/websites/add", json={"name": "p306-nd2", "kind": "app", "runtime": "node", "remote_id": st.host.id})
    _ROWS306["sites"].append(_p9_json(r4).get("id") or 0)
    _db306.session.expire_all()
    failed = _db306.session.get(_Site306, _p9_json(r4).get("id") or 0)
    eq("F28b (POST /websites/add): a real install failure (its image cannot be pulled) still undoes the account it "
       "made (control)", (getattr(failed, "state", None), "website-account-remove" in verbs), ("failed", True))


# ── F29. The disk count ─────────────────────────────────────────────────────────────────────────
def _any_bash306(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
    """shell_as_game_user for any shell of the account (an _ENV one or not), in bash over its scratch home."""
    if sh.startswith(_ws306._ENV):
        return _bash306(server, user, sh, timeout, selfname, scope, stdin_text)
    home = _home306(user)
    os.makedirs(home, exist_ok=True)
    env = dict(os.environ, HOME=home, PATH=_BIN306 + os.pathsep + os.environ.get("PATH", ""), FAKE_CALLS=_CALLS306,
               **_RUN306["env"])
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp306.run(["bash", "-c", sh.replace("/home/%s" % user, home)], capture_output=True, timeout=timeout,  # nosec B603 B607
                   env=env, check=False)
    return r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace"), r.returncode


def _f29_disk(st):
    _bash_seams306()
    _p9_patch(_core306, "shell_as_game_user", _any_bash306)
    _p9_patch(_wfr306, "game_account_write_refusal", lambda *a, **k: None)
    wrote = []
    _p9_patch(_files306, "write_file", lambda remote, account, rel, content: wrote.append(rel) or (True, "Saved."))
    site = _site306(st, "p306-du", kind="static", disk_mb=64)
    su = _Client306(st.su.id)
    _reset306(FAKE_RC_du=1, FAKE_DU_OUT=1000)
    r = su.post("/websites/%d/files/save" % site.id, json={"path": "index.html", "content": "<p>p306</p>"})
    eq("F29 (POST /websites/<id>/files/save): a du that could not read every file (exit 1, a partial number) is no "
       "measurement: nothing is written and the page says the use could not be measured (the partial number was "
       "used, through a pipe whose status was cut's)", (r.status_code, wrote), (507, []))
    _reset306(FAKE_DU_OUT=1000)
    r2 = su.post("/websites/%d/files/save" % site.id, json={"path": "index.html", "content": "<p>p306</p>"})
    du = [c["argv"] for c in _calls306("du")]
    eq("F29 (POST /websites/<id>/files/save): the count is the site's own folder (~/site), not the whole home with "
       "the account's container images (a WordPress site was over its 2048 MB right after its install); a "
       "measured folder under the limit takes the write (control)",
       (r2.status_code, wrote, [a[-1] for a in du]), (200, ["site/html/index.html"],
                                                      [os.path.join(_home306(site.account), "site")]))
    _reset306(FAKE_RC_du=1, FAKE_DU_OUT=7)
    ok, out = _sw306.site_probe(_NS306(is_local=True), site)
    _reset306(FAKE_DU_OUT=7)
    ok2, out2 = _sw306.site_probe(_NS306(is_local=True), site)
    eq("F29 (ssh_manager.websites.site_probe): the site card's disk figure is du's only when du read everything",
       (ok, _ws306.parse_probe(out)["disk_mb"], ok2, _ws306.parse_probe(out2)["disk_mb"]), (True, None, True, 7))
    _f29_quota()


def _f29_quota():
    names = ("subprocess", "pwd", "_web_made", "_web_quota_mount", "resolve")
    saved = {n: getattr(_H306, n) for n in names}
    sub = _Sub306()
    try:
        _H306.subprocess, _H306._web_made, _H306.resolve = sub, (lambda user: True), (lambda name: "/usr/sbin/" + name)
        _H306.pwd = _NS306(getpwnam=lambda name: _NS306(pw_uid=1500, pw_gid=1500, pw_dir="/home/" + name))
        _H306._web_quota_mount = lambda home: ("/home", True)
        with _ctx306.redirect_stdout(_io306.StringIO()), _ctx306.redirect_stderr(_io306.StringIO()):
            rcs = [_H306.do_website_quota_set(["ws906", mb], "") for mb in ("2048", "0")]
    finally:
        for n, v in saved.items():
            setattr(_H306, n, v)
    soft = [c[3] for c in sub.calls if c[1:3] == ["-u", "ws906"]]
    eq("F29 (website-quota-set): on a file system with user quotas the account's quota is its site's limit plus the "
       "allowance for its container images, which the quota counts (an image's files are the account's own); a "
       "limit of 0 stays no quota", (rcs, soft), ([0, 0], [str((2048 + 4096) * 1024), "0"]))


# ── M3. Removing a website account while its user manager stops ────────────────────────────────
class _UserdelSub306(_Sub306):
    """The helper's subprocess with userdel refusing (exit 8: a process still running) `busy` times first."""

    def __init__(self, busy):
        super().__init__()
        self.busy = busy

    def run(self, argv, **kw):
        if list(argv)[-2:-1] == ["-r"] and str(argv[0]).endswith("userdel"):
            self.calls.append(list(argv))
            self.busy -= 1
            return _NS306(returncode=8 if self.busy >= 0 else 0, stdout=b"", stderr=b"userdel: user is logged in\n")
        return super().run(argv, **kw)


def _remove_verb306(busy):
    names = ("subprocess", "pwd", "resolve", "_web_made", "WEB_MARK_DIR", "_addon_forget_account", "_forget_account_tmp",
             "_web_guard_refresh", "time")
    saved = {n: getattr(_H306, n) for n in names}
    marks = _tf306.mkdtemp(prefix="p306-marks-", dir=_TREE306)
    with open(os.path.join(marks, "ws907"), "w", encoding="utf-8"):
        pass
    sub, slept = _UserdelSub306(busy), []
    try:
        _H306.subprocess, _H306.resolve, _H306.WEB_MARK_DIR = sub, (lambda name: "/usr/sbin/" + name), marks
        _H306.pwd = _NS306(getpwnam=lambda name: _NS306(pw_uid=1907, pw_gid=1907, pw_dir="/home/" + name))
        _H306._web_made = lambda user: True
        _H306._addon_forget_account = _H306._forget_account_tmp = lambda *a: 0
        _H306._web_guard_refresh, _H306.time = (lambda: 0), _NS306(sleep=slept.append)
        with _ctx306.redirect_stdout(_io306.StringIO()), _ctx306.redirect_stderr(_io306.StringIO()):
            rc = _H306.do_website_account_remove(["ws907"], "")
    finally:
        for n, v in saved.items():
            setattr(_H306, n, v)
    return rc, [c for c in sub.calls if str(c[0]).endswith("userdel")], os.path.exists(os.path.join(marks, "ws907")), slept


def _m3_userdel(st):
    rc, userdels, mark, slept = _remove_verb306(busy=2)
    eq("M3 (website-account-remove): while the stopped user manager's last processes still end (userdel exits 8), "
       "the account is deleted on a later try in the same call, its mark removed (the first undo of a failed "
       "install failed, and only the job's second call worked)", (rc, len(userdels), mark, len(slept)), (0, 3, False, 2))
    rc2, userdels2, _mark2, slept2 = _remove_verb306(busy=0)
    eq("M3 (website-account-remove): an account with nothing left running is deleted at once, with no wait (control)",
       (rc2, len(userdels2), slept2), (0, 1, []))


# ── M5. A raw proxy snippet ─────────────────────────────────────────────────────────────────────
def _m5_snippet(st):
    site = _site306(st, "p306-raw", kind="static")
    su = _Client306(st.su.id)
    r = su.post("/websites/%d/rules" % site.id, json={"rules": [], "raw": "respond {env.HOME}"})
    _db306.session.expire_all()
    kept = _db306.session.get(_Site306, site.id).raw_proxy_snippet or ""
    eq("M5 (POST /websites/<id>/rules): a raw snippet that reads the proxy's environment is refused in plain words and "
       "not stored (it was stored, answered \"checked and applied\", and silently left out of the configuration)",
       (r.status_code, "may not read the proxy's environment" in (_p9_json(r).get("message") or ""), kept), (400, True, ""))
    r2 = su.post("/websites/%d/rules" % site.id, json={"rules": [], "raw": "header X-P306 yes"})
    _db306.session.expire_all()
    eq("M5 (POST /websites/<id>/rules): a snippet the configuration takes is stored (control)",
       (r2.status_code, _db306.session.get(_Site306, site.id).raw_proxy_snippet), (200, "header X-P306 yes"))


# ── M6. An image update of a failed site ───────────────────────────────────────────────────────
def _m6_update_state(st):
    _bash_seams306()
    site = _site306(st, "p306-upd", kind="static")
    site.state, site.state_reason = "failed", "The site's container did not start. Its last log lines are below."
    _db306.session.commit()
    _reset306()
    r = _Client306(st.su.id).post("/websites/%d/update-image" % site.id)
    _db306.session.expire_all()
    got = _db306.session.get(_Site306, site.id)
    eq("M6 (POST /websites/<id>/update-image): a successful update of a failed site (restarted from its new image) "
       "records it running and clears its old failure (it stayed failed, with the old reason)",
       (r.status_code, got.state, got.state_reason), (200, "running", ""))
    site.state, site.state_reason = "failed", "kept"
    _db306.session.commit()
    _reset306(FAKE_RC_podman=1)
    r2 = _Client306(st.su.id).post("/websites/%d/update-image" % site.id)
    _db306.session.expire_all()
    got = _db306.session.get(_Site306, site.id)
    eq("M6 (POST /websites/<id>/update-image): a failed update leaves the site's state as it was (control)",
       (r2.status_code, got.state, got.state_reason), (502, "failed", "kept"))


# ── M11. The image build folder ────────────────────────────────────────────────────────────────
def _m11_build_dir(st):
    _bash_seams306()
    sites = {kind: _site306(st, "p306-m11-%s" % kind, kind=kind) for kind in ("static", "wordpress", "php")}
    os.makedirs(os.path.join(_home306(sites["static"].account), "site", "image"))
    _reset306(FAKE_IMAGE_EXISTS=0)
    codes = [_Client306(st.su.id).post("/websites/%d/update-image" % s.id).status_code for s in sites.values()]
    eq("M11 (POST /websites/<id>/update-image): only the kind whose PHP image is built on the host has ~/site/image "
       "(every site, static and WordPress included, got an empty one); the empty one an earlier install left is gone",
       (codes, {k: os.path.isdir(os.path.join(_home306(s.account), "site", "image")) for k, s in sites.items()}),
       ([200, 200, 200], {"static": False, "wordpress": False, "php": True}))


# ── the run ─────────────────────────────────────────────────────────────────────────────────────
def _rmtree306(path):
    """Remove `path` whole, folders a step made read-only included."""
    for top, dirs, _files in os.walk(path):
        for d in dirs:
            # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: owner-only scratch folders
            os.chmod(os.path.join(top, d), 0o700)
    _shutil306.rmtree(path, ignore_errors=True)


def _drop306(model, ids):
    for i in ids:
        row = _db306.session.get(model, i) if i else None
        if row is not None:
            _db306.session.delete(row)


def _cleanup306():
    _db306.session.rollback()
    _drop306(_GDB306, _ROWS306["dbs"])
    sites = set(_ROWS306["sites"]) | {s.id for s in _Site306.query.filter(
        _Site306.remote_id.in_(_ROWS306["remotes"] or [0])).all()}
    _drop306(_GDB306, [g.id for g in _GDB306.query.filter(_GDB306.website_id.in_(sorted(sites) or [0])).all()])
    for d in _Dom306.query.filter(_Dom306.website_id.in_(sorted(sites) or [0])).all():
        _db306.session.delete(d)
    for p in _Proxy306.query.filter(_Proxy306.remote_id.in_(_ROWS306["remotes"] or [0])).all():
        _db306.session.delete(p)
    _drop306(_Site306, sorted(sites))
    _drop306(_User306, _ROWS306["users"])
    _drop306(_Remote306, _ROWS306["remotes"])
    _db306.session.commit()
    _rmtree306(_TREE306)


def _ran306(step, st):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran306.last)."""
    import traceback
    try:
        step(st)
        _ran306.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db306.session.rollback()
        _ran306.last = traceback.format_exc()[-1500:]
        return False


_ran306.last = ""
_SECTIONS306 = (_f23_php_build, _f24_append, _f25_undo, _f26_dns, _f26a_cache_switch, _f27_cache_build,
                _f27_wiring, _f28_node, _f29_disk, _m3_userdel, _m5_snippet, _m6_update_state,
                _m11_build_dir)
_tools306()
_trips306 = len(_P9_TRIPPED)
with _p9.app_context():
    try:
        _p9_arm(who="part306")
        _p9_patch(_sw306, "ports_apply", lambda *a, **k: (True, _sw306.OK_PORTS))
        _p9_patch(_sw306, "proxy_apply", lambda *a, **k: (True, _sw306.OK_APPLIED))
        _p9_patch(_sw306, "proxy_stop", lambda *a, **k: (True, "stopped"))
        _p9_patch(_sw306, "tunnel_apply", lambda *a, **k: (True, _sw306.OK_TUNNEL))
        _p9_patch(_sw306, "quota_set", lambda *a, **k: (True, _sw306.OK_QUOTA))
        _p9_patch(_sw306, "cpu_limit", lambda *a, **k: (True, "container"))
        _st306 = _rows306()
        for _sec306 in _SECTIONS306:
            eq("part306: %s ran to the end" % _sec306.__name__, (_ran306(_sec306, _st306), _ran306.last), (True, ""))
        eq("part306: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips306:], [])
    finally:
        _p9_restore_all()
        _w306._STATUS.clear()
        _wapps306._JOBS.clear()
        _cleanup306()
