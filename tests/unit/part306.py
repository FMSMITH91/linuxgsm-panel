"""Part 306 of the unit suite: fixes the websites' third proof round on the test host (P3) turned up.

F23. The PHP sites' image builds with the Podman the panel installs: in Docker's image format (Podman's default
     OCI format ignores SHELL), and from RUN lines that are POSIX sh as well as bash.
F24. Drupal's append to the settings.php its installer left read-only works, and the modes are put back; a write
     that fails says why (M4), with the step's own lines in the panel's log.
F25. An app install whose undo could not drop its database says NOT undone and what is left, and keeps the site
     and its database rows (a delete retries them) instead of saying "undone" over a database left behind.

HOW IT RUNS. part12's app and its database for the routes, with the host stand-ins at ssh_manager.websites' own
seams (its helper, the account's ids). A site's account shells run in real bash over a scratch home, with stand-in
podman and systemctl first on PATH that record their argv (one JSON line each). Nothing reaches a host (part12's
tripwire is armed).
"""
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
from panel.ops.ssh_manager import websites as _sw306
from panel.routes import _shared as _shared306
from panel.routes import websites as _w306
from panel.routes import websites_apps as _wapps306
from panel.services import websites as _ws306

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
with open(os.environ["FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps({"tool": tool, "argv": argv}) + "\n")
sys.exit(rc)
'''


def _tools306():
    os.makedirs(_BIN306, exist_ok=True)
    for name in ("podman", "systemctl", "journalctl"):
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
_SECTIONS306 = (_f23_php_build, _f24_append, _f25_undo)
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
