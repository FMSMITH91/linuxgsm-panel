"""Reset password on a site's Database tab: a new password for the database's user, and the site kept working.

For the database a one-click app was installed with, the app's settings file gets the new password in the same
step (services.website_db_password); for a Node.js app, each of its variables that held the old password. The
order (OWASP Secrets Management Cheat Sheet, "2.7.2 Rotation"; "2.4.1 Architectural Patterns for Automated
Rotation": create the new secret, set it, test it, then finish):

1. a new password from the CSPRNG (ssh_manager.databases.new_password: 32 characters of letters, digits, - _ .);
2. the app's settings get it (nothing else is changed when they do not hold the current password);
3. the database's user gets it;
4. the site's database must answer it from the site's own network, its app's tables there;
5. then the panel stores it (encrypted). A failure at 3 or 4 puts the old password back where it was changed,
   and says so; one that cannot be put back says that too, so nobody is told the site works when it may not.

A database no app is known to use keeps the warning (its code must be given the new password), and the new
password is in the no-store answer, for the page to show masked (OWASP ASVS 5.0, 14.2.6 and 14.3.2).
"""
import json

from flask import jsonify

from panel.core import i18n
from panel.core.config import decrypt_secret, encrypt_secret
from panel.db.models import db
from panel.ops.ssh_manager import databases as _dbs
from panel.ops.ssh_manager import websites as _sw
from panel.routes import databases as _d
from panel.routes import websites as _w
from panel.services import website_db_password as _wdp

S_KEPT = "The database has a new password and {app}'s settings have it: the site keeps working."
S_ENV_KEPT = "The database has a new password and the app's variables ({names}) have it; the app was restarted."
S_PUT_BACK = "The new password did not work ({why}), so the old one was put back: the site keeps working."
S_NOT_PUT_BACK = ("The new password did not work ({why}) and the old one could not be put back everywhere ({left}). "
                  "Reset the password again.")
S_BUSY = "The website is being set up. Wait until it is running or stopped, then try again."
S_UNKNOWN = ("The database has a new password. The site's code must be given it: it cannot reach the database "
             "until then.")


def plan(site, r):
    """What a reset of `r` changes besides the database: {"kind": "php"|"env", "app": name, ...}, or None."""
    old = decrypt_secret(r.secret or "") or ""
    got = _wdp.app_settings(site, r)
    if got and old:
        return {"kind": "php", "app": got[0], "files": list(got[1]), "before": got[2]}
    if site.kind == "app" and old:
        from panel.routes.websites_settings import _saved_env
        names = _wdp.env_names(_saved_env(site), old)
        if names:
            return {"kind": "env", "app": "", "names": names}
    return None


def confirm_words(site, r):
    """What the reset dialog says will happen to the site's app, or "" (a database no app is known to use)."""
    p = plan(site, r)
    if p is None:
        return ""
    if p["kind"] == "php":
        return i18n.tr("{app}'s settings get the new password; the site keeps working.", app=p["app"])
    return i18n.tr("The app's variables ({names}) get the new password, and the app is restarted.",
                   names=", ".join(p["names"]))


def _set_env(site, old, new):
    from panel.routes.websites_settings import _saved_env
    env = _saved_env(site)
    for name in _wdp.env_names(env, old):
        env[name] = new
    site.env_enc = encrypt_secret(json.dumps(env, sort_keys=True))
    db.session.commit()
    return _w.host_call(_sw.env_apply, site.remote, site)


def _to_app(site, p, old, new):
    """Give the app `new` in place of `old`: (ok, sentence)."""
    if p["kind"] == "php":
        return _w.host_call(_sw.app_db_password, site.remote, site, p["files"], p["before"], old, new)
    return _set_env(site, old, new)


def _check(site, r, p, new):
    """Whether the site's database answers `new` from the site's network: (ok, sentence). An env app: its restart."""
    if p["kind"] != "php":
        return True, ""
    from panel.services import websites_catalog as _wc
    from panel.services import websites_recipes as _wr
    steps = (_wc.recipe(site.app_recipe) or {}).get("steps") or []
    prefix = next((s.get("tables") for s in steps if s.get("type") == "verify-install" and "tables" in s), "")
    db_port = (_w.site_db(site) or ("", 3306))[1]
    values = _wr.values_for(site, db={"name": r.name, "user": r.name, "password": new})
    return _w.host_call(_sw.db_reaches, site.remote, site, values, prefix or "", db_port)


def _change(site, r, hd, p, part, old, new):
    """Change one part, the app's settings ("app") or the database's user ("db"), from `old` to `new`."""
    if part == "app":
        return _to_app(site, p, old, new)
    return _dbs.set_password(site.remote, hd, r.name, new)


def _undo(site, r, hd, p, done, old, new, why):
    """Put the old password back in each part of `done`, after `why`: the sentence saying how it went."""
    left = []
    for part in reversed(done):
        ok, said = _change(site, r, hd, p, part, new, old)
        if not ok:
            left.append(i18n.tr(said))
    if left:
        return i18n.Sentence(S_NOT_PUT_BACK, why=i18n.tr(why), left="; ".join(left))
    return i18n.Sentence(S_PUT_BACK, why=i18n.tr(why))


def _with_app(site, r, hd, p):
    """The reset with the app kept in step: (ok, sentence).

    A PHP app's settings change first (refused, when they do not hold the current password, with nothing
    changed); a Node.js app's variables last, as writing them restarts the app, which then signs in with them.
    """
    old, new = decrypt_secret(r.secret), _dbs.new_password()
    done = []
    for part in ("app", "db") if p["kind"] == "php" else ("db", "app"):
        ok, said = _change(site, r, hd, p, part, old, new)
        if not ok:
            return False, _undo(site, r, hd, p, done, old, new, said) if done else said
        done.append(part)
    ok, said = _check(site, r, p, new)
    if not ok:
        return False, _undo(site, r, hd, p, done, old, new, said)
    r.secret = encrypt_secret(new)
    db.session.commit()
    if p["kind"] == "php":
        return True, i18n.Sentence(S_KEPT, app=p["app"])
    return True, i18n.Sentence(S_ENV_KEPT, names=", ".join(p["names"]))


def reset(site, r):
    """POST .../reset-password: the reset, audited; the new password in the answer only when no app has it."""
    hd = _d._host_row(site.remote_id)
    if hd is None:
        return _w.say(409, _d._NOT_READY)
    p = plan(site, r)
    detail = "new password for database %s" % r.name
    if p is not None and _w.setting_up(site.id):
        return _w.say(409, S_BUSY)
    if p is not None:
        ok, said = _with_app(site, r, hd, p)
        words = "%s, %s kept in step" % (detail, p["app"] or "the app's variables") if ok else "%s failed: %s" % (
            detail, i18n.tr(said))
        return _w.acted(site, "website_db_password", ok, said, words)
    secret = _dbs.new_password()
    ok, said = _dbs.set_password(site.remote, hd, r.name, secret)
    if not ok:
        return _w.acted(site, "website_db_password", ok, said, detail)
    r.secret = encrypt_secret(secret)
    db.session.commit()
    _w.audit(site, "website_db_password", detail)
    return _d._no_store(jsonify({"success": True, "message": i18n.tr(S_UNKNOWN), "password": secret}))
