"""A game server's MariaDB/MySQL databases on its own host: the service layer the routes call.

Every call goes through `_core.run_privileged` with a db-* verb (panel/security/privileged.py and
tools/panel-helper hold the verbs, their validators and their SQL). Passwords are passed as that
call's `secrets`, so they travel on stdin on every transport and are scrubbed out of the answer.

What comes back to a caller is a fixed sentence (an i18n.Sentence where it names something), never
the client's own words: those can quote a statement, and the routes show them to the viewer.

This module is not one of the package's _MODULES (its generic names, create and drop, must not
shadow another submodule's through the package's __getattr__): import it by name,
`from panel.ops.ssh_manager import databases`.
"""
import re
import secrets as _secrets
import string

from panel.core import i18n
from panel.ops.ssh_manager import _core
from panel.security import privileged as _priv

SLUG_RE = r"^[a-z0-9]{1,16}$"
PASSWORD_LENGTH = 32
_PW_FIRST = string.ascii_letters
_PW_ALPHABET = string.ascii_letters + string.digits + "-_."
_PW_CLASSES = (str.isupper, str.islower, str.isdecimal, "-_.".__contains__)

# Seconds each verb may take. A dump and an import scale with the database; an install with apt.
TIMEOUTS = {"db-probe": 45, "db-admin-check": 30, "db-create": 60, "db-password": 60,
            "db-sizes": 30, "db-dump": 1800, "db-import": 1800, "db-drop": 1800, "db-harden": 180}
APT_TIMEOUT = 900
# The oldest servers the panel manages: MariaDB 10.4 (unix_socket root, ALTER USER, DROP USER IF
# EXISTS) and MySQL 8.0 (caching_sha2_password, auth_socket root on Ubuntu).
MIN_MARIADB = (10, 4)
MIN_MYSQL = (8, 0)
_LOOPBACK = ("127.0.0.1", "::1", "localhost")

S_UNREADABLE = ("The host did not answer, so the database server could not be checked. "
                "Nothing was changed.")
S_NO_CLIENT = "This host has no database client (mariadb or mysql), so the panel can't manage its databases."
S_REFUSED = "The panel refused that request. Nothing was changed."
S_CREATED = "Database {name} was created."
S_EXISTS = ("A database or account named {name} already exists on this host, and the panel never takes over "
            "one it did not make.")
S_CREATE_FAILED = "The database server refused to create {name}. Nothing was kept."
S_PW_CHANGED = "The password of database {name} was changed."
S_PW_FAILED = "The database server refused the new password of {name}; the old one still works."
S_DUMPED_GAME = "The databases were saved into the server's files."
S_DUMPED_ARCHIVE = "A copy of the databases was kept on the host for 30 days."
S_DUMP_FAILED = "These databases could not be saved: {names}."
S_RESTORED = "Database {name} was restored from the dump in the server's files."
S_NO_DUMP = "There is no dump of {name} in the server's files (panel-db-dumps/{name}.sql.gz)."
S_RESTORE_FAILED = "The restore of {name} did not finish; the database may hold part of the dump."
S_DROPPED = "Database {name} was deleted. A copy is kept on the host for 30 days."
S_NOT_EMPTY = "No copy of {name} could be kept, and it is not empty, so it was not deleted."
S_DROP_FAILED = "Database {name} could not be deleted."
S_INSTALLED = "MariaDB was installed and set up, listening on this machine only."
S_INSTALL_FAILED = "MariaDB could not be installed: apt did not finish."
S_FOREIGN = ("MariaDB is installed, but it already holds databases the panel did not make, so the panel "
             "left its settings alone.")
S_HARDEN_FAILED = "MariaDB was installed, but setting it up did not finish."


def db_lock(remote):
    """The lock create, drop, password and setup on one host are made under."""
    return _core._host_lock("db", remote)


def db_name(server_id, slug):
    """'gs<server_id>_<slug>' for a game server's database; ValueError on a bad id or slug."""
    if isinstance(server_id, bool) or not isinstance(server_id, int) or server_id < 1:
        raise ValueError("not a server id")
    if not isinstance(slug, str) or not re.match(SLUG_RE, slug) or slug.endswith("\n"):
        raise ValueError("a database name is 1 to 16 lower-case letters and digits")
    name = "gs%d_%s" % (server_id, slug)
    if not re.fullmatch(_priv.DB_NAME_RE, name):
        raise ValueError("not a game database name")
    return name


def new_password():
    """A random database password: PASSWORD_LENGTH characters from `secrets`, starting with a letter,
    with at least one upper-case letter, lower-case letter, digit and one of - _ .

    Nothing in it needs quoting in SQL, a client option file, YAML, KeyValues, INI or an oxmysql
    connection URI, and it passes MySQL's validate_password MEDIUM policy.
    """
    while True:
        pw = _secrets.choice(_PW_FIRST) + "".join(_secrets.choice(_PW_ALPHABET)
                                                  for _ in range(PASSWORD_LENGTH - 1))
        if all(any(test(c) for c in pw) for test in _PW_CLASSES):
            return pw


def plugin_for(hostdb):
    """'native' where the server offers mysql_native_password (every MariaDB), else 'sha2'."""
    return "native" if hostdb.flavor == "mariadb" or hostdb.native_ok else "sha2"


def auth_plugin_name(plugin):
    """The GameDatabase.auth_plugin value for a plugin_for answer."""
    return "mysql_native_password" if plugin == "native" else "caching_sha2_password"


def _auth(hostdb):
    return "socket" if hostdb.auth_mode != "login" else "tcp%d" % int(hostdb.port or 3306)


def _secrets_for(hostdb, pw=None):
    """run_privileged's `secrets` for `hostdb`: its admin login in login mode, and `pw`."""
    out = {"pw": pw} if pw else {}
    if hostdb.auth_mode == "login":
        from panel.core.config import decrypt_secret
        out["admin"] = (hostdb.admin_user or "", decrypt_secret(hostdb.admin_secret or "") or "")
    return out


def _verb(remote, verb, args, secrets=None):
    """One db-* verb: (rc, output), the output scrubbed of every secret it was given.

    The helper scrubs what the client printed on the panel's own host; this covers a remote and the
    pre-helper shell too, before any caller sees a word. A verb the panel's own table refuses is
    rc 2, with nothing run.
    """
    try:
        out, err, rc = _core.run_privileged(remote, verb, list(args), timeout=TIMEOUTS[verb],
                                            secrets=secrets or {})
    except _priv.VerbError:
        return 2, ""
    return rc, _priv.db_scrub("\n".join(x for x in (out, err) if x), _priv._db_secret_values(secrets))


def _version_tuple(text):
    m = re.match(r"(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _parse_probe(out):
    """The probe's key=value lines as {pkgs, listeners, active, vars, socket_root}."""
    facts = {"pkgs": {}, "listeners": [], "active": {}, "vars": {}, "socket_root": ""}
    for line in out.splitlines():
        key, sep, val = line.partition("=")
        if not sep:
            continue
        if key == "pkg":
            name, _t, ver = val.partition("\t")
            facts["pkgs"][name] = ver
        elif key == "listen":
            facts["listeners"].append(val)
        elif key.startswith("active."):
            facts["active"][key[7:]] = val
        elif key.startswith("var."):
            facts["vars"][key[4:]] = val
        elif key == "socket_root":
            facts["socket_root"] = val
    return facts


def _is_loopback(addr):
    host = addr.rsplit(":", 1)[0].strip("[]")
    return host in _LOOPBACK or host.startswith("127.")


def _exposed(v, listeners):
    """Whether the server listens beyond loopback: its bind-address, or a listener ss saw."""
    binds = [b.strip() for b in v.get("bind_address", "").split(",") if b.strip()]
    return any(b not in _LOOPBACK for b in binds) or any(not _is_loopback(a) for a in listeners)


def _warnings(v, listeners, flavor, native_ok):
    """The warning keys for a server's variables and listeners."""
    out = ["exposed"] if _exposed(v, listeners) else []
    if v.get("skip_networking", "").upper() == "ON":
        out.append("skip_networking")
    if v.get("require_secure_transport", "").upper() == "ON":
        out.append("tls_required")
    if flavor == "mysql" and not native_ok:
        out.append("old_logins_only")
    return out


def _flavor_state(v, pkgs):
    """(flavor, state) for a server root signed in to: 'ready' or 'unsupported'."""
    text = (v.get("version", "") + " " + v.get("version_comment", "")).lower()
    flavor = "mariadb" if "mariadb" in text else "mysql"
    if "percona" in text or any(p.startswith("percona") for p in pkgs):
        return flavor, "unsupported"
    floor = MIN_MARIADB if flavor == "mariadb" else MIN_MYSQL
    return flavor, ("ready" if _version_tuple(v.get("version")) >= floor else "unsupported")


_ROOT_STATES = {"denied": ("needs_login", ""), "error": ("unreadable", "")}


def _no_socket_state(facts):
    """(state, detail) when root could not sign in over the socket."""
    root, pkgs, listeners = facts["socket_root"], facts["pkgs"], facts["listeners"]
    if root in _ROOT_STATES:
        return _ROOT_STATES[root]
    if any(p.startswith("percona") for p in pkgs):
        return "unsupported", "percona"
    if root == "noclient":
        return ("unsupported", "noclient") if (listeners or pkgs) else ("none", "")
    return _no_server_state(pkgs, listeners, any(s == "active" for s in facts["active"].values()))


def _no_server_state(pkgs, listeners, running):
    """(state, detail) when nothing answered on the socket."""
    if listeners:
        return "needs_login", ""            # a server with no socket here: Docker, an upstream build
    if running:
        return "unsupported", "nosocket"    # a service running with neither socket nor port
    if pkgs:
        return "unsupported", "stopped"
    return "none", ""


def probe(remote):
    """What database server `remote` has, as a dict.

    state: 'none' (offer setup), 'ready' (root signs in over the socket), 'needs_login' (a server is
    there but the socket sign-in is refused, or it only listens on a port), 'unsupported' (Percona,
    too old, stopped, no client; `detail` says which), 'unreadable' (the probe failed: never read
    as 'none'). Also flavor, version, port, native_ok, warnings (keys), socket_root, packages,
    listeners. Writes nothing on the host.
    """
    rc, out = _verb(remote, "db-probe", [])
    facts = _parse_probe(out) if rc == 0 else None
    if not facts or not facts["socket_root"]:
        # An empty answer is a failed read (memory of "" is not a measurement), never "no server".
        return {"state": "unreadable", "detail": "", "sentence": S_UNREADABLE, "flavor": "", "version": "", "port": 3306,
                "native_ok": True, "warnings": [], "socket_root": "", "packages": {}, "listeners": []}
    v = facts["vars"]
    flavor = "mariadb" if any(p.startswith("mariadb") for p in facts["pkgs"]) else "mysql"
    detail = ""
    if facts["socket_root"] == "ok":
        flavor, state = _flavor_state(v, facts["pkgs"])
    else:
        state, detail = _no_socket_state(facts)
    native_ok = flavor == "mariadb" or v.get("native", "").upper() == "ACTIVE"
    port = int(v["port"]) if v.get("port", "").isdecimal() else 3306
    return {"state": state, "detail": detail, "flavor": flavor, "version": v.get("version", "")[:40],
            "port": port, "native_ok": native_ok,
            "warnings": _warnings(v, facts["listeners"], flavor, native_ok) if state != "none" else [],
            "socket_root": facts["socket_root"], "packages": facts["pkgs"],
            "listeners": facts["listeners"]}


def _apt_install(remote):
    """apt-install mariadb-server; on 22.04/24.04 add universe and retry once. True when it worked."""
    out, err, rc = _core.run_privileged(remote, "apt-install", ["mariadb-server"], timeout=APT_TIMEOUT)
    if rc == 0:
        return True
    text = "%s\n%s" % (out, err)
    if "Unable to locate package" not in text and "no installation candidate" not in text:
        return False
    _core.run_privileged(remote, "apt-add-repo", ["universe"], timeout=APT_TIMEOUT)
    _core.run_privileged(remote, "apt-update", [], timeout=APT_TIMEOUT)
    return _core.run_privileged(remote, "apt-install", ["mariadb-server"], timeout=APT_TIMEOUT)[2] == 0


def install_mariadb(remote):
    """Install MariaDB from the Ubuntu archive and set it up: (ok, sentence, panel admin password).

    The password is linuxgsm_panel_admin's (the caller stores it encrypted); "" when setup did not
    run. The setup (db-harden) refuses a server holding databases the panel did not make, so a
    server that was already there is never reconfigured.
    """
    with db_lock(remote):
        if not _apt_install(remote):
            return False, S_INSTALL_FAILED, ""
        pw = new_password()
        rc, _out = _verb(remote, "db-harden", ["mariadb"], {"pw": pw})
    if rc == 0:
        return True, S_INSTALLED, pw
    if rc == 3:
        return False, S_FOREIGN, ""
    return False, S_HARDEN_FAILED, ""


def check_admin_login(remote, port, user, pw):
    """'ok', 'denied', 'lacks_grants' or 'unreadable' for an admin login on 127.0.0.1:`port`."""
    if not (re.fullmatch(_priv.DB_ADMIN_USER_RE, str(user or ""))
            and re.fullmatch(_priv.DB_ADMIN_PW_RE, str(pw or ""))):
        return "denied"             # a login no client could be handed is a login that cannot sign in
    rc, out = _verb(remote, "db-admin-check", ["mariadb", "tcp%d" % int(port)], {"admin": (user, pw)})
    words = out.split()
    for answer in ("ok", "denied", "lacks_grants"):
        if rc == 0 and answer in words:
            return answer
    return "unreadable"


def _sentence(rc, ok, fail, **vals):
    """The sentence for a write verb's rc: `ok`, `fail`, or the shared ones for 127 and 2."""
    if rc == 0:
        return True, i18n.Sentence(ok, **vals)
    if rc == 127:
        return False, S_NO_CLIENT
    if rc == 2:
        return False, S_REFUSED
    return False, i18n.Sentence(fail, **vals)


def create(remote, hostdb, name, pw, maxconn):
    """Make database `name` and its two accounts with password `pw`: (ok, sentence)."""
    args = [hostdb.flavor, _auth(hostdb), name, plugin_for(hostdb), str(int(maxconn))]
    with db_lock(remote):
        rc, _out = _verb(remote, "db-create", args, _secrets_for(hostdb, pw))
    if rc == 3:
        return False, i18n.Sentence(S_EXISTS, name=name)
    return _sentence(rc, S_CREATED, S_CREATE_FAILED, name=name)


def set_password(remote, hostdb, name, pw):
    """Give both of `name`'s accounts password `pw`: (ok, sentence)."""
    args = [hostdb.flavor, _auth(hostdb), name, plugin_for(hostdb)]
    with db_lock(remote):
        rc, _out = _verb(remote, "db-password", args, _secrets_for(hostdb, pw))
    return _sentence(rc, S_PW_CHANGED, S_PW_FAILED, name=name)


def sizes(remote, hostdb, names):
    """{name: bytes} for `names` in ONE call (0 for a database with no tables); None if unreadable."""
    names = list(names)
    if not names:
        return {}
    rc, out = _verb(remote, "db-sizes", [hostdb.flavor, _auth(hostdb)] + names, _secrets_for(hostdb))
    if rc != 0:
        return None
    got = {n: 0 for n in names}
    for line in out.splitlines():
        name, _t, size = line.partition("\t")
        if name in got and size.strip().isdecimal():
            got[name] = int(size.strip())
    return got


def _account_refusal(remote, account):
    """The root-capable-account guard for a dump or import run as `account`: a sentence, or None."""
    from panel.routes import _shared
    return _shared.game_account_write_refusal(remote, account)


def dump(remote, hostdb, dest, account, names):
    """Dump `names` (one call): dest 'game' into the account's ~/panel-db-dumps, written as the
    account, or 'archive' into the host's root-only archive. (ok, sentence).

    A dump into the game's files first asks the root-capable-account guard: an account that can
    become root is never written as.
    """
    names = list(names)
    why = _account_refusal(remote, account) if dest == "game" and names else None
    if why:
        return False, why
    rc, out = (_verb(remote, "db-dump", [hostdb.flavor, _auth(hostdb), dest, account or "-"] + names,
                    _secrets_for(hostdb)) if names else (0, ""))
    return _dump_answer(rc, out, dest, names)


def _dump_answer(rc, out, dest, names):
    """(ok, sentence) for a db-dump's rc and its dumped=/failed= lines."""
    if rc == 0:
        return True, S_DUMPED_GAME if dest == "game" else S_DUMPED_ARCHIVE
    if rc in (127, 2):
        return _sentence(rc, "", "")
    failed = [line[7:] for line in out.splitlines() if line.startswith("failed=")]
    return False, i18n.Sentence(S_DUMP_FAILED, names=", ".join(failed or names))


def restore(remote, hostdb, account, name, pw):
    """Import ~/panel-db-dumps/<name>.sql.gz into `name`, run as `account` and signed in as the
    database's own account (password `pw`). (ok, sentence). Asks the root-capable-account guard first."""
    why = _account_refusal(remote, account)
    if why:
        return False, why
    rc, _out = _verb(remote, "db-import", [hostdb.flavor, str(int(hostdb.port or 3306)), account, name],
                    {"pw": pw})
    if rc == 4:
        return False, i18n.Sentence(S_NO_DUMP, name=name)
    return _sentence(rc, S_RESTORED, S_RESTORE_FAILED, name=name)


def drop(remote, hostdb, account, name):
    """Delete `name` and its accounts after keeping a copy in the host's archive: (ok, sentence).

    `account` is not needed: the copy goes to the root-only archive, which outlives the server's
    files. With no copy only an empty database is deleted.
    """
    del account
    with db_lock(remote):
        rc, _out = _verb(remote, "db-drop", [hostdb.flavor, _auth(hostdb), name], _secrets_for(hostdb))
    if rc == 3:
        return False, i18n.Sentence(S_NOT_EMPTY, name=name)
    return _sentence(rc, S_DROPPED, S_DROP_FAILED, name=name)
