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
import ipaddress
import re
import secrets as _secrets
import string
from types import SimpleNamespace

from panel.core import i18n
from panel.ops.ssh_manager import _core, firewall as _fw, ufweval
from panel.security import privileged as _priv

SLUG_RE = r"^[a-z0-9]{1,16}$"
PASSWORD_LENGTH = 32
_PW_FIRST = string.ascii_letters
_PW_ALPHABET = string.ascii_letters + string.digits + "-_."
_PW_CLASSES = (str.isupper, str.islower, str.isdecimal, "-_.".__contains__)

# Seconds each verb may take. A dump and an import scale with the database; an install with apt.
TIMEOUTS = {"db-probe": 45, "db-admin-check": 30, "db-create": 60, "db-password": 60, "db-rehost": 60,
            "db-sizes": 30, "db-dump": 1800, "db-import": 1800, "db-drop": 1800, "db-harden": 180}
APT_TIMEOUT = 900
# The oldest servers the panel manages: MariaDB 10.4 (unix_socket root, ALTER USER, DROP USER IF
# EXISTS) and MySQL 8.0 (caching_sha2_password, auth_socket root on Ubuntu).
MIN_MARIADB = (10, 4)
MIN_MYSQL = (8, 0)
_LOOPBACK = ("127.0.0.1", "::1", "localhost")
# The ports a MySQL or MariaDB server answers on besides the one it reports (MySQL's X protocol).
DB_PORTS = (3306, 33060)
# What the host's firewall verdict makes of a server listening on the network (_reach_keys): the
# firewall lets no other machine reach it (an info line, not a warning), or it could not be read.
_FIREWALL_KEY = {"blocked": "firewalled", "unknown": "firewall_unknown"}

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
S_DROPPED_EMPTY = "Database {name} was deleted. It held nothing, so no copy was kept."
S_NOT_EMPTY = "No copy of {name} could be kept, and it is not empty, so it was not deleted."
S_DROP_FAILED = "Database {name} could not be deleted."
S_INSTALLED = "MariaDB was installed and set up, listening on this machine only."
S_INSTALL_FAILED = "MariaDB could not be installed: apt did not finish."
S_FOREIGN = ("MariaDB is installed, but it already holds databases the panel did not make, so the panel "
             "left its settings alone.")
S_HARDEN_FAILED = "MariaDB was installed, but setting it up did not finish."
S_LOGIN_REFUSED = ("The database server refused the panel's stored admin login. A super admin can replace or "
                   "clear it on the Databases tab.")

# The client's and the dump tool's words for a sign-in the server refused (1045: wrong user or
# password; 1698: a plugin login such as unix_socket refused).
_DENIED_MARKS = _priv.DB_DENIED_ERRORS + ("Got error: 1045", "Got error: 1698")
# Remote id -> True while the stored admin login of that host's server is refused (the tab says so).
LOGIN_REFUSED = {}


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
    """Return a random database password.

    PASSWORD_LENGTH characters from `secrets`, starting with a letter, with at least one upper-case
    letter, lower-case letter, digit and one of - _ .

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
    """The verb's sign-in for `hostdb`: the socket, a login on 127.0.0.1, or a login on a tailnet server.

    `hostdb` is a HostDatabaseServer, a DatabaseEndpoint, or a view of either (target_view) that
    carries the server's `address` and the game host's `client` address its accounts are made for.
    """
    if hostdb.auth_mode != "login":
        return "socket"
    addr = getattr(hostdb, "address", "") or ""
    return "tcp%d" % int(hostdb.port or 3306) + ("@" + addr if addr else "")


def _client_args(hostdb):
    """The verb's optional last argument: the one game-host address the accounts are made for."""
    client = getattr(hostdb, "client", None)
    return [client] if client else []


def _drop_args(hostdb):
    """db-drop's optional arguments: the account host, then `kept` when a copy was already made."""
    return _client_args(hostdb) + (["kept"] if getattr(hostdb, "copy_kept", False) else [])


def copy_kept(hostdb):
    """`hostdb` as a drop target whose copy was already kept (by the database's own account): no second dump."""
    return SimpleNamespace(**dict(vars(target_view(hostdb, client=getattr(hostdb, "client", None))), copy_kept=True))


def target_view(hostdb, client=None, login=None, address=None):
    """`hostdb` as a verb target that makes accounts for `client`, signs in with `login`, at `address`.

    login: (user, encrypted secret) in place of the stored admin login (a database's own account,
    for a dump or a sign-in check from its game host); address: the tailnet address a game host
    reaches the server at. Nothing is written to `hostdb`.
    """
    user, secret = login if login else (getattr(hostdb, "admin_user", ""), getattr(hostdb, "admin_secret", ""))
    return SimpleNamespace(
        flavor=hostdb.flavor, native_ok=hostdb.native_ok, port=hostdb.port,
        auth_mode="login" if (login or address or hostdb.auth_mode == "login") else "socket",
        address=address if address is not None else (getattr(hostdb, "address", "") or ""),
        admin_user=user, admin_secret=secret, client=client)


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


def _admin_verb(remote, hostdb, verb, args, pw=None):
    """Run a verb signed in as the server's administrator: (rc, output, stored login refused).

    Only a host in login mode can have its login refused; what each call finds is kept in
    LOGIN_REFUSED for the tab, until a call signs in again or the login is replaced or cleared.
    """
    rc, out = _verb(remote, verb, args, _secrets_for(hostdb, pw))
    if hostdb.auth_mode != "login" or rc == 2:
        return rc, out, False
    refused = rc != 0 and any(m in out for m in _DENIED_MARKS)
    key = getattr(remote, "id", None)
    if refused:
        LOGIN_REFUSED[key] = True
    elif rc == 0:
        LOGIN_REFUSED.pop(key, None)
    return rc, out, refused


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


def _private_bind(host):
    """Whether a bind address reaches no other machine but over Tailscale: loopback, or a tailnet address."""
    if host in _LOOPBACK or host.startswith("127."):
        return True
    try:
        return ufweval.in_tailnet(ipaddress.ip_address(host))
    except ValueError:
        return False                # '*', '0.0.0.0', '::' and a name all reach every interface


def _exposed(v, listeners):
    """Whether the server listens beyond loopback and the tailnet: its bind-address, or a listener ss saw."""
    binds = [b.strip() for b in v.get("bind_address", "").split(",") if b.strip()]
    return (any(not _private_bind(b) for b in binds)
            or any(not _private_bind(a.rsplit(":", 1)[0].strip("[]")) for a in listeners))


def _on_tailnet(v, listeners):
    """Whether the server listens on a tailnet address (and nowhere beyond it: _exposed is False)."""
    binds = [b.strip() for b in v.get("bind_address", "").split(",") if b.strip()]
    hosts = binds + [a.rsplit(":", 1)[0].strip("[]") for a in listeners]
    return any(_private_bind(h) and not _is_loopback(h + ":0") for h in hosts)


def _reach_keys(v, listeners, firewall):
    """Who can reach the server, as one key: exposed, firewall_unknown, firewalled, tailnet, or none."""
    if _exposed(v, listeners):
        return [_FIREWALL_KEY.get(firewall, "exposed")]
    return ["tailnet"] if _on_tailnet(v, listeners) else []


def _warnings(v, listeners, flavor, native_ok, firewall=None):
    """The warning keys for a server's variables and listeners.

    `firewall` is _firewall_verdict's answer for a server that listens on the network: 'blocked'
    drops the exposed warning (the host's firewall lets no other machine reach the port), 'unknown'
    says it could not be checked instead, and 'open' or None keeps it.
    """
    out = _reach_keys(v, listeners, firewall)
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


def _ufw_rule_lines(out):
    """The rule lines of `ufw status verbose`: everything after its "--" underline."""
    lines = out.splitlines()
    at = next((i for i, line in enumerate(lines) if line.strip().startswith("--")), None)
    return [] if at is None else [line for line in lines[at + 1:] if line.strip()]


def _rule_opens(line, ports):
    """Whether one ufw rule line lets another machine reach any of `ports` (a maybe counts as yes).

    A rule on a Tailscale interface or on one that carries only this machine's own traffic (lo,
    docker0...) reaches no other machine but the tailnet.
    """
    spec = ufweval.row_spec(_fw._parse_ufw_rule(line))
    iface = spec["iface"]
    if spec["action"] not in ("ALLOW", "LIMIT") or spec["direction"] != "IN":
        return False
    if iface.startswith("tailscale") or ufweval._HOST_ONLY_IFACE_RE.match(iface.rstrip("+") or "-"):
        return False
    return any(ufweval._port_match(spec["dports"], spec["proto"], p, None) != ufweval.NO for p in ports)


def ufw_db_verdict(out, rc, ports):
    """'blocked', 'open' or 'unknown': whether the host's ufw lets another machine reach `ports`.

    `out`/`rc` are `ufw status verbose`'s. 'open' for no ufw, an inactive one, a default incoming
    allow, or an IN rule allowing one of the ports other than on tailscale0 or a host-only
    interface; 'unknown' for a read that failed or a status this cannot read (never 'open': a host
    that could not be checked is said to be so).
    """
    if rc == 127:
        return "open"
    if rc != 0 or not (out or "").strip():
        return "unknown"
    if not _fw._ufw_is_active(out):
        return "open"
    m = _fw._FWA_DEFAULT_RE.search(out)
    if not m:
        return "unknown"
    if m.group(1) == "allow" or any(_rule_opens(line, ports) for line in _ufw_rule_lines(out)):
        return "open"
    return "blocked"


def _firewall_verdict(remote, port):
    """ufw_db_verdict for `remote`'s database ports (3306, 33060 and `port`), read with one ufw-status.

    Read only, through the verb the Network tab reads it with; nothing is changed.
    """
    try:
        out, _err, rc = _core.run_privileged(remote, "ufw-status", ["verbose"], timeout=15, sudo=None)
    except Exception:
        return "unknown"
    return ufw_db_verdict(out, rc, sorted(set(DB_PORTS) | {int(port)}))


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
    return _probe_answer(remote, facts, state, detail, flavor)


def _probe_answer(remote, facts, state, detail, flavor):
    """The probe's dict from what it read; the host's firewall is read for a server on the network only."""
    v = facts["vars"]
    native_ok = flavor == "mariadb" or v.get("native", "").upper() == "ACTIVE"
    port = int(v["port"]) if v.get("port", "").isdecimal() else 3306
    # The firewall is read only for a server that listens on the network: one more call, then.
    fw = _firewall_verdict(remote, port) if state != "none" and _exposed(v, facts["listeners"]) else None
    return {"state": state, "detail": detail, "flavor": flavor, "version": v.get("version", "")[:40],
            "port": port, "native_ok": native_ok, "firewall": fw,
            "warnings": _warnings(v, facts["listeners"], flavor, native_ok, fw) if state != "none" else [],
            "socket_root": facts["socket_root"], "packages": facts["pkgs"],
            "listeners": facts["listeners"]}


def _apt_install(remote, package="mariadb-server"):
    """apt-install `package`; on 22.04/24.04 add universe and retry once. True when it worked."""
    out, err, rc = _core.run_privileged(remote, "apt-install", [package], timeout=APT_TIMEOUT)
    if rc == 0:
        return True
    text = "%s\n%s" % (out, err)
    if "Unable to locate package" not in text and "no installation candidate" not in text:
        return False
    _core.run_privileged(remote, "apt-add-repo", ["universe"], timeout=APT_TIMEOUT)
    _core.run_privileged(remote, "apt-update", [], timeout=APT_TIMEOUT)
    return _core.run_privileged(remote, "apt-install", [package], timeout=APT_TIMEOUT)[2] == 0


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


def admin_check(remote, port, user, pw):
    """(verdict, server variables) for an admin login on 127.0.0.1:`port`.

    verdict: 'ok', 'denied', 'lacks_grants' or 'unreadable'. The variables are what the login read
    of the server (version, port, native logins: db-probe's var. lines), {} when it could not sign in.
    """
    if not (re.fullmatch(_priv.DB_ADMIN_USER_RE, str(user or ""))
            and re.fullmatch(_priv.DB_ADMIN_PW_RE, str(pw or ""))):
        return "denied", {}         # a login no client could be handed is a login that cannot sign in
    rc, out = _verb(remote, "db-admin-check", ["mariadb", "tcp%d" % int(port)], {"admin": (user, pw)})
    verdict = _admin_verdict(rc, out)
    v = _parse_probe(out)["vars"] if verdict in ("ok", "scoped", "lacks_grants") else {}
    return _scoped(verdict, v)


def _scoped(verdict, v):
    """(verdict, v) with the narrow grant's 'scoped' read as a working login, or as 'partial_revokes'.

    The narrow grant names its databases `gs%`: a wildcard, unless MySQL's partial_revokes is on,
    which reads % and _ in a grant literally, so the login could make no gs<n>_ database.
    """
    if verdict == "scoped":
        verdict = "partial_revokes" if v.get("partial_revokes", "").upper() == "ON" else "ok"
    return verdict, v


def _admin_verdict(rc, out):
    """db-admin-check's verdict: a word of its own line; a variable's value (var.x=…) never counts as one."""
    words = [w for line in out.splitlines() if not line.startswith("var.") for w in line.split()]
    return next((a for a in ("ok", "scoped", "denied", "lacks_grants") if rc == 0 and a in words), "unreadable")


# The dedicated login the tab offers instead of a server's own root or master login (`password` is
# filled in on the viewer's page). It signs in over TCP from this host, so its host is 127.0.0.1.
SCOPED_USER = "linuxgsm_panel"
SCOPED_HOST = "127.0.0.1"


def scoped_grant_sql(password, user=SCOPED_USER, host=SCOPED_HOST):
    """The statements that make the dedicated panel login with the narrow grant (DB_SCOPED_GRANT_MARKS).

    For the operator to run on their own server, as its administrator; the panel never runs them.
    CREATE USER is a server-wide right (it can change or drop any account), so the login is as
    trusted as an administrator in that respect; the rest is limited to the gs% databases and to
    mysql.user's User and Host columns.
    """
    a = "'%s'@'%s'" % (user, host)
    return ("CREATE USER %s IDENTIFIED BY '%s';\n"
            "GRANT CREATE USER ON *.* TO %s;\n"
            "GRANT SELECT (User, Host) ON mysql.user TO %s;\n"
            "GRANT ALL PRIVILEGES ON `gs%%`.* TO %s WITH GRANT OPTION;\n" % (a, password, a, a, a))


def check_admin_login(remote, port, user, pw):
    """'ok', 'denied', 'lacks_grants' or 'unreadable' for an admin login on 127.0.0.1:`port`."""
    return admin_check(remote, port, user, pw)[0]


def with_login_facts(p, v):
    """Probe `p` (root could not sign in over the socket) completed with what an admin login read.

    The socket probe sees packages and listeners only, so a server reached through a stored login had
    no version and no native-login answer, and every account was made caching_sha2 even where
    mysql_native_password is offered. `v` is admin_check's variables; {} leaves `p` as it is.
    """
    if not v:
        return p
    text = (v.get("version", "") + " " + v.get("version_comment", "")).lower()
    flavor = "mariadb" if "mariadb" in text else "mysql"
    native_ok = flavor == "mariadb" or v.get("native", "").upper() == "ACTIVE"
    port = int(v["port"]) if v.get("port", "").isdecimal() else p.get("port", 3306)
    return dict(p, flavor=flavor, version=v.get("version", "")[:40], port=port, native_ok=native_ok,
                warnings=_warnings(v, p.get("listeners") or [], flavor, native_ok, p.get("firewall")))


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
    args = [hostdb.flavor, _auth(hostdb), name, plugin_for(hostdb), str(int(maxconn))] + _client_args(hostdb)
    with db_lock(remote):
        rc, _out, refused = _admin_verb(remote, hostdb, "db-create", args, pw)
    if refused:
        return False, S_LOGIN_REFUSED
    if rc == 3:
        return False, i18n.Sentence(S_EXISTS, name=name)
    return _sentence(rc, S_CREATED, S_CREATE_FAILED, name=name)


def set_password(remote, hostdb, name, pw):
    """Give both of `name`'s accounts password `pw`: (ok, sentence)."""
    args = [hostdb.flavor, _auth(hostdb), name, plugin_for(hostdb)] + _client_args(hostdb)
    with db_lock(remote):
        rc, _out, refused = _admin_verb(remote, hostdb, "db-password", args, pw)
    if refused:
        return False, S_LOGIN_REFUSED
    return _sentence(rc, S_PW_CHANGED, S_PW_FAILED, name=name)


def sizes(remote, hostdb, account, names):
    """What the list shows of `names`, in ONE call; None if unreadable.

    {"sizes": {name: bytes} (0 for a database with no tables), "dumps": {name: the Unix time of
    the dump in `account`'s ~/panel-db-dumps}} (a name with no dump there is not in "dumps").
    `account` "-" reads no dumps.
    """
    names = list(names)
    if not names:
        return {"sizes": {}, "dumps": {}}
    rc, out, _refused = _admin_verb(remote, hostdb, "db-sizes",
                                    [hostdb.flavor, _auth(hostdb), account or "-"] + names)
    if rc != 0:
        return None
    got, dumps = {n: 0 for n in names}, {}
    for line in out.splitlines():
        name, _t, val = line.partition("\t")
        val = val.strip()
        if not val.isdecimal():
            continue
        if name in got:
            got[name] = int(val)
        elif name.startswith("dump=") and name[5:] in got:
            dumps[name[5:]] = int(val)
    return {"sizes": got, "dumps": dumps}


def _account_refusal(remote, account):
    """The root-capable-account guard for a dump or import run as `account`: a sentence, or None."""
    from panel.routes import _shared
    return _shared.game_account_write_refusal(remote, account)


def dump(remote, hostdb, dest, account, names):
    """Dump `names` in one call. -> (ok, sentence).

    dest 'game' writes into the account's ~/panel-db-dumps, as the account; 'archive' into the
    host's root-only archive.

    A dump into the game's files first asks the root-capable-account guard: an account that can
    become root is never written as.
    """
    names = list(names)
    why = _account_refusal(remote, account) if dest == "game" and names else None
    if why:
        return False, why
    rc, out, refused = (_admin_verb(remote, hostdb, "db-dump", [hostdb.flavor, _auth(hostdb), dest, account or "-"]
                                    + names) if names else (0, "", False))
    if refused:
        return False, S_LOGIN_REFUSED
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
    """Import ~/panel-db-dumps/<name>.sql.gz into `name`. -> (ok, sentence).

    Run as `account` and signed in as the database's own account (password `pw`). Asks the
    root-capable-account guard first. `ok` is None when there is no dump to restore (nothing was
    touched).
    """
    why = _account_refusal(remote, account)
    if why:
        return False, why
    addr = getattr(hostdb, "address", "") or ""
    target = str(int(hostdb.port or 3306)) + ("@" + addr if addr else "")
    rc, _out = _verb(remote, "db-import", [hostdb.flavor, target, account, name], {"pw": pw})
    if rc == 4:
        return None, i18n.Sentence(S_NO_DUMP, name=name)
    return _sentence(rc, S_RESTORED, S_RESTORE_FAILED, name=name)


def drop(remote, hostdb, account, name):
    """Delete `name` and its accounts after keeping a copy in the host's archive: (ok, sentence).

    `account` is not needed: the copy goes to the root-only archive, which outlives the server's
    files. With no copy only an empty database is deleted.
    """
    del account
    with db_lock(remote):
        rc, _out, refused = _admin_verb(remote, hostdb, "db-drop", [hostdb.flavor, _auth(hostdb), name]
                                        + _drop_args(hostdb))
    if refused:
        return False, S_LOGIN_REFUSED
    if rc == 3:
        return False, i18n.Sentence(S_NOT_EMPTY, name=name)
    # "nocopy": the database held nothing (or was already gone), so there was nothing to keep.
    return _sentence(rc, S_DROPPED_EMPTY if "nocopy" in _out.split() else S_DROPPED, S_DROP_FAILED, name=name)


# ── a database server on another machine (over Tailscale) ──────────────────────────────────────
# The client's words for "nothing answered there" (2002 socket, 2003 TCP, 2013 lost during the
# handshake) and for "this server takes TLS connections only" (MySQL 3159, MariaDB 4036).
_UNREACHABLE_MARKS = ("ERROR 2002", "ERROR 2003", "ERROR 2013")
_TLS_MARKS = ("ERROR 3159", "ERROR 4036")
# ...and "this password type wants TLS or the server's key" (2061, caching_sha2_password).
_KEY_MARKS = _priv.DB_KEY_ERRORS
# MySQL 8: the account is the definer of an event or routine, so a login without SET_USER_ID may not
# rename or drop it (ER_CANNOT_USER_REFERENCED_AS_DEFINER).
_DEFINER_MARKS = ("ERROR 4006",)
_SEEN_RE = re.compile(r"Access denied for user '[^']*'@'([0-9A-Fa-f:.]{2,45})'")
S_NET_UNREACHABLE = ("{host} can't reach the database server at {address}, port {port}. Check that it listens on "
                     "that address and that its firewall lets {host} in over Tailscale; the panel changes neither.")
S_NET_DENIED = "The database server refused the new account from {host}."
S_NET_SEEN = "The database server sees {host} as {seen}, not {client}."
S_NET_TLS = "This database server only accepts TLS connections; the panel can use it over Tailscale only without TLS."
S_NET_ERROR = "The database server could not be reached from {host}."
S_NET_KEY = ("The database server would not take this login's password without TLS (caching_sha2_password, error "
             "2061), and it did not send its public key. Make the login with mysql_native_password, or let the "
             "server hand out its key.")
S_REHOST_DEFINER = ("MySQL refused to move the account of {name}: it defines an event or a stored routine in its "
                    "database (error 4006), which only a login with SET_USER_ID may move. Nothing was changed.")


def _net_kind(rc, out):
    """'ok', 'noclient', 'unreachable', 'tls', 'keyauth', 'denied' or 'error' for a sign-in from a game host."""
    if rc in (0, 127):
        return "ok" if rc == 0 else "noclient"
    low = out.lower()
    # The first family the client's words match, in this order; anything else is an error.
    families = (("keyauth", any(m in out for m in _KEY_MARKS)),
                ("tls", any(m in out for m in _TLS_MARKS) or "secure transport" in low),
                ("unreachable", any(m in out for m in _UNREACHABLE_MARKS)),
                ("denied", any(m in out for m in _DENIED_MARKS)))
    return next((kind for kind, hit in families if hit), "error")


def seen_in(out):
    """The address a refused sign-in says the server saw (its 1045 text), when it is a tailnet address."""
    m = _SEEN_RE.search(out or "")
    if not m:
        return ""
    try:
        return _priv.db_net_addr(str(ipaddress.ip_address(m.group(1))))
    except (ValueError, _priv.VerbError):
        return ""


def endpoint_check(remote, address, port, user, pw):
    """(verdict, server variables) for an admin login on the server at `address`:`port`, signed in from `remote`.

    As admin_check, from a game host to a server on another machine over the tailnet; verdict also
    'noclient' (the game host has no database client), 'unreachable' or 'tls'.
    """
    if not (re.fullmatch(_priv.DB_ADMIN_USER_RE, str(user or ""))
            and re.fullmatch(_priv.DB_ADMIN_PW_RE, str(pw or ""))):
        return "denied", {}
    rc, out = _verb(remote, "db-admin-check", ["mariadb", "tcp%d@%s" % (int(port), address)],
                    {"admin": (user, pw)})
    if rc == 0:
        verdict, v = _scoped(_admin_verdict(rc, out), _parse_probe(out)["vars"])
        return verdict, (v if verdict != "denied" else {})
    if rc == 127:
        return "noclient", {}
    words = out.split()
    return next((w for w in ("unreachable", "keyauth", "tls") if w in words), "unreadable"), {}


def sign_in_check(remote, hostdb, name, pw):
    """Sign in from game host `remote` as database `name`'s own account: (kind, address the server saw).

    kind as _net_kind. The proof that a new account works from where the game connects, made before
    the database is kept; one db-sizes call, which reads nothing but its own database's size.
    """
    view = target_view(hostdb, login=(name, _encrypt(pw)))
    rc, out = _verb(remote, "db-sizes", [view.flavor, _auth(view), "-", name], _secrets_for(view))
    return _net_kind(rc, out), seen_in(out)


def _encrypt(pw):
    from panel.core.config import encrypt_secret
    return encrypt_secret(pw)


def rehost(remote, hostdb, name, old, new):
    """Move `name`'s account from game-host address `old` to `new`: (ok, sentence)."""
    with db_lock(remote):
        rc, _out, refused = _admin_verb(remote, hostdb, "db-rehost", [hostdb.flavor, _auth(hostdb), name, old, new])
    _out = _out or ""
    if refused:
        return False, S_LOGIN_REFUSED
    if rc != 0 and any(m in _out for m in _DEFINER_MARKS):
        return False, i18n.Sentence(S_REHOST_DEFINER, name=name)
    return _sentence(rc, "The account of {name} now signs in from {new}.",
                     "The database server did not move the account of {name}.", name=name, new=new)


CLIENT_PACKAGES = {"mariadb": "mariadb-client", "mysql": "mysql-client"}


def install_client(remote, flavor):
    """Install the database client for `flavor` on `remote` from Ubuntu: True when it worked."""
    return _apt_install(remote, CLIENT_PACKAGES.get(flavor, "mariadb-client"))
