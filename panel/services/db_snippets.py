"""Ready-to-paste connection settings for a game server's database (the Databases tab).

Each kind is the config a game's database plugin reads, with this database's host, port, name, user
and password filled in. The keys are the plugins' own:

* LuckPerms (plugins/LuckPerms/config.yml, the same on Velocity and Waterfall): `storage-method`
  `mariadb` or `mysql`, then `data:` `address`, `database`, `username`, `password`.
* CoreProtect (plugins/CoreProtect/config.yml): `database-type: mysql` in current versions,
  `use-mysql: true` in older ones (current versions read it too and only warn when the two
  disagree), then `mysql-host`, `mysql-port`, `mysql-database`, `mysql-username`, `mysql-password`
  (CoreProtect's Config.java and ConfigHandler.java).
* Plan (plugins/Plan/config.yml): `Database.Type: MySQL` (it supports SQLite and MySQL) and
  `Database.MySQL.Host/Port/User/Password/Database` (Plan's default config.yml).
* FiveM's oxmysql (server.cfg): `set mysql_connection_string "mysql://user:pass@host:port/db?charset=utf8mb4"`.
* SourceMod (addons/sourcemod/configs/databases.cfg): a KeyValues section with `driver`, `host`,
  `database`, `user`, `pass`, `port`; SourceBans++ reads the section named `sourcebans`.
* extDB3 (@extDB3/extdb3-conf.ini): a section named after the database with `IP`, `Port`,
  `Username`, `Password`, `Database`.
* MySQLOO (Garry's Mod Lua): `mysqloo.connect(host, user, pass, database, port)`.
* Generic: the five values, a JDBC URL and a mysql:// URI.

The host is always 127.0.0.1, never `localhost`: a client built on libmysqlclient reads `localhost`
as "use the socket", and the socket path compiled into it need not be this host's. Passwords the
panel makes hold only letters, digits and `-_.` (ssh_manager.databases.new_password), so they go
into a URI, YAML, KeyValues, INI or a Lua string as they are.
"""
from panel.services import cod_mods as _cm

HOST = "127.0.0.1"

# Kind -> the label the select shows (the plugin's own name; a technical literal, not translated).
LABELS = {
    "luckperms": "LuckPerms",
    "coreprotect": "CoreProtect",
    "plan": "Plan",
    "fivem": "FiveM (oxmysql)",
    "sourcemod": "SourceMod / SourceBans++",
    "extdb3": "extDB3",
    "mysqloo": "MySQLOO",
    "generic": "Generic",
}

_MC_SERVERS = frozenset({"mc", "pmc"})
_MC_PROXIES = frozenset({"vpmc", "wmc"})
# Source engine games run SourceMod; Garry's Mod's database addon is MySQLOO instead.
_SOURCEMOD_GAMES = _cm._LGSM_SOURCE_ENGINE - {"gmod"}

# The first name the Add field suggests, by game.
_SUGGEST = {"mc": "luckperms", "pmc": "luckperms", "vpmc": "luckperms", "wmc": "luckperms",
            "fivem": "fivem", "arma3": "extdb", "gmod": "gmod", "rust": "oxide"}


def kinds_for(game_type):
    """The snippet kinds for a game: its own plugins' first, then generic."""
    gt = (game_type or "").lower()
    if gt in _MC_SERVERS:
        own = ["luckperms", "coreprotect", "plan"]
    elif gt in _MC_PROXIES:
        own = ["luckperms", "plan"]
    elif gt == "fivem":
        own = ["fivem"]
    elif gt in _SOURCEMOD_GAMES:
        own = ["sourcemod"]
    elif gt == "gmod":
        own = ["mysqloo"]
    elif gt == "arma3":
        own = ["extdb3"]
    else:
        own = []
    return own + ["generic"]


def suggest_slug(game_type, taken):
    """The name the Add field offers: the game's usual one, else data, data2, ... not in `taken`."""
    gt = (game_type or "").lower()
    first = _SUGGEST.get(gt) or ("sourcebans" if gt in _SOURCEMOD_GAMES else "data")
    taken = set(taken or ())
    for slug in [first, "data"] + ["data%d" % n for n in range(2, 100)]:
        if slug not in taken:
            return slug
    return ""


def _luckperms(v):
    return ("storage-method: %(lp_method)s\n"
            "data:\n"
            "  address: '%(host)s:%(port)s'\n"
            "  database: '%(name)s'\n"
            "  username: '%(user)s'\n"
            "  password: '%(password)s'\n") % v


def _coreprotect(v):
    return ("use-mysql: true\n"
            "database-type: mysql\n"
            "table-prefix: co_\n"
            "mysql-host: %(host)s\n"
            "mysql-port: %(port)s\n"
            "mysql-database: %(name)s\n"
            "mysql-username: %(user)s\n"
            "mysql-password: %(password)s\n") % v


def _plan(v):
    return ("Database:\n"
            "  Type: MySQL\n"
            "  MySQL:\n"
            "    Host: %(host)s\n"
            "    Port: %(port)s\n"
            "    User: %(user)s\n"
            "    Password: %(password)s\n"
            "    Database: %(name)s\n") % v


def _fivem(v):
    return ('set mysql_connection_string "mysql://%(user)s:%(password)s@%(host)s:%(port)s/%(name)s'
            '?charset=utf8mb4"\n') % v


def _sourcemod(v):
    return ('"%(sm_entry)s"\n'
            '{\n'
            '\t"driver"\t"default"\n'
            '\t"host"\t"%(host)s"\n'
            '\t"database"\t"%(name)s"\n'
            '\t"user"\t"%(user)s"\n'
            '\t"pass"\t"%(password)s"\n'
            '\t"port"\t"%(port)s"\n'
            '}\n') % v


def _extdb3(v):
    return ("[%(name)s]\n"
            "IP = %(host)s\n"
            "Port = %(port)s\n"
            "Username = %(user)s\n"
            "Password = %(password)s\n"
            "Database = %(name)s\n") % v


def _mysqloo(v):
    return ('local db = mysqloo.connect("%(host)s", "%(user)s", "%(password)s", "%(name)s", %(port)s)\n'
            'db:connect()\n') % v


def _generic(v):
    return ("Host: %(host)s\n"
            "Port: %(port)s\n"
            "Database: %(name)s\n"
            "User: %(user)s\n"
            "Password: %(password)s\n"
            "JDBC: jdbc:%(jdbc)s://%(host)s:%(port)s/%(name)s\n"
            "URI: mysql://%(user)s:%(password)s@%(host)s:%(port)s/%(name)s\n") % v


_RENDER = {"luckperms": _luckperms, "coreprotect": _coreprotect, "plan": _plan, "fivem": _fivem,
           "sourcemod": _sourcemod, "extdb3": _extdb3, "mysqloo": _mysqloo, "generic": _generic}


def render(kind, flavor, port, name, secret):
    """One kind's text for database `name` (also its user) on port `port`, with `secret` as the password.

    `flavor` ('mariadb' or 'mysql') picks LuckPerms' storage-method and the JDBC driver. The Databases
    tab renders with a placeholder for the password and puts the real one in only when it is asked
    for. An unknown kind is the generic one.
    """
    maria = flavor != "mysql"
    v = {"host": HOST, "port": int(port), "name": name, "user": name, "password": secret,
         "lp_method": "mariadb" if maria else "mysql", "jdbc": "mariadb" if maria else "mysql",
         "sm_entry": "sourcebans" if name.endswith("_sourcebans") else "default"}
    return _RENDER.get(kind, _generic)(v)


def render_all(game_type, flavor, port, name, secret):
    """Every kind this game offers, rendered: [(kind, label, text)], the game's own first."""
    return [(k, LABELS[k], render(k, flavor, port, name, secret)) for k in kinds_for(game_type)]
