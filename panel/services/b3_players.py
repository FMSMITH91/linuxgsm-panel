"""B3's players and penalties, read from B3's own database (the one the B3 add-on was given).

What the Add-ons tab's B3 players section shows (routes/addons_b3.py): a search by name, alias, B3
id or GUID, one player's aliases, addresses, connections and penalties, and the latest penalties.
The tables are B3's own (b3/sql/mysql/b3.sql at addons.B3_COMMIT: clients, aliases, ipaliases,
penalties, groups); the panel only reads them.

HOW IT READS. Every statement here is a constant: values are bound parameters (the db-query verb's
EXECUTE ... USING), so nothing a viewer types becomes SQL text (SQL Injection Prevention Cheat
Sheet, "Defense Option 1: Prepared Statements"). A search matches only indexed columns, from the
start of the text (clients.name, aliases.alias, clients.guid, clients.id), and every list is
bounded: a page is PAGE_SIZE rows, the next page continues after the last row shown (keyset), and
one player's lists stop at ALIASES_MAX, ADDRESSES_MAX and PENALTIES_MAX rows. The verb runs them in
a READ ONLY transaction that is rolled back.

PERSONAL DATA. A player's IP addresses and GUID are personal data. Without `unmask` (the route
decides: Manage a server's databases, which can already read these tables whole) they are not even
selected: the addresses are a count, the GUID is left out, and a GUID is searched only whole, never
by its start (a prefix search would hand it over one character at a time).
"""
import re
import threading
import time

from panel.services import addons as _ad

PAGE_SIZE = 15
ALIASES_MAX = 50
ADDRESSES_MAX = 50
PENALTIES_MAX = 100
QUERY_MAX = 36          # B3's longest searched column: clients.guid, VARCHAR(36)
ID_MAX = 4294967295     # clients.id is INT UNSIGNED
CACHE_SECONDS = 60      # how long the B3 add-on's database name is reused without asking the host
# B3's penalty types (penalties.type) and the ones the latest-penalties list can be narrowed to.
TYPES = ("Ban", "TempBan", "Kick", "Warning", "Notice")
KINDS = {"all": ("Ban", "TempBan", "Kick", "Warning"), "bans": ("Ban", "TempBan")}
TABLES_MISSING = 1146   # ER_NO_SUCH_TABLE: B3 creates its tables at its first start

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ID_RE = re.compile(r"@?([0-9]{1,10})\Z")
_GUID_RE = re.compile(r"[A-Za-z0-9]{8,36}\Z")
_AFTER_RE = re.compile(r"([0-9]{1,10})\.([0-9]{1,10})\Z")
_COLOR_RE = re.compile(r"\^[0-9A-Za-z]")
_INT_RE = re.compile(r"-?\d{1,19}\Z")

# ── the statements ────────────────────────────────────────────────────────────────────────────────
# One search: a name or an alias starting with the text, the B3 id (@123), and the whole GUID, or, with
# `unmask` and a text shaped like one, a GUID starting with it. A part that does not apply gets NULL,
# which matches nothing (the server sees that before reading a row). The page after `after` (the last
# row's last-seen time and id) when it is set. The matching ids are found first, through each
# column's own index (STRAIGHT_JOIN: never a scan of every player checked against the list).
_SEARCH_PARTS = (" FROM (SELECT id FROM clients WHERE name LIKE ? ESCAPE '!'"
                 " UNION SELECT client_id FROM aliases WHERE alias LIKE ? ESCAPE '!'"
                 " UNION SELECT id FROM clients WHERE id = ?")
_SEARCH_GUID = {False: " UNION SELECT id FROM clients WHERE guid = ?) m",
                True: " UNION SELECT id FROM clients WHERE guid LIKE ? ESCAPE '!') m"}
_SEARCH_REST = (" STRAIGHT_JOIN clients c ON c.id = m.id LEFT JOIN `groups` g ON g.id = c.group_bits"
                " WHERE ? IS NULL OR c.time_edit < ? OR (c.time_edit = ? AND c.id < ?)"
                " ORDER BY c.time_edit DESC, c.id DESC LIMIT 16")
_PLAYER_COLS = {False: "SELECT c.id, c.name, c.connections, c.time_add, c.time_edit, g.name AS grp",
                True: "SELECT c.id, c.name, c.connections, c.time_add, c.time_edit, g.name AS grp, c.guid"}
# (unmask, GUID by its start) -> the statement. A GUID's start is searched only with `unmask`.
SEARCH_SQL = {(u, prefix): "".join((_PLAYER_COLS[u], _SEARCH_PARTS, _SEARCH_GUID[prefix], _SEARCH_REST))
              for u, prefix in ((False, False), (True, False), (True, True))}
CLIENT_SQL = {
    False: ("SELECT c.id, c.name, c.connections, c.time_add, c.time_edit, g.name AS grp, g.level"
            " FROM clients c LEFT JOIN `groups` g ON g.id = c.group_bits WHERE c.id = ?"),
    True: ("SELECT c.id, c.name, c.connections, c.time_add, c.time_edit, g.name AS grp, g.level, c.guid, c.ip"
           " FROM clients c LEFT JOIN `groups` g ON g.id = c.group_bits WHERE c.id = ?"),
}
ALIASES_SQL = ("SELECT alias, num_used, time_add, time_edit FROM aliases WHERE client_id = ?"
               " ORDER BY time_edit DESC, id DESC LIMIT 51")
ADDRESSES_SQL = {
    False: "SELECT COUNT(*) AS n FROM ipaliases WHERE client_id = ?",
    True: ("SELECT ip, num_used, time_add, time_edit FROM ipaliases WHERE client_id = ?"
           " ORDER BY time_edit DESC, id DESC LIMIT 51"),
}
PENALTIES_SQL = ("SELECT p.id, p.type, p.duration, p.inactive, p.reason, p.keyword, p.time_add, p.time_expire,"
                 " p.admin_id, a.name AS admin FROM penalties p LEFT JOIN clients a ON a.id = p.admin_id"
                 " WHERE p.client_id = ? ORDER BY p.time_add DESC, p.id DESC LIMIT 101")
# The latest penalties of the kinds asked (four slots; an unused one is NULL), newest first (B3
# writes a penalty when it is given, so its id follows its time), after id `before` when set.
RECENT_SQL = ("SELECT p.id, p.type, p.duration, p.inactive, p.reason, p.keyword, p.time_add, p.time_expire,"
              " p.admin_id, a.name AS admin, p.client_id, c.name AS player FROM penalties p"
              " LEFT JOIN clients c ON c.id = p.client_id LEFT JOIN clients a ON a.id = p.admin_id"
              " WHERE p.type IN (?, ?, ?, ?) AND (? IS NULL OR p.id < ?) ORDER BY p.id DESC LIMIT 16")


def clean_query(q):
    """The search text, trimmed, or None when it is not one: 1 to QUERY_MAX characters, no control characters."""
    if not isinstance(q, str):
        return None
    q = q.strip()
    if not q or len(q) > QUERY_MAX or _CTRL_RE.search(q):
        return None
    return q


def like_prefix(text):
    """A LIKE pattern for values starting with `text`: B3's own % _ and ! taken literally (ESCAPE '!')."""
    return text.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"


def parse_after(text):
    """(last seen, id) from a search's next-page mark "<time>.<id>", None for none, False when it is not one."""
    if text in (None, ""):
        return None
    m = _AFTER_RE.fullmatch(text) if isinstance(text, str) else None
    return (int(m.group(1)), int(m.group(2))) if m else False


def search_statement(q, unmask, after=None):
    """The search for clean_query() text `q` (one page; `after` from parse_after)."""
    pattern = like_prefix(q)
    m = _ID_RE.fullmatch(q)
    prefix = bool(unmask) and _GUID_RE.fullmatch(q) is not None
    guid = pattern if prefix else (q if _GUID_RE.fullmatch(q) else None)
    t, cid = (str(after[0]), str(after[1])) if after else (None, None)
    params = [pattern, pattern, str(int(m.group(1))) if m else None, guid, t, t, t, cid]
    return {"sql": SEARCH_SQL[(bool(unmask), prefix)], "params": params, "cap": PAGE_SIZE + 1}


def query_kind(q, unmask):
    """What a search looked for, for its audit row (never the text itself)."""
    kinds = ["name or alias"]
    if _ID_RE.fullmatch(q):
        kinds.append("B3 id")
    if _GUID_RE.fullmatch(q):
        kinds.append("GUID start" if unmask else "whole GUID")
    return ", ".join(kinds)


def detail_statements(client_id, unmask):
    """The four reads of one player: the player, its aliases, its addresses (a count without `unmask`), penalties."""
    cid = str(int(client_id))
    return [{"sql": CLIENT_SQL[bool(unmask)], "params": [cid], "cap": 1},
            {"sql": ALIASES_SQL, "params": [cid], "cap": ALIASES_MAX + 1},
            {"sql": ADDRESSES_SQL[bool(unmask)], "params": [cid], "cap": ADDRESSES_MAX + 1},
            {"sql": PENALTIES_SQL, "params": [cid], "cap": PENALTIES_MAX + 1}]


def recent_statement(kind, before=None):
    """The latest penalties of `kind` (a KINDS key), after penalty id `before` when set."""
    types = list(KINDS[kind]) + [None] * (4 - len(KINDS[kind]))
    b = str(int(before)) if before else None
    return {"sql": RECENT_SQL, "params": types + [b, b], "cap": PAGE_SIZE + 1}


# ── reading the answer ────────────────────────────────────────────────────────────────────────────
def records(statement):
    """The rows of one finished statement (db_data.parse's), each a {column: text or None}."""
    sets = (statement or {}).get("sets") or []
    if not sets:
        return []
    cols = sets[0].get("columns") or []
    return [dict(zip(cols, row)) for row in sets[0].get("rows") or []]


def _int(v, default=0):
    return int(v) if isinstance(v, str) and _INT_RE.fullmatch(v) else default


def plain(text):
    """B3's text as shown: colour codes (^1) taken out."""
    return _COLOR_RE.sub("", text or "")


def _player(r, unmask):
    out = {"id": _int(r.get("id")), "name": plain(r.get("name")), "connections": _int(r.get("connections")),
           "first_seen": _int(r.get("time_add")), "last_seen": _int(r.get("time_edit")),
           "group": plain(r.get("grp"))}
    if unmask:
        out["guid"] = r.get("guid") or ""
    return out


def players(statement, unmask):
    """({"players": [...], "after": next-page mark or ""}) from a search_statement answer."""
    rows = [_player(r, unmask) for r in records(statement)]
    more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    after = "%d.%d" % (rows[-1]["last_seen"], rows[-1]["id"]) if more and rows else ""
    return {"players": rows, "after": after}


def state(r, now):
    """A penalty's state: "removed" (an admin lifted it), "active", "expired", or "" for a kick or a notice."""
    if r.get("inactive") == "1":
        return "removed"
    kind, expire = r.get("type"), _int(r.get("time_expire"))
    if kind in ("Kick", "Notice"):
        return ""
    return "active" if expire == -1 or expire > now else "expired"


def penalty(r, now):
    """One penalty row as the page shows it; admin id 0 is B3 itself."""
    admin_id = _int(r.get("admin_id"))
    out = {"id": _int(r.get("id")), "type": r.get("type") if r.get("type") in TYPES else "",
           "duration": _int(r.get("duration")), "reason": plain(r.get("reason")), "keyword": r.get("keyword") or "",
           "time": _int(r.get("time_add")), "expires": _int(r.get("time_expire")), "state": state(r, now),
           "admin": "B3" if admin_id == 0 else (plain(r.get("admin")) or "@%d" % admin_id),
           "admin_id": admin_id}
    if "client_id" in r:
        out.update(player_id=_int(r.get("client_id")), player=plain(r.get("player")))
    return out


def recent(statement, now):
    """({"penalties": [...], "before": next page's id or 0}) from a recent_statement answer."""
    rows = [penalty(r, now) for r in records(statement)]
    more = len(rows) > PAGE_SIZE
    rows = rows[:PAGE_SIZE]
    return {"penalties": rows, "before": rows[-1]["id"] if more and rows else 0}


def _capped(rows, cap):
    return rows[:cap], len(rows) > cap


def detail(statements, unmask, now):
    """One player from detail_statements' four answers, or None when there is no such player."""
    found = records(statements[0])
    if not found:
        return None
    p = dict(_player(found[0], unmask), level=_int(found[0].get("level")))
    aliases, p["aliases_more"] = _capped([{"alias": plain(r.get("alias")), "used": _int(r.get("num_used")),
                                           "first": _int(r.get("time_add")), "last": _int(r.get("time_edit"))}
                                          for r in records(statements[1])], ALIASES_MAX)
    p["aliases"] = aliases
    if unmask:
        p["ip"] = found[0].get("ip") or ""
        p["addresses"], p["addresses_more"] = _capped(
            [{"ip": r.get("ip") or "", "used": _int(r.get("num_used")), "first": _int(r.get("time_add")),
              "last": _int(r.get("time_edit"))} for r in records(statements[2])], ADDRESSES_MAX)
    else:
        p["address_count"] = _int((records(statements[2]) or [{}])[0].get("n"))
    p["penalties"], p["penalties_more"] = _capped([penalty(r, now) for r in records(statements[3])],
                                                  PENALTIES_MAX)
    return p


# ── which database is B3's ────────────────────────────────────────────────────────────────────────
# server id -> (monotonic time, the B3 add-on's database name, "" when B3 is not installed). Filled by
# the Add-ons tab's own status read too, so opening the players section after the tab asks the host
# nothing more.
_DB = {}
_DB_LOCK = threading.Lock()


def remember(gs_id, found, now=None):
    """Note B3's database on server `gs_id` from addons.parse_status()'s add-ons (`found`)."""
    meta = (found.get(_ad.B3) or {}).get("meta") or {}
    name = meta.get("database") if isinstance(meta.get("database"), str) else ""
    with _DB_LOCK:
        _DB[gs_id] = (time.monotonic() if now is None else now, name)
    return name


def database_name(gs_id, now=None):
    """B3's database name on server `gs_id` while the note is fresh ("" for no B3), else None (ask the host)."""
    now = time.monotonic() if now is None else now
    with _DB_LOCK:
        got = _DB.get(gs_id)
    if got is None or now - got[0] >= CACHE_SECONDS:
        return None
    return got[1]


def forget(gs_id):
    """Drop the note for server `gs_id` (B3 was installed or removed there)."""
    with _DB_LOCK:
        _DB.pop(gs_id, None)
