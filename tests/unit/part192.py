"""Part 192 of the unit suite: the dashboard's server list as compact cards on a phone.

Held here:
* The page, through the app: each server row carries the phone card's hooks — the name and game
  label together on line 1 (the label d-md-none, so a wider screen never draws it), the player count
  with its word ("player" for one with no cap, "players" otherwise; d-md-none), the account name
  marked when it only repeats the server's name, the select-all box labelled for the phone, and the
  "more" popover holding Console, Files, Tags and Uninstall but never Start, Restart or Stop, with a
  toggle that names it.
* panel.css: inside the mobile media query the column headers (all but the select-all cell) are
  hidden, each row is a wrapping flex card and the size container the narrow-row query reads, and
  the Actions cell is no longer pinned over the row; outside it the popover is reset to a plain
  inline span and its toggle hidden (which is what keeps the desktop row as it was); the narrow-row
  container query hides the closed popover and shows the toggle.
* dashboard.js in node: _dashPlayersCell writes the same shape the template renders, and a tap on an
  action inside an open "more" popover closes it (and does nothing anywhere else, or without
  popover support).

HOW IT RUNS. part12's app with its transport tripwire armed; the player cache is seeded and cleared
in a finally. Scripts in node through part47's runner. Nothing reaches a host or data/.
"""
import os as _os192
import re as _re192

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part47 import _cut47, _node47
from unit.part12 import (P9_ADMIN, P9_LOCAL, _P9_TRIPPED, _p9_arm, _p9_client, _p9_delete_server,
                         _p9_new_server, _p9_patch, _p9_restore_all)
from panel.ops import system_ops as _so192
from panel.services import monitoring as _mon192

_trips192 = len(_P9_TRIPPED)

# ── 1. the page, through the app ────────────────────────────────────────────────────────────────
_page192 = ""
_ids192 = []
try:
    _ids192.append(_p9_new_server(P9_LOCAL, "dmbsame192", "mc", 25992, game_display="Minecraft Java Edition"))
    _ids192.append(_p9_new_server(P9_LOCAL, "dmbacct192", "cs2", 27992, name="Pug Night 192",
                                  game_display="Counter-Strike 2"))
    _mon192._player_counts[_ids192[0]] = {"count": 1, "max": None, "name": ""}
    _mon192._player_counts[_ids192[1]] = {"count": 3, "max": 20, "name": ""}
    _p9_arm(who="part192")
    _p9_patch(_so192, "get_server_status", lambda: {})
    _page192 = _p9_client(P9_ADMIN).get("/").get_data(as_text=True)
finally:
    _p9_restore_all()
    for _sid192 in _ids192:
        _mon192._player_counts.pop(_sid192, None)
        _p9_delete_server(_sid192)


def _row192(sid):
    """The server's <tr>, as rendered ("" when it is not on the page)."""
    m = _re192.search(r'<tr data-server-id="%d"[\s\S]*?</tr>' % sid, _page192)
    return m.group(0) if m else ""


_r1_192, _r2_192 = (_row192(_ids192[0]), _row192(_ids192[1])) if len(_ids192) == 2 else ("", "")
check("dashboard phone card: line 1 is the name and the game label together, the label d-md-none so a "
      "wider screen never draws it",
      '<span class="dash-srv-title"><strong data-no-i18n>dmbsame192</strong><span class="d-md-none dash-m-game" '
      'data-no-i18n>Minecraft Java Edition</span></span>' in _r1_192, _r1_192[:600])
check("dashboard phone card: the player count carries its word, \"player\" for one player with no cap and "
      "\"players\" for 3 / 20, d-md-none",
      '1 <span class="d-md-none dash-m-unit">player</span>' in _r1_192
      and '3 / 20 <span class="d-md-none dash-m-unit">players</span>' in _r2_192,
      repr((_re192.findall(r'<td id="players-\d+"[\s\S]*?</td>', _r1_192 + _r2_192))))
check("dashboard phone card: the account name is marked to leave out only where it repeats the server's "
      "name",
      "dash-short dash-short-dup" in _r1_192 and "dash-short" in _r2_192 and "dash-short-dup" not in _r2_192, "")
check("dashboard phone card: the status, players and connect cells and the map carry the classes the "
      "phone layout places them by",
      all(c in _r2_192 for c in ('class="dash-td-status"', "dash-td-players", 'class="dash-td-connect"',
                                 "dash-map")), "")


def _more192(row, sid):
    """The popover's markup in `row`: from its opening tag to its closing one (nothing inside it is
    a span)."""
    i = row.find('<span class="dash-more" id="dash-more-%d" popover>' % sid)
    j = row.find("</span>", i)
    return row[i:j] if i >= 0 and j > i else ""


_m2_192 = _more192(_r2_192, _ids192[1]) if len(_ids192) == 2 else ""
check("dashboard phone card: the \"more\" popover holds Console, Files, Tags and Uninstall, and never "
      "Start, Restart or Stop, nor the reorder buttons Customise shows",
      all(k in _m2_192 for k in ("srv-console", "srv-files", 'data-action="editServerTags"', "uninstall-trigger"))
      and "srv-ctl" not in _m2_192 and "srv-move" not in _m2_192 and "sort-handle" not in _m2_192, _m2_192[:400])
check("dashboard phone card: the toggle names that popover and the server it is for",
      bool(_ids192) and _re192.search(r'<button type="button" class="btn btn-outline-secondary btn-sm dash-more-btn" '
                                      r'popovertarget="dash-more-%d"\s+title="More actions" '
                                      r'aria-label="More actions for Pug Night 192">' % _ids192[1], _r2_192) is not None,
      "")
check("dashboard phone card: the select-all box keeps a label on the phone, tied to it by id",
      'id="srv-check-all-%d"' % P9_LOCAL in _page192
      and '<label class="d-md-none dash-m-selall" for="srv-check-all-%d">Select all on this host</label>'
      % P9_LOCAL in _page192, "")


# ── 2. panel.css ────────────────────────────────────────────────────────────────────────────────
def _blocks192(css):
    """The rules of a stylesheet: [(prelude, body)], an at-rule's body parsed the same way."""
    out, i, n = [], 0, len(css)
    while i < n:
        j = css.find("{", i)
        if j < 0:
            break
        depth, k = 1, j + 1
        while k < n and depth:
            depth += {"{": 1, "}": -1}.get(css[k], 0)
            k += 1
        prelude, body = " ".join(css[i:j].split()), css[j + 1:k - 1]
        out.append((prelude, _blocks192(body) if prelude.startswith("@") else body))
        i = k
    return out


def _decls192(body):
    """A rule body as {property: value}."""
    return {p.split(":", 1)[0].strip(): p.split(":", 1)[1].strip()
            for p in body.split(";") if ":" in p}


with open(_os192.path.join(_root, "panel", "static", "css", "panel.css"), encoding="utf-8") as _fh192:
    _css192 = _blocks192(_re192.sub(r"/\*[\s\S]*?\*/", "", _fh192.read()))


def _rule192(at, selector):
    """{prop: value} of every rule whose selector list holds `selector`, inside the at-rule `at`
    (None: top level), a later rule's value over an earlier one's; {} when there is none."""
    scopes = [b for p, b in _css192 if p == at] if at else [_css192]
    out = {}
    for scope in scopes:
        for prelude, body in scope:
            if isinstance(body, str) and selector in [s.strip() for s in prelude.split(",")]:
                out.update(_decls192(body))
    return out


_MOB192 = "@media (width <= 767.98px)"
_TR192 = ".table-responsive .dash-srv-table > tbody > tr[data-server-id]"
check("panel.css dashboard phone card: inside the mobile media query the column headers are hidden, all "
      "but the select-all cell",
      _rule192(_MOB192, ".table-responsive .dash-srv-table > thead > tr > th:not(.dash-th-check)").get("display")
      == "none", "")
_trd192 = _rule192(_MOB192, _TR192)
check("panel.css dashboard phone card: each row is a wrapping flex card, and the size container the "
      "narrow-row query reads",
      (_trd192.get("display"), _trd192.get("flex-wrap"), _trd192.get("container"))
      == ("flex", "wrap", "dmbrow / inline-size"), repr(_trd192))
_act192 = _rule192(_MOB192, _TR192 + " > td.col-actions")
check("panel.css dashboard phone card: the Actions cell is unpinned and takes a line of its own",
      (_act192.get("position"), _act192.get("flex"), _act192.get("min-width"), _act192.get("display"))
      == ("static", "1 0 100%", "0", "flex"),
      repr(_act192))
_reset192 = _rule192(None, ".dash-more")
check("panel.css dashboard phone card: outside any media query the popover is a plain inline span and "
      "its toggle is hidden (the desktop row as it was)",
      (_reset192.get("display"), _reset192.get("position"), _reset192.get("padding"), _reset192.get("border"))
      == ("inline", "static", "0", "0")
      and _rule192(None, ".col-actions .dash-more-btn").get("display") == "none", repr(_reset192))
_CQ192 = "@container dmbrow (width < 19rem)"
check("panel.css dashboard phone card: a row too narrow for every button hides the closed popover and "
      "shows its toggle",
      _rule192(_CQ192, ".table-responsive .dash-srv-table .dash-more:not(:popover-open)").get("display") == "none"
      and _rule192(_CQ192, ".table-responsive .dash-srv-table td.col-actions > .dash-more-btn").get("display")
      == "block", "")

# ── 3. dashboard.js in node ─────────────────────────────────────────────────────────────────────
with open(_os192.path.join(_root, "panel", "static", "js", "dashboard.js"), encoding="utf-8") as _fh192:
    _DB192 = _fh192.read()
_js192 = _node47(
    "const cells = {};\n"
    "global.document = {getElementById: id => (cells[id] = cells[id] || {innerHTML: ''}),\n"
    "                   addEventListener: () => {}};\n"
    + _cut47(_DB192, "function _dashPlayersCell(") + "\n" + _cut47(_DB192, "function _dmbCloseMoreMenu(") + "\n"
    "_dashPlayersCell({id: 1, players: 1});\n"
    "_dashPlayersCell({id: 2, players: 3, max_players: 20});\n"
    "_dashPlayersCell({id: 3, players: 1, max_players: 20});\n"
    "_dashPlayersCell({id: 4, players: null});\n"
    "function menu(open, canHide) {\n"
    "  const m = {hidden: 0, matches: s => s === ':popover-open' && open};\n"
    "  if (canHide) m.hidePopover = () => { m.hidden++; };\n"
    "  return m;\n"
    "}\n"
    "function tap(m, insideAction) {\n"
    "  const hit = {closest: s => (s === '.dash-more' ? m : null)};\n"
    "  _dmbCloseMoreMenu({target: {closest: s => (s === 'a, button' && insideAction ? hit : null)}});\n"
    "  return m.hidden;\n"
    "}\n"
    "let threw = false;\n"
    "try { tap(menu(true, false), true); } catch (e) { threw = String(e); }\n"
    "console.log(JSON.stringify({cells: [1, 2, 3, 4].map(i => cells['players-' + i].innerHTML),\n"
    "  open: tap(menu(true, true), true), closed: tap(menu(false, true), true),\n"
    "  notAction: tap(menu(true, true), false), threw}));\n")
if _js192 is None:
    skip("dashboard.js dashboard phone card: the player cell and the more-menu close", "node is not installed here")
else:
    eq("dashboard.js dashboard phone card: _dashPlayersCell writes the template's shape — \"player\" for one "
       "player with no cap, \"players\" with a cap or more, no word for an unknown count",
       _js192.get("cells"),
       ['<i class="bi bi-people-fill text-secondary"></i> 1 <span class="d-md-none dash-m-unit">player</span>',
        '<i class="bi bi-people-fill text-secondary"></i> 3 / 20 <span class="d-md-none dash-m-unit">players</span>',
        '<i class="bi bi-people-fill text-secondary"></i> 1 / 20 <span class="d-md-none dash-m-unit">players</span>',
        '<span class="text-secondary">—</span>'])
    eq("dashboard.js dashboard phone card: a tap on an action in an open \"more\" popover closes it; a closed "
       "one, a tap that is not on an action, and a browser without popovers are left alone",
       [_js192.get(k) for k in ("open", "closed", "notAction", "threw")], [1, 0, 0, False])

check("part192: nothing reached a real transport", len(_P9_TRIPPED) == _trips192, repr(_P9_TRIPPED[_trips192:]))
