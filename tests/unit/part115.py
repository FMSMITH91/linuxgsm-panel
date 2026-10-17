"""Part 115 of the unit suite: the twentieth review's page fixes (builder C).

Held here, each against the code path the finding named:

* Files & Config's backup card: after a schedule save settles, the select that was changed shows what
  is stored. #445 made a failed save read the card again, but the read skips a FOCUSED select, and a
  select keeps focus after a pick: the select kept showing the choice it never stored (and picking it
  again to retry fired no change).
* the GMod content card: one poll chain while a job runs. A second Uninstall confirmed before the card
  redrew re-read the card too, and each read that found the job running scheduled its own next poll:
  two chains, each reading the host every 5 s until the job ended.
* the dashboard's empty state: it told a new operator to "install a game server from the Game Servers
  page". That page folded into the dashboard; nothing in the sidebar is called that.

HOW IT RUNS. The card's script in node on part87's DOM through part106's harness, with fetch answered by
hand so the order of replies is the check's; the dashboard through part12's Flask app and client
(part12 has run), as accounts that see no servers.
"""
import os

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_restore_all
from unit.part106 import _js106, _read106
from unit.part109 import _PEND109
from panel.db.models import Group as _G115, User as _U115, db as _db115
from panel.security import auth as _auth115

_TRIP115_START = len(_P9_TRIPPED)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Files & Config's backup card: a settled save leaves the changed select showing what is stored
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SF115 = _read106("static", "js", "server_files.js")
_name115b = "Files & Config backup card: the changed select after a settled save"
_outb115 = _js106(_name115b, _PEND109 + (
    "var serverId = 1;\n"
    "global._bkRenderDisk = () => {}; global._bkRenderStatus = () => {}; global._bkRenderRows = () => {};\n"
    "global._bkPollWhileRunning = () => {};\n"
    "const iv = document.getElementById('bk-interval'), kp = document.getElementById('bk-keep');\n"
    "for (const s of [iv, kp]) { s.options = [{value: 'default'}, {value: '1'}, {value: '3'}, {value: '7'}];\n"
    "  s.appendChild = o => { s.options.push(o); return o; }; }\n"
    "const info = (days, keep) => ({schedule: {interval_set: true, interval_days: days, keep_set: true, keep},\n"
    "                               status: null, backups: []});\n"), _SF115, (
    "var _bkPoll", "var _bkShown", "function _bkShow(", "var _r30c_sfBkSaves", "function loadBackups(",
    "function renderBackups(", "function saveBkSchedule(", "function _r32c_sfBkPutBack("), (
    "  const out = {};\n"
    "  loadBackups(); reply('/info', info(7, 3)); await settle();\n"
    "  out.first = [iv.value, kp.value];\n"
    # the operator picks Every 3 days; the select keeps focus after the pick
    "  const pick = async (how, stored) => { iv.value = '3'; iv.focus(); saveBkSchedule();\n"
    "    const p = take('/schedule'); if (!p) return 'no save sent';\n"
    "    if (how === 'reject') p.fail(); else p.ok(how); await settle();\n"
    "    const before = iv.value;\n"
    "    reply('/info', info(stored, 3)); await settle();\n"
    "    return {before, after: iv.value, posted: p.body}; };\n"
    "  out.refused = await pick({success: false}, 7);\n"
    "  out.failed = await pick('reject', 7);\n"
    # a save that stored, and a later poll while the select is focused: neither moves it (controls)
    "  out.saved = await pick({success: true}, 3);\n"
    "  iv.value = '1'; loadBackups(); reply('/info', info(3, 3)); await settle(); out.polled = iv.value;\n"
    # two saves whose replies cross: the read the last-settled one sends shows what the server holds
    "  iv.value = '7'; saveBkSchedule(); const a = take('/schedule');\n"
    "  iv.value = '1'; saveBkSchedule(); const b = take('/schedule');\n"
    "  if (a && b) { b.ok({success: true}); await settle(); a.ok({success: true}); await settle();\n"
    "    while (count('/info')) { reply('/info', info(7, 3)); await settle(); } }\n"
    "  out.crossed = iv.value;\n"
    "  console.log(JSON.stringify(out));\n"))
if _outb115 is not None:
    _ref115 = _outb115.get("refused") or {}
    _fail115 = _outb115.get("failed") or {}
    check("Files & Config backup card: a schedule save the route refused, or that got no answer, puts the "
          "focused select back to the stored value at once and again on the re-read (it kept showing the "
          "choice it never stored, and picking it again to retry fired no change); two saves whose replies "
          "cross end on what the server holds, not on the last pick",
          _outb115.get("first") == ["7", "3"]
          and _ref115.get("posted") == {"interval": "3"} and _ref115.get("before") == "7"
          and _ref115.get("after") == "7"
          and _fail115.get("before") == "7" and _fail115.get("after") == "7"
          and _outb115.get("crossed") == "7", repr(_outb115))
    check("Files & Config backup card: ...a save that stored keeps the pick; a plain poll still leaves a "
          "focused select alone (controls)",
          (_outb115.get("saved") or {}).get("after") == "3" and _outb115.get("polled") == "1", repr(_outb115))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The GMod content card polls one chain at a time while a job runs
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Every read that found a job running scheduled the next. Two Uninstalls confirmed before the card
# redrew are two POSTs, each re-reading 1.5 s later whatever it answered: two chains, each polling
# the host every 5 s for as long as the job ran.
_SD115 = _read106("static", "js", "server_detail.js")
_name115g = "GMod content card: two Uninstalls confirmed before the redraw"
_outg115 = _js106(_name115g, _PEND109 + (
    "var serverId = 1; global._esc = escapeHtml; global.tfHtml = (k, v) => k;\n"
    "const el = document.getElementById('gmod-content-body');\n"
    "el.querySelector = () => null; el.querySelectorAll = () => [];\n"
    # a cleared timer is marked, so the check counts the polls still waiting
    "global.clearTimeout = id => { if (timers[id - 1]) timers[id - 1].cleared = true; };\n"
    "const live = () => timers.filter(t => !t.cleared);\n"
    "const takeGet = () => { const i = pend.findIndex(p => p.u.indexOf('gmod-content') >= 0 && !p.body);\n"
    "  return i < 0 ? null : pend.splice(i, 1)[0]; };\n"
    "const takePost = () => { const i = pend.findIndex(p => p.u.indexOf('gmod-content') >= 0 && p.body);\n"
    "  return i < 0 ? null : pend.splice(i, 1)[0]; };\n"), _SD115, (
    "var _r30c_gmcRunning", "function _r30c_gmcRepoll(", "var _r32c_gmcTimer", "function _r32c_gmcLater(",
    "function _r30c_gmcWorking(", "function loadGmodContent(", "function _gmcOutcome(", "function _gmcPost("), (
    "  const out = {gets: []};\n"
    "  const RUN = {games: [], job: {status: 'running', msg: 'p115 removing'}};\n"
    "  loadGmodContent(); takeGet().ok({games: []}); await settle();\n"
    "  _gmcPost({action: 'uninstall', games: ['css']}, 'Removing…');\n"
    "  _gmcPost({action: 'uninstall', games: ['tf2']}, 'Removing…');\n"
    "  const a = takePost(), b = takePost();\n"
    "  if (!a || !b) { console.log(JSON.stringify({error: 'no posts'})); return; }\n"
    "  a.ok({success: true}); await settle(); b.ok({success: false, message: 'busy'}); await settle();\n"
    "  out.afterPosts = live().length;\n"
    # three rounds of the job running: run every poll that is due, answer every read it sent
    "  for (let i = 0; i < 3; i++) { live().forEach(t => { t.cleared = true; t.fn(); });\n"
    "    let n = 0, p = takeGet(); while (p) { n++; p.ok(RUN); await settle(); p = takeGet(); }\n"
    "    out.gets.push(n); }\n"
    "  out.waiting = live().map(t => t.ms);\n"
    # the job ends: the chain stops (control)
    "  live().forEach(t => { t.cleared = true; t.fn(); });\n"
    "  const DONE = {games: [], job: {status: 'done', msg: 'removed'}};\n"
    "  let p = takeGet(); while (p) { p.ok(DONE); await settle(); p = takeGet(); }\n"
    "  out.ended = live().length;\n"
    "  console.log(JSON.stringify(out));\n"))
if _outg115 is not None:
    check("GMod content card: two Uninstalls confirmed before the card redrew leave ONE poll chain, one read "
          "of the host per 5 s (each re-read that found the job running scheduled its own next, so the "
          "two POSTs' re-reads polled the host twice per 5 s for as long as the job ran)",
          _outg115.get("afterPosts") == 1 and _outg115.get("gets") == [1, 1, 1]
          and _outg115.get("waiting") == [5000], repr(_outg115))
    check("GMod content card: ...and the chain still stops once a read finds the job ended (control)",
          _outg115.get("ended") == 0 and _outg115.get("gets") != [], repr(_outg115))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The dashboard's empty state names no page that does not exist
# ════════════════════════════════════════════════════════════════════════════════════════════════
_mine115 = {"users": [], "groups": []}
_dash115 = {}
try:
    with _p9.app_context():
        for _k115, _perms115 in (("remotes", [_auth115.VIEW_SERVERS, _auth115.MANAGE_REMOTES]),
                                 ("install", [_auth115.VIEW_SERVERS, _auth115.MANAGE_REMOTES,
                                              _auth115.INSTALL_SERVER])):
            _g115 = _G115(name="p115_%s" % _k115, description="", is_default=False)
            _g115.set_permissions(_perms115)
            # never signed in with: the client below sets the session, so the hash is of random bytes
            _u115 = _U115(username="p115_%s" % _k115, password_hash=_auth115.hash_password(os.urandom(12).hex()),
                          display_name="p115 %s" % _k115, is_superadmin=False, is_active=True)
            _u115.groups.append(_g115)
            _db115.session.add_all([_g115, _u115])
            _db115.session.commit()
            _mine115["users"].append((_k115, _u115.id))
            _mine115["groups"].append(_g115.id)
    _p9_arm(who="part115")
    for _k115, _uid115 in _mine115["users"]:
        _r115 = _p9_client(_uid115).get("/")
        _dash115[_k115] = (_r115.status_code, _r115.get_data(as_text=True))
finally:
    _p9_restore_all()
    with _p9.app_context():
        for _made115 in _mine115["users"]:
            _db115.session.delete(_db115.session.get(_U115, _made115[1]))
        for _gid115 in _mine115["groups"]:
            _db115.session.delete(_db115.session.get(_G115, _gid115))
        _db115.session.commit()

_rem115 = _dash115.get("remotes", (0, ""))
_ins115 = _dash115.get("install", (0, ""))
check("dashboard: the empty state sends no one to a 'Game Servers page' (it folded into the dashboard; the "
      "sidebar has no such entry), and an account that may install is told to install on the host it adds",
      _ins115[0] == 200 and "Game Servers page" not in _ins115[1]
      and "Start by adding a remote server, then install a game server on it." in _ins115[1]
      and "/servers/install" in _ins115[1],
      repr((_ins115[0], "Game Servers page" in _ins115[1], "install a game server on it" in _ins115[1])))
check("dashboard: ...an account that may add hosts but not install is told only to add one (it gets no "
      "install link, so it is not told to install)",
      _rem115[0] == 200 and "Game Servers page" not in _rem115[1]
      and "Start by adding a remote server." in _rem115[1] and "install a game server on it" not in _rem115[1]
      and "/servers/install" not in _rem115[1],
      repr((_rem115[0], "Game Servers page" in _rem115[1], "install a game server on it" in _rem115[1])))

check("part115: nothing its route drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP115_START, repr(_P9_TRIPPED[_TRIP115_START:][:6]))
