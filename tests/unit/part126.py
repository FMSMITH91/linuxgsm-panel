"""Part 126 of the unit suite: review 1022b, builder C (the browser side).

* Files & Config's backup card, while a schedule save is unanswered: #448 dropped every read sent
  then, whole. fetch has no timeout, so a save that never answered froze the card (a backup started
  meanwhile stayed "Backing up..." with Back up now disabled; a deleted backup stayed listed) until
  the browser gave the request up. Such a read now draws all but the two schedule selects, and a save
  stops counting as unanswered after 15 s, as the host page's Backups card does.
* The dashboard's install-progress rows under an active filter: a row a poll built for a server the
  filter hides showed as a nameless bar among the servers that match. It now takes its server's
  display when it is built; the filter keeps the two in step from then on.

HOW IT RUNS. server_files.js's backup card through part106's harness with fetch answered by hand
(part109's); install_progress.js whole, in node on part121's small DOM. Nothing reaches a server or
the data dir.
"""
from unit.part01 import check
from unit.part47 import _SETTLE47
from unit.part106 import _js106, _read106
from unit.part109 import _PEND109
from unit.part121 import _DOM121, _node121

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Files & Config's backup card while a schedule save is unanswered
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SF126 = _read106("static", "js", "server_files.js")
_name126 = "Files & Config backup card: a schedule save that does not answer"
_out126 = _js106(_name126, _PEND109 + (
    "var serverId = 1; const rows = [], status = [];\n"
    "global._bkRenderDisk = () => {}; global._bkPollWhileRunning = () => {};\n"
    "global._bkRenderRows = d => rows.push(d.tag); global._bkRenderStatus = s => status.push(s && s.running);\n"
    "const iv = document.getElementById('bk-interval'), kp = document.getElementById('bk-keep');\n"
    "for (const s of [iv, kp]) { s.options = [{value: 'default'}, {value: '1'}, {value: '3'}, {value: '7'}];\n"
    "  s.appendChild = o => { s.options.push(o); return o; }; }\n"
    "const info = (tag, days, keep, running) => ({tag, status: {running},\n"
    "  schedule: {interval_set: true, interval_days: days, keep_set: true, keep}, backups: []});\n"), _SF126, (
    "var _bkPoll", "var _bkShown", "function _bkShow(", "var _r30c_sfBkSaves",
    "function loadBackups(", "function renderBackups(", "function saveBkSchedule(",
    "function _r32c_sfBkPutBack("), (
    "  const out = {};\n"
    "  loadBackups(); reply('/info', info('first', 7, 3, false)); await settle();\n"
    # the operator picks Every 3 days; the save goes out and never answers. Then the select loses
    # focus, so a schedule drawn from a read would show.
    "  timers.length = 0; iv.value = '3'; iv.focus(); saveBkSchedule(); const p = take('/schedule');\n"
    "  if (!p) { console.log(JSON.stringify({sent: 'no save'})); return; }\n"
    "  document.activeElement = null;\n"
    # a backup is running: the 4 s poll's read, sent and answered while the save is unanswered
    "  loadBackups(); reply('/info', info('during', 7, 3, true)); await settle();\n"
    "  out.during = {rows: rows.slice(-1)[0], running: status.slice(-1)[0], sel: [iv.value, kp.value]};\n"
    # the bound: the save's own timer, by its length
    "  out.bound = timers.map(t => t.ms).filter(ms => ms >= 10000);\n"
    "  timers.filter(t => t.ms >= 10000).forEach(t => t.fn());\n"
    "  loadBackups(); reply('/info', info('after', 7, 3, false)); await settle();\n"
    "  out.after = {rows: rows.slice(-1)[0], sel: [iv.value, kp.value]};\n"
    # the stalled save answers at last: its settled read draws what is stored, and nothing is released twice
    "  p.ok({success: true}); await settle(); reply('/info', info('late', 3, 3, false)); await settle();\n"
    "  out.late = {rows: rows.slice(-1)[0], sel: [iv.value, kp.value], pending: _r34c_sfBkPending};\n"
    "  console.log(JSON.stringify(out));\n"))
if _out126 is not None:
    check("Files & Config backup card: a read answered while a schedule save is unanswered still draws the "
          "list and the running backup (the whole reply was dropped: a stalled save froze the card on "
          "'Backing up...' with the list never updating), and leaves the schedule selects on the pick",
          _out126.get("during") == {"rows": "during", "running": True, "sel": ["3", "3"]}, repr(_out126))
    check("Files & Config backup card: ...a save stops counting as unanswered after 15 s (fetch has no "
          "timeout), so a later read draws the schedule again; a save that answers after that is not "
          "released twice and its re-read draws what is stored",
          _out126.get("bound") == [15000]
          and _out126.get("after") == {"rows": "after", "sel": ["7", "3"]}
          and _out126.get("late") == {"rows": "late", "sel": ["3", "3"], "pending": 0}, repr(_out126))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The dashboard's install-progress rows under an active filter
# ════════════════════════════════════════════════════════════════════════════════════════════════
_IP126 = _read106("static", "js", "install_progress.js")
_name126 = "install progress: a row built under an active dashboard filter"
_out126 = _node121(_name126, _DOM121 + _SETTLE47 + _IP126 + r"""
const poll = async () => { window.watchInstallsNow(); await settle(); await settle(); };
const shown = id => { const r = row(id); return r ? r.style.display !== 'none' : null; };
const srv = id => root.querySelector('tr[data-server-id="' + id + '"]');
// what filterServers leaves: Alpha (7) matches, Beta (8) is hidden
const filter = () => { srv(7).style.display = ''; srv(8).style.display = 'none'; };
(async () => {
  const out = {};
  swap([7, 8]); filter(); onload(); await settle();
  // Beta starts installing, and so does Alpha (control): the poll builds both rows
  installs = [{id: 7, name: 'a', percent: 5}, {id: 8, name: 'b', percent: 5}]; await poll();
  out.live = [shown(7), shown(8)];
  // Beta ends with a caveat after a swap took its row (settle builds it), Alpha with one in place
  swap([7, 8]); filter(); installs = [];
  status['7'] = {status: 'done', warn: true, message: 'w7'};
  status['8'] = {status: 'done', warn: true, message: 'w8'}; await poll();
  out.ended = [shown(7), shown(8), (row(8) || {attrs: {}}).attrs['data-settled'] || null];
  // a swap the poll's own drawEndings answers (no filter pass after it)
  swap([7, 8]); filter(); await poll();
  out.redrawn = [shown(7), shown(8)];
  // 7 ends clean; before its 8 s timer runs, it installs again and ends with a caveat. The old timer
  // leaves the new ending's row alone.
  installs = [{id: 7, name: 'a', percent: 5}]; await poll(); touts = [];
  installs = []; status['7'] = {status: 'done'}; await poll(); const okTimers = touts.slice();
  installs = [{id: 7, name: 'a', percent: 5}]; await poll();
  installs = []; status['7'] = {status: 'done', warn: true, message: 'w7b'}; await poll();
  okTimers.forEach(f => f());
  out.oldTimer = {timers: okTimers.length, settled: (row(7) || {attrs: {}}).attrs['data-settled'] || null};
  console.log(JSON.stringify(out));
})();
""")
if _out126 is not None:
    check("install progress: a progress row a poll builds for a server the dashboard filter hides is hidden "
          "with it (a nameless bar showed among the servers that match); a visible server's row shows",
          _out126.get("live") == [True, False], repr(_out126))
    check("install progress: ...and so is an ending row built for it, by a settle after a swap took its "
          "row, and by a poll's redraw of kept endings",
          _out126.get("ended") == [True, False, "warn"] and _out126.get("redrawn") == [True, False],
          repr(_out126))
    check("install progress: a clean ending's 8 s timer leaves alone the ending of an install of the same "
          "server that ended after it (it dropped the new caveat's row, undismissed)",
          _out126.get("oldTimer") == {"timers": 1, "settled": "warn"}, repr(_out126))
