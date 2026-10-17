"""Part 112 of the unit suite: the nineteenth review's page fixes (builder C).

Held here, each against the code path the finding named:

* Files & Config's backup card: a schedule save that FAILED reads the card again. #444 dropped a read
  sent before a save and counted on the save's success to read again, so after a failed save the
  dropped read's update was lost (a deleted backup still listed) and the select kept the choice it
  never stored.
* the GMod content card: the first poll after Apply/Uninstall started a job polls again when it
  misses. The re-poll keyed on the last ANSWERED job state, which is "none running" until a poll
  after the start is answered, so that poll missing stopped the card for good.
* Tailscale's Peer Reachability Check: a refusal (the route's 400 for a host it will not ping, a 403,
  a 500) says the route's reason. It was printed as "<host> is not responding", about a peer nobody
  pinged.
* the OS Updates card (integration): a start the route refused (an update the panel did not start is
  running, the probe went unanswered, a reboot under way) or never answered says so on the card too.
  The card kept "Installing updates… (watch the popup)", written before the request.

HOW IT RUNS. Scripts in node on part87's DOM through part106's harness, with fetch answered by hand so
the order of replies is the check's; the check-peer route through part12's Flask app and client
(part12 has run), which refuses the host before anything would be pinged.
"""
import json as _json112

from unit.part01 import check
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9_arm, _p9_client, _p9_restore_all
from unit.part106 import _js106, _read106
from unit.part109 import _PEND109
from panel.ops import system_ops as _so112

_TRIP112_START = len(_P9_TRIPPED)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Files & Config's backup card reads again after a schedule save that failed
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SF112 = _read106("static", "js", "server_files.js")
_name112f = "Files & Config backup card: a schedule save that failed"
_outf112 = _js106(_name112f, _PEND109 + (
    "var serverId = 1; const seen = []; global.renderBackups = d => seen.push(d.tag);\n"
    "document.getElementById('bk-interval').value = '3'; document.getElementById('bk-keep').value = '';\n"), _SF112, (
    "var _bkShown", "var _r30c_sfBkSaves", "function loadBackups(", "function saveBkSchedule("), (
    "  const out = {};\n"
    # a read on its way (a delete's re-read), then a save that the route refuses
    "  loadBackups(); saveBkSchedule();\n"
    "  reply('/info', {tag: 'dropped-1'}); await settle();\n"
    "  reply('/schedule', {success: false}); await settle();\n"
    "  out.refusedReads = count('/info');\n"
    "  reply('/info', {tag: 'after-refused'}); await settle();\n"
    # the same with a save that got no answer at all
    "  loadBackups(); saveBkSchedule();\n"
    "  reply('/info', {tag: 'dropped-2'}); await settle();\n"
    "  take('/schedule').fail(); await settle();\n"
    "  out.failedReads = count('/info');\n"
    "  reply('/info', {tag: 'after-failed'}); await settle();\n"
    "  out.seen = seen;\n"
    "  console.log(JSON.stringify(out));\n"))
if _outf112 is not None:
    check("Files & Config backup card: a schedule save the route refused, or that got no answer, reads the "
          "card again, so a read it dropped is not lost (a deleted backup stayed listed and the select "
          "kept the unsaved choice until a reload)",
          _outf112.get("refusedReads") == 1 and _outf112.get("failedReads") == 1
          and _outf112.get("seen") == ["after-refused", "after-failed"], repr(_outf112))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The GMod content card: the first poll after a job started polls again when it misses
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SD112 = _read106("static", "js", "server_detail.js")
_name112g = "GMod content card: the first poll after Apply"
_outg112 = _js106(_name112g, _PEND109 + (
    "var serverId = 1; global._esc = escapeHtml; global.tfHtml = (k, v) => k;\n"
    "const el = document.getElementById('gmod-content-body');\n"
    "el.querySelector = () => null; el.querySelectorAll = () => [];\n"), _SD112, (
    "var _r30c_gmcRunning", "function _r30c_gmcRepoll(", "function _r30c_gmcWorking(",
    "function loadGmodContent(", "function _gmcOutcome(", "function _gmcPost("), (
    "  const out = {};\n"
    # the card was last drawn with no job running: that is when Apply is offered
    "  loadGmodContent(); take('gmod-content').ok({games: []}); await settle();\n"
    # Apply: the POST answers success, its 1.5 s poll runs and gets `answer`; the timers it then set
    "  const afterApply = async (posted, answer) => {\n"
    "    timers.length = 0; _gmcPost({action: 'mount', games: ['css']}, 'Applying…');\n"
    "    take('gmod-content').ok(posted); await settle();\n"
    "    const first = timers.filter(t => t.ms === 1500); first.forEach(t => t.fn());\n"
    "    const n = timers.length, p = take('gmod-content');\n"
    "    if (!p) return 'no poll';\n"
    "    if (answer === 'reject') p.fail(); else p.ok(answer); await settle();\n"
    "    return timers.slice(n).map(t => t.ms); };\n"
    "  out.error = await afterApply({success: true}, {error: 'x', games: []});\n"
    "  out.rejected = await afterApply({success: true}, 'reject');\n"
    # controls: a good read that finds no job running stops the polling; then a refused Apply started
    # no job, so a failed poll after it schedules nothing
    "  out.endedGood = await afterApply({success: true}, {games: []});\n"
    "  out.refused = await afterApply({success: false, message: 'busy'}, {error: 'x'});\n"
    "  console.log(JSON.stringify(out));\n"))
if _outg112 is not None:
    check("GMod content card: the first poll after Apply or Uninstall started a job polls again when it "
          "misses (an error reply, no reply), backing off from 5 s (it keyed on the last answered job "
          "state, 'none running' before the start, so the card stopped for good)",
          _outg112.get("error") == [5000] and _outg112.get("rejected") == [5000], repr(_outg112))
    check("GMod content card: ...a refused Apply (no job started) schedules nothing after a failed poll, "
          "and a good read with no job running stops (controls)",
          _outg112.get("refused") == [] and _outg112.get("endedGood") == [], repr(_outg112))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Peer Reachability Check: a refusal is said as the route's reason, not as "not responding"
# ════════════════════════════════════════════════════════════════════════════════════════════════
_TS112 = _read106("static", "js", "tailscale.js")
_name112t = "Peer Reachability Check: the route's refusals"
_outt112 = _js106(_name112t, _PEND109 + (
    "global.tfHtml = (k, v) => k.replace(/\\{(\\w+)\\}/g, (m, n) => escapeHtml(String(v[n])));\n"
    "document.getElementById('peer-host').value = 'http://box.tailnet.ts.net';\n"), _TS112, (
    "function checkPeer(",), (
    "  const out = {}, res = document.getElementById('peer-result');\n"
    "  const ask = async d => { res.innerHTML = ''; res.textContent = ''; checkPeer();\n"
    "    take('check-peer').ok(d); await settle();\n"
    "    return {text: res.textContent, html: String(res.innerHTML), danger: res.children.map(c => c.className)}; };\n"
    "  out.invalid = await ask({success: false, message: 'Enter a hostname or IP address.'});\n"
    "  out.bare = await ask({success: false, error: 'x'});\n"
    "  out.down = await ask({success: true, reachable: false, is_tailscale_ip: false});\n"
    "  out.up = await ask({success: true, reachable: true, latency_ms: 4});\n"
    "  console.log(JSON.stringify(out));\n"))
if _outt112 is not None:
    _inv112 = _outt112.get("invalid") or {}
    check("Peer Reachability Check: the route's 400 for a host it will not ping shows the route's reason, "
          "not '<host> is not responding' (a reading nobody took, about a peer that may be up)",
          _inv112.get("text") == "Enter a hostname or IP address." and "not responding" not in _inv112.get("html", "")
          and _inv112.get("danger") == ["text-danger"], repr(_outt112))
    check("Peer Reachability Check: ...a refusal with no message (a 403, the catch-all 500) says the check "
          "failed; a real reading still says not responding / reachable (controls)",
          (_outt112.get("bare") or {}).get("text") == "Error checking host"
          and "not responding" not in (_outt112.get("bare") or {}).get("html", "")
          and "http://box.tailnet.ts.net is not responding" in (_outt112.get("down") or {}).get("html", "")
          and "is reachable (4ms)" in (_outt112.get("up") or {}).get("html", ""), repr(_outt112))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The OS Updates card says a refused start was refused (integration of B's foreign-update refusal)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM112 = _read106("static", "js", "remote_manage.js")
_name112o = "OS Updates card: a start the route refused"
_outo112 = _js106(_name112o, _PEND109 + (
    "global.MOUNT = ''; global.REMOTE_ID = 3;\n"), _RM112, (
    "var _osuTimer", "function _startOsUpdate(", "function _r31j_osuNotStarted(", "function _pollOsUpdate("), (
    "  const info = document.getElementById('update-info'), st = document.getElementById('osu-state'),\n"
    "        spin = document.getElementById('osu-spin');\n"
    "  const start = async how => { info.textContent = '3 updates available'; spin.style.display = '';\n"
    "    _startOsUpdate(); const p = take('/os-update/start');\n"
    "    if (!p) return 'no start sent';\n"
    "    if (how === 'reject') p.fail(); else p.ok(how); await settle();\n"
    "    return {card: info.textContent, popup: st.textContent, cls: st.className, spin: spin.style.display,\n"
    "            polls: count('/os-update/status')}; };\n"
    "  const out = {};\n"
    "  out.busy = await start({success: false, message: " + _json112.dumps(_so112.R31B_UPDATE_BUSY) + "});\n"
    "  out.rejected = await start('reject');\n"
    "  out.started = await start({success: true, message: 'started'});\n"
    "  console.log(JSON.stringify(out));\n"))
if _outo112 is not None:
    _busy112 = _outo112.get("busy") or {}
    _rej112 = _outo112.get("rejected") or {}
    check("OS Updates card: a start refused because an update the panel did not start is running says so in "
          "the popup AND on the card, stops the spinner and watches nothing (the card kept 'Installing "
          "updates… (watch the popup)' about an update the panel never started)",
          _busy112.get("card") == _so112.R31B_UPDATE_BUSY and _busy112.get("popup") == _so112.R31B_UPDATE_BUSY
          and "text-danger" in (_busy112.get("cls") or "") and _busy112.get("spin") == "none"
          and _busy112.get("polls") == 0, repr(_outo112))
    check("OS Updates card: ...a start that got no answer says it could not start on the card too; a start "
          "that worked still says Installing and polls (control)",
          _rej112.get("card") == "Couldn't start the update." and _rej112.get("polls") == 0
          and (_outo112.get("started") or {}).get("card") == "Installing updates… (watch the popup)"
          and (_outo112.get("started") or {}).get("polls") == 1, repr(_outo112))

# The page's assumption, held against the route: what it refuses arrives as success:false + message.
try:
    _p9_arm(who="part112")
    _c112 = _p9_client(P9_ADMIN)
    _r112 = _c112.post("/api/tailscale/check-peer", json={"host": "http://box.tailnet.ts.net"},
                       headers={"X-Requested-With": "XMLHttpRequest"})
    _j112 = _r112.get_json(silent=True) or {}
    check("Peer Reachability Check: the route refuses a URL-shaped host with 400 {success: false, message} "
          "(the shape the page now reads) before anything is pinged",
          _r112.status_code == 400 and _j112.get("success") is False
          and _j112.get("message") == "Enter a hostname or IP address." and "reachable" not in _j112,
          repr((_r112.status_code, _j112)))
finally:
    _p9_restore_all()

check("part112: nothing its route drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP112_START, repr(_P9_TRIPPED[_TRIP112_START:][:6]))
