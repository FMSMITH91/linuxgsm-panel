"""Part 109 of the unit suite: the eighteenth review's page and script fixes (builder C).

Held here, each against the code path the finding named:

* the Raw config editor: a draft typed there is kept (and its Save refused as behind the file) when a
  settings save re-reads the cfg with the box NOT focused, the ordinary flow, since the Raw and
  settings tabs are separate panes; a refill clears a 'behind' note as it clears a 'stale' one.
* the GMod content card: a poll that could not read the host while a content job runs keeps polling
  (backing off), and says the job's line or outcome above the alert; it stopped for good.
* the Users page: a Lapsed invite has its Revoke button (it works again if its creator is reactivated).
* the Backups card (Server Management) and Files & Config's backup card: a re-read is not drawn from a
  read that may predate a settings or schedule save.
* the Live Resources card: an older /live answer arriving after a newer one is dropped.

HOW IT RUNS. Scripts in node on part87's DOM through part106's harness, with fetch answered by hand so
the order of replies is the check's; the Users page through part12's Flask app and client (part12 has
run), every stub through _p9_patch and undone in the finally.
"""
import json as _json109

from unit.part01 import check
from unit.part12 import P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_restore_all
from unit.part106 import _js106, _read106
from panel.db.models import AuditLog, Invite, User, db
from panel.security import auth as _auth109

_TRIP109_START = len(_P9_TRIPPED)

# fetch answered by hand: each request waits in `pend` until the check answers it, in any order.
_PEND109 = (
    "const pend = [];\n"
    "global.fetch = (u, o) => new Promise((res, rej) => pend.push({u, body: o && o.body ? JSON.parse(o.body) : null,\n"
    "  ok: d => res({ok: true, status: 200, json: () => Promise.resolve(d)}), fail: () => rej(new Error('x'))}));\n"
    "const take = pat => { const i = pend.findIndex(p => p.u.indexOf(pat) >= 0);\n"
    "  return i < 0 ? null : pend.splice(i, 1)[0]; };\n"
    "const count = pat => pend.filter(p => p.u.indexOf(pat) >= 0).length;\n"
    # answer a request that may not have been sent: a missing one fails its check by name, not a crash
    "const reply = (pat, d) => { const p = take(pat); if (p) p.ok(d); };\n"
    # timers recorded, not run: a check runs one by hand when it means to
    "const timers = []; global.setTimeout = (fn, ms) => { timers.push({fn, ms}); return timers.length; };\n"
    "global.clearTimeout = () => {};\n")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The Raw config editor keeps a draft typed before switching to the settings tab
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #443 kept a typed-into box only while it was FOCUSED. The Raw and settings tabs are separate panes,
# so a settings save is made with the box hidden and unfocused: the draft was replaced with the file's
# text and no word. And a refill after a 'behind' mark left the "Reload before saving" note beside a
# box whose Save worked again.
_SF109 = _read106("static", "js", "server_files.js")
_name109r = "Raw config editor: a settings save's re-read with the box unfocused"
_outr109 = _js106(_name109r, (
    "var serverId = 1; function _tr(s){ return s; }\n"
    "let sent = [];\n"
    "const reply = d => { global.fetch = (u, o) => { sent.push(o && o.body ? JSON.parse(o.body) : null);\n"
    "  return Promise.resolve({ok: true, status: 200, json: () => Promise.resolve(d)}); }; };\n"), _SF109, (
    "var _r26c_rawRead", "var _r29j_rawShown", "function _r29j_rawText(", "function loadConfig(",
    "function refreshRawConfig(", "function _r26c_rawStale(", "function _r29j_rawBehind(", "function saveRaw("), (
    "  const out = {}, ta = document.getElementById('cfg-raw'), msg = document.getElementById('cfg-raw-msg');\n"
    "  const save = async () => { sent = []; reply({success: true}); saveRaw(); await settle();\n"
    "    return sent.filter(Boolean).map(b => b.raw); };\n"
    "  const reread = async raw => { reply({groups: [], raw}); refreshRawConfig(); await settle(); };\n"
    "  document.activeElement = null;\n"
    # no read has filled the box yet: a re-read fills it (nothing typed there is a draft of the file)
    "  await reread('a=0\\n'); out.first = ta.value;\n"
    "  reply({groups: [], raw: 'a=1\\n'}); loadConfig(); await settle();\n"
    "  ta.value = 'a=1\\nb=9\\n';\n"
    "  await reread('a=2\\n');\n"
    "  out.blurTyped = {text: ta.value, note: msg.textContent !== ''};\n"
    "  out.blurTyped.posted = await save(); out.blurTyped.msg = msg.className;\n"
    # the operator puts the box back as it was filled: the next re-read refills it and the note goes
    "  _r26c_rawRead = 'behind'; msg.textContent = 'behind-note'; ta.value = 'a=1\\n';\n"
    "  await reread('a=3\\n');\n"
    "  out.refilled = {text: ta.value, note: msg.textContent, posted: await save()};\n"
    "  console.log(JSON.stringify(out));\n"))
if _outr109 is not None:
    check("Raw config editor: a draft typed in the Raw box, then a settings saved from the other tab (box "
          "unfocused), is kept and its Save refused with a note (#443 kept only a FOCUSED box, so the "
          "draft was replaced with no word)",
          _outr109.get("blurTyped") == {"text": "a=1\nb=9\n", "note": True, "posted": [],
                                        "msg": "small ms-2 text-danger"}, repr(_outr109))
    check("Raw config editor: ...a box refilled after a 'behind' mark loses the mark's note and saves, and "
          "a box no read ever filled is filled (controls)",
          _outr109.get("refilled") == {"text": "a=3\n", "note": "", "posted": ["a=3\n"]}
          and _outr109.get("first") == "a=0\n", repr(_outr109))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The GMod content card keeps polling a running job through an unread host
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SD109 = _read106("static", "js", "server_detail.js")
_name109g = "GMod content card: polls while a job runs"
_outg109 = _js106(_name109g, _PEND109 + (
    "var serverId = 1; global._esc = escapeHtml; global.tfHtml = (k, v) => k;\n"
    "const el = document.getElementById('gmod-content-body');\n"
    "const slot = new E87('div'); slot.remove = () => { slot.removed = true; };\n"
    "el.querySelector = q => q === '#gmc-outcome-slot'\n"
    "  && el.innerHTML.indexOf('gmc-outcome-slot') >= 0 ? slot : null;\n"
    "el.querySelectorAll = () => [];\n"), _SD109, (
    "var _r30c_gmcRunning", "function _r30c_gmcRepoll(", "function _r30c_gmcWorking(",
    "function loadGmodContent(", "function _gmcOutcome("), (
    "  const out = {};\n"
    "  const RUN = {status: 'running', msg: 'p109 downloading'};\n"
    "  const poll = async how => { const n = timers.length; loadGmodContent(); const p = take('gmod-content');\n"
    "    if (how === 'reject') p.fail(); else p.ok(how); await settle();\n"
    "    return timers.slice(n).map(t => t.ms); };\n"
    "  out.good = await poll({games: [], job: RUN});\n"
    "  out.unread1 = await poll({games: [], content_readable: false, job: RUN});\n"
    "  out.unreadHtml = [el.innerHTML.indexOf('p109 downloading') >= 0, el.innerHTML.indexOf('alert-warning') >= 0];\n"
    "  out.unread2 = await poll({games: [], mounts_readable: false, job: RUN});\n"
    "  out.unread3 = await poll({games: [], content_readable: false, job: RUN});\n"
    "  out.goodAgain = await poll({games: [], job: RUN});\n"
    "  out.error = await poll({error: 'x'});\n"
    "  out.rejected = await poll('reject');\n"
    # the job ended while the host still is not read: no more polls, and its outcome is said
    "  out.doneUnread = await poll({games: [], content_readable: false, job: {status: 'error', msg: 'p109 failed'}});\n"
    "  out.outcome = [slot.textContent, slot.className];\n"
    "  out.idleError = await poll({error: 'x'});\n"
    "  out.idleReject = await poll('reject');\n"
    "  console.log(JSON.stringify(out));\n"))
if _outg109 is not None:
    check("GMod content card: a poll that could not read the host while a content job runs polls again, "
          "backing off 5 s, 10 s, 20 s, and keeps the job's line above the alert (it stopped for good, so "
          "the job's outcome was never shown without a reload)",
          _outg109.get("unread1") == [5000] and _outg109.get("unread2") == [10000]
          and _outg109.get("unread3") == [20000] and _outg109.get("unreadHtml") == [True, True],
          repr(_outg109))
    check("GMod content card: ...an error reply or no reply during a running job polls again too, and a "
          "good read resets the backoff (controls: a good running read polls at 5 s)",
          _outg109.get("good") == [5000] and _outg109.get("goodAgain") == [5000]
          and _outg109.get("error") == [5000] and _outg109.get("rejected") == [10000], repr(_outg109))
    check("GMod content card: ...a job that ended while the host is unread shows its outcome above the "
          "alert and stops polling, and with no job running a failed poll schedules nothing",
          _outg109.get("doneUnread") == [] and _outg109.get("idleError") == [] and _outg109.get("idleReject") == []
          and isinstance(_outg109.get("outcome"), list) and "p109 failed" in _outg109["outcome"][0]
          and "text-danger" in _outg109["outcome"][1], repr(_outg109))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The Backups card (Server Management) does not draw a read that may predate a save
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BK109 = _read106("static", "js", "remote_manage_backups.js")
_LIST109 = {"settings": {"enabled": True, "keep_days": 5}, "full": {"interval_days": 7, "keep": 2},
            "games": [{"id": 4, "name": "p109"}], "backups": []}
_name109b = "Backups card: a re-read and a save in flight"
_outb109 = _js106(_name109b, _PEND109 + (
    "global.bkMsg = () => {}; global.bkApplyLimits = () => {}; global.bkRenderDisk = () => {};\n"
    "global.fbSummary = () => {}; global.bkRenderFullStatus = () => {}; global.bkRenderAutoStatus = () => {};\n"
    "global.bkRenderList = () => {}; global.bkShowEncState = () => {}; global.bkRenderFullSchedule = () => {};\n"
    "global.schedNote = () => ''; global._r20cIntervalOption = () => {};\n"
    "let drawn = 0; global.bkRenderGames = () => { drawn++; };\n"
    "const iv = document.getElementById('gsi-4'); iv.value = '3';\n"
    "const kp = document.getElementById('gsk-4'); kp.value = ''; kp.validity = {};\n"), _BK109, (
    "var _r30c_bkSaving", "function _r30c_bkSave(", "function _r25c_bkUnread(", "function _r29c_bkSetIdle(",
    "function _r29c_bkEditing(", "function loadBackups(", "function setGameSchedule("), (
    "  const out = {};\n"
    "  const SAVED = {success: true, schedule: {interval_set: true, interval_days: 3, keep_set: false, keep: 2}};\n"
    "  const LIST = " + _json109.dumps(_LIST109) + ";\n"
    "  const reset = () => { global._bkSched = {4: {interval_set: false, keep_set: false}}; };\n"
    # a re-read asked for while a save is unanswered (a blur: the field's change, then the held re-read)
    "  reset(); setGameSchedule(4); loadBackups();\n"
    "  out.heldWhileSaving = count('/api/panel/backups');\n"
    "  reply('/schedule', SAVED); await settle();\n"
    "  out.sentAfterSave = count('/api/panel/backups');\n"
    "  reply('/api/panel/backups', LIST); await settle(); out.drawnAfter = drawn;\n"
    # a read already on its way when a save starts: its reply is dropped and the card read again
    "  drawn = 0; reset(); loadBackups(); setGameSchedule(4);\n"
    "  reply('/schedule', SAVED); await settle();\n"
    "  reply('/api/panel/backups', LIST); await settle();\n"
    "  out.olderRead = [drawn, global._bkSched[4].interval_set, count('/api/panel/backups')];\n"
    "  reply('/api/panel/backups', LIST); await settle(); out.olderReadThen = drawn;\n"
    # a save that never answers stops holding re-reads back once its time is up
    "  drawn = 0; reset(); const n = timers.length; setGameSchedule(4); loadBackups();\n"
    "  const held = count('/api/panel/backups');\n"
    "  timers.slice(n).filter(t => t.ms === 15000).forEach(t => t.fn());\n"
    "  out.stalled = [held, count('/api/panel/backups')];\n"
    "  console.log(JSON.stringify(out));\n"))
if _outb109 is not None:
    check("Backups card: a re-read asked for while a Schedule/Keep save is unanswered is sent once the "
          "save has answered (nothing ordered the two: a read served first redrew the old schedule "
          "beside '✓ Schedule saved')",
          _outb109.get("heldWhileSaving") == 0 and _outb109.get("sentAfterSave") == 1
          and _outb109.get("drawnAfter") == 1, repr(_outb109))
    check("Backups card: ...a read already sent when a save starts is not drawn (window._bkSched keeps what "
          "the save stored) and the card is read again; a save that never answers stops holding re-reads "
          "back after 15 s",
          _outb109.get("olderRead") == [0, True, 1] and _outb109.get("olderReadThen") == 1
          and _outb109.get("stalled") == [0, 1], repr(_outb109))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Files & Config's backup card: the same, for its schedule selects and 4 s poll
# ════════════════════════════════════════════════════════════════════════════════════════════════
_name109f = "Files & Config backup card: reads and a schedule save"
_outf109 = _js106(_name109f, _PEND109 + (
    "var serverId = 1; const seen = []; global.renderBackups = d => seen.push(d.tag);\n"
    "document.getElementById('bk-interval').value = '3'; document.getElementById('bk-keep').value = '';\n"), _SF109, (
    "var _bkShown", "var _r30c_sfBkSaves", "function loadBackups(", "function saveBkSchedule("), (
    "  const out = {};\n"
    "  loadBackups(); saveBkSchedule();\n"
    "  reply('/info', {tag: 'before-save'}); await settle();\n"
    "  reply('/schedule', {success: true}); await settle();\n"
    "  reply('/info', {tag: 'after-save'}); await settle();\n"
    "  loadBackups(); loadBackups();\n"
    "  const older = take('/info'); take('/info').ok({tag: 'newer'}); await settle();\n"
    "  older.ok({tag: 'older'}); await settle();\n"
    "  out.seen = seen;\n"
    "  console.log(JSON.stringify(out));\n"))
if _outf109 is not None:
    check("Files & Config backup card: a read sent before a schedule save is not drawn after it (it put the "
          "old schedule back in the select and in _bkShown), nor an older read after a newer one; the "
          "save's own re-read is drawn (control)",
          _outf109.get("seen") == ["after-save", "newer"], repr(_outf109))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Live Resources: an older /live answer arriving after a newer one is dropped
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM109 = _read106("static", "js", "remote_manage.js")
_name109l = "Live Resources: /live answers out of order"
_outl109 = _js106(_name109l, _PEND109 + (
    "var REMOTE_ID = 1; let painted = 0, badge = [];\n"
    "global._r18cPaintHostBadge = up => badge.push(up); global._livePaintCpu = () => { painted++; };\n"
    "global._livePaintMemory = () => {}; global._livePaintDisk = () => {};\n"), _RM109, (
    "var _r29c_liveMiss", "var _r30c_liveSent", "function _r30c_liveOld(", "function pollLive("), (
    "  const st = document.getElementById('live-stale'), out = {};\n"
    "  st.style.display = 'none';\n"
    # A slow, then B fails, then A answers good, then C fails: two misses in a row, A is older than B
    "  pollLive(); const a = take('/live'); pollLive(); take('/live').fail(); await settle();\n"
    "  a.ok({cpu: 1}); await settle();\n"
    "  pollLive(); take('/live').fail(); await settle();\n"
    "  out.missMiss = [st.style.display, painted, badge.length];\n"
    # D slow, E answers an error, D answers good late: the paused note stays, the host is not Reachable
    "  pollLive(); const d = take('/live'); pollLive(); take('/live').ok({error: 'x'}); await settle();\n"
    "  d.ok({cpu: 1}); await settle();\n"
    "  out.errorThenOld = [st.style.display, painted, badge.indexOf(true)];\n"
    # in order, a good answer clears it (control)
    "  const before = painted; pollLive(); take('/live').ok({cpu: 1}); await settle();\n"
    "  out.inOrder = [st.style.display, painted - before];\n"
    "  console.log(JSON.stringify(out));\n"))
if _outl109 is not None:
    check("Live Resources: an older /live answer arriving after a newer one is dropped: it reset the miss "
          "count between two misses (the paused note never came), and after an error it hid the note and "
          "painted the host Reachable",
          _outl109.get("missMiss") == ["", 0, 0] and _outl109.get("errorThenOld") == ["", 0, -1], repr(_outl109))
    check("Live Resources: ...an answer in order is drawn and clears the note (control)",
          _outl109.get("inOrder") == ["none", 1], repr(_outl109))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. A Lapsed invite can be revoked
# ════════════════════════════════════════════════════════════════════════════════════════════════
# Lapsed is not dead: Invite.authority_intact reads its creator's current row at redemption, so the
# link works again once they are reactivated, and it counts toward Invite.MAX_LIVE, whose refusal
# says to revoke links that had no Revoke button.
_mine109 = {"users": [], "invites": []}
try:
    _p9_arm(who="part109")
    with _p9.app_context():
        _cr109 = User(username="p109_creator", password_hash=_auth109.hash_password("Str0ng!passw0rd-p109"),
                      display_name="p109 creator", is_superadmin=True, is_active=True)
        db.session.add(_cr109)
        db.session.commit()
        _mine109["users"].append(_cr109.id)
        _inv109, _tok109 = Invite.mint(_cr109, hours=720, superadmin=True, note="p109-lapsed")
        db.session.add(_inv109)
        _cr109.is_active = False                     # deactivated: the invite reads Lapsed
        db.session.commit()
        _iid109 = _inv109.id
        _mine109["invites"].append(_iid109)
    _c109 = _p9_client(P9_ADMIN)
    _page109 = _c109.get("/users").get_data(as_text=True)
    _row109 = _page109[_page109.find("p109-lapsed"):][:2500]
    _r109 = _c109.post("/users/invite/%d/revoke" % _iid109, headers={"X-Requested-With": "XMLHttpRequest"})
    with _p9.app_context():
        _rev109 = db.session.get(Invite, _iid109).revoked_at is not None
    check("Users page: a Lapsed invite (its creator deactivated) has a Revoke button, and posting it "
          "revokes the link (it had none, yet works again if the creator is reactivated, and counts "
          "toward the live-invite cap)",
          "Lapsed" in _row109 and ("/users/invite/%d/revoke" % _iid109) in _row109
          and _r109.status_code == 200 and _rev109, repr((_row109[:300], _r109.status_code, _rev109)))
finally:
    _p9_restore_all()
    with _p9.app_context():
        if _mine109["invites"]:
            Invite.query.filter(Invite.id.in_(_mine109["invites"])).delete(synchronize_session=False)
        AuditLog.query.filter(AuditLog.target == "p109-lapsed").delete(synchronize_session=False)
        for _u109 in _mine109["users"]:
            _urow109 = db.session.get(User, _u109)
            if _urow109 is not None:
                db.session.delete(_urow109)
        db.session.commit()

check("part109: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP109_START, repr(_P9_TRIPPED[_TRIP109_START:][:6]))
