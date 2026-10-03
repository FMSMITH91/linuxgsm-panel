"""Page flows: what tools/js_coverage/walk.py does on a page after pressing every control once.

Pressing each distinct control once reaches most of a page, but not what needs an order or a value:
typing a console command and sending it, opening a folder and then a file in it, ticking servers
and then a bulk action, answering a dialog OK on one path and Cancel on another, dragging a row by
its handle, dropping a folder from disk. Each flow here is a function of the Driver, run with the
page loaded; most of it is in-page JavaScript (driver.run: an async body with the helpers as `J`),
and the rest is input only the browser can make (driver.drag, .keys, .drop_files).

Every step goes through the page's own handlers — a click, a key, a drop, an event the element
would fire — never a panel function called directly, so what is measured is what a person can
reach. A flow that no longer finds its element does nothing and says nothing; the coverage it
produced drops, which is where a renamed element shows up.
"""
import json
import os

import pyotp

# ── shared ─────────────────────────────────────────────────────────────────────────────────────
# Answer the dialog the last step opened: OK (typing the password or the name it asks for) or
# Cancel. The same helper the walk uses between controls.
OK = "J.settleDialogs(true, PW); await J.sleep(400);"
CANCEL = "J.settleDialogs(false, PW); await J.sleep(200);"


def js(body):
    """Make a flow of one in-page script."""
    def flow(d):
        d.run(body)
    flow.__doc__ = "In-page: " + " ".join(body.split())[:60]
    return flow


# ── the command palette (every page; run on the dashboard) ────────────────────────────────────
PALETTE = r"""
J.key(document, 'k', {ctrlKey: true}); await J.sleep(400);
const inp = document.getElementById('cmdk-input');
if (!inp) return 0;
for (const q of ['sur', 'fire', 'restart', 'zzzz-nothing', '']) {
  J.type('#cmdk-input', q); await J.sleep(150);
  J.key(document, 'ArrowDown'); J.key(document, 'ArrowDown'); J.key(document, 'ArrowUp');
}
J.type('#cmdk-input', 'restart'); await J.sleep(200);
const li = document.querySelector('.cmdk-item');
if (li) li.dispatchEvent(new MouseEvent('mousemove', {bubbles: true}));
J.key(document, 'Enter'); await J.sleep(300);
J.settleDialogs(false);
J.key(document, 'k', {ctrlKey: true}); await J.sleep(200);
J.type('#cmdk-input', 'start'); await J.sleep(200);
const row = Array.from(document.querySelectorAll('.cmdk-item')).find(r => r.dataset.act === 'start');
if (row) row.click();
await J.sleep(300);
J.key(document, 'k', {ctrlKey: true}); await J.sleep(200); J.key(document, 'Escape');
J.key(document, 'k', {ctrlKey: true}); await J.sleep(200);
const box = document.getElementById('cmdk'); if (box) box.click();
return 1;
"""

# ── the dashboard ──────────────────────────────────────────────────────────────────────────────
DASH_FILTERS = r"""
for (const q of ['sur', 'zzzz', 'rust', '']) { J.type('#srv-search', q); await J.sleep(150); }
// Tag filters: one on, a second on (rows must carry both), both off again.
J.click('[data-action="toggleTagFilter"]', 0); await J.sleep(150);
J.click('[data-action="toggleTagFilter"]', 1); await J.sleep(150);
J.click('[data-action="toggleTagFilter"]', 1); J.click('[data-action="toggleTagFilter"]', 0);
// Sorting: every column of the first host, twice (ascending, then descending).
const heads = document.querySelectorAll('.server-remote-card:first-of-type [data-action="sortDashCol"]');
for (const h of heads) { h.click(); await J.sleep(60); h.click(); await J.sleep(60); }
return 1;
"""

DASH_BULK = r"""
// Tick servers one by one, the whole of one host, then everything shown.
const boxes = Array.from(document.querySelectorAll('.srv-check'));
for (const b of boxes.slice(0, 3)) { b.checked = true; b.dispatchEvent(new Event('change', {bubbles: true})); }
J.click('.srv-check-all', 0); await J.sleep(100);
J.click('[data-action="selectAllShown"]'); await J.sleep(100);
// Each bulk action: the ones that ask are cancelled once and confirmed once.
for (const act of ['stop', 'restart', 'update', 'start']) {
  const btn = document.querySelector('.bulk-bar [data-action="bulkAction"][data-args*="' + act + '"]');
  if (!btn) continue;
  btn.click(); await J.sleep(300); J.settleDialogs(false, PW); await J.sleep(150);
  if (!document.querySelector('.srv-check:checked')) J.click('[data-action="selectAllShown"]');
  btn.click(); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(900);
  J.click('[data-action="selectAllShown"]'); await J.sleep(100);
}
J.click('[data-action="clearSelection"]');
// A row's own actions: Stop on a server with players asks first (Cancel, then OK).
const stop = document.querySelector('[data-action="doAction"][data-args*="stop"]');
if (stop) {
  stop.click(); await J.sleep(300); J.settleDialogs(false, PW);
  stop.click(); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(800);
}
// Copying a server's address.
const code = document.querySelector('[id^="connect-"] code');
if (code) code.click();
return 1;
"""

DASH_LAYOUT = r"""
J.click('[data-action="toggleLayoutEdit"]'); await J.sleep(200);
// Down, then back up: the first of each kind, so neither is the no-op at an end.
for (const kind of ['movePanel', 'moveHostCard', 'moveServerRow']) {
  J.click('[data-action="' + kind + '"][data-args^="[1"]', 0); await J.sleep(300);
  J.click('[data-action="' + kind + '"][data-args^="[-1"]', 1); await J.sleep(300);
}
return 1;
"""

DASH_HIDE_SHOW = r"""
// Hiding a stat tile drops a restore chip; restoring saves and reloads the page.
J.click('[data-action="hidePanel"]', 0); await J.sleep(500);
J.click('[data-action="showPanel"]'); await J.sleep(1500);
return 1;
"""

DASH_TAGS = r"""
J.type('#tag-name', 'jscov-tag'); J.type('#tag-color', '#aa3355');
const notify = document.getElementById('tag-notify');
if (notify) { notify.checked = false; }
J.click('[data-action="createTag"]'); await J.sleep(800);
J.type('#tag-name', 'jscov-tag'); J.click('[data-action="createTag"]'); await J.sleep(600);  // a duplicate
// The tag editor: tick every tag on the first server, save; open it again and cancel.
J.click('[data-action="editServerTags"]', 0); await J.sleep(800);
document.querySelectorAll('[id^="tagcb-"]').forEach(cb => { cb.checked = !cb.checked; });
J.settleDialogs(true, PW); await J.sleep(800);
J.click('[data-action="editServerTags"]', 1); await J.sleep(800); J.settleDialogs(false, PW);
// Delete the new tag from the list: Cancel, then OK.
const del = () => Array.from(document.querySelectorAll('#tag-list button')).pop();
if (del()) { del().click(); await J.sleep(200); J.settleDialogs(false, PW); }
if (del()) { del().click(); await J.sleep(200); J.settleDialogs(true, PW); await J.sleep(800); }
return 1;
"""


def dash_drag(d):
    """Drag a stat tile, a host card and a server row by their handles, with a real pointer."""
    d.run("J.click('[data-action=\"toggleLayoutEdit\"]'); await J.sleep(200); "
          "if (!document.body.classList.contains('layout-edit')) "
          "J.click('[data-action=\"toggleLayoutEdit\"]');")
    d.drag("#dash-tiles [data-drag-handle]", 260, 0)
    d.drag("#server-cards > .server-remote-card [data-drag-handle]", 0, 240)
    d.drag(".server-remote-card tbody [data-drag-handle]", 0, 110)
    d.drag(".server-remote-card tbody [data-drag-handle]", 1, 1)      # a shaky click: no move
    d.run("J.click('[data-action=\"toggleLayoutEdit\"]');")


# ── a server: console, players, actions ───────────────────────────────────────────────────────
CONSOLE = r"""
const out = document.getElementById('console-output');
if (J.q('#command-input') && J.q('#command-form')) {
  for (const c of ['status', 'say hello']) {
    J.type('#command-input', c);
    J.q('#command-form').dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
    await J.sleep(400);
  }
}
if (out) {
  out.focus();
  out.dispatchEvent(new KeyboardEvent('keydown', {key: 'a', ctrlKey: true, bubbles: true, cancelable: true}));
  out.scrollTop = 0; out.dispatchEvent(new Event('scroll'));
  await J.sleep(600);
  out.scrollTop = out.scrollHeight; out.dispatchEvent(new Event('scroll'));
}
// The console controls: timestamps off and on, older lines, clear.
J.click('[data-action="toggleConsoleTs"]'); await J.sleep(200);
J.click('[data-action="toggleConsoleTs"]'); await J.sleep(200);
J.click('[data-action="loadMoreConsole"]'); await J.sleep(1200);
// The poller pushes new lines every few seconds: stay long enough to receive some.
await J.sleep(6000);
J.click('[data-action="clearConsole"]'); await J.sleep(300);
await J.sleep(3000);
return 1;
"""

PLAYERS = r"""
J.click('[data-action="refreshPlayers"]'); await J.sleep(1500);
// Announce, by Enter in the box.
if (J.type('#pl-say', 'hello everyone')) {
  J.q('#pl-say').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true, cancelable: true}));
  await J.sleep(600);
}
// Ban asks for a scope (this server / all of them, with a reason); the backdrop cancels.
const ban = () => document.querySelector('#pl-rows [data-action="moderatePlayer"][data-args*="ban"]');
for (const pick of ['[data-scope="this"]', '[data-scope="all"]', null]) {
  if (!ban()) break;
  ban().click(); await J.sleep(300);
  if (pick) { J.type('#ban-reason', 'jscov'); J.click(pick); }
  else {
    const ov = Array.from(document.querySelectorAll('body > div')).pop();
    if (ov) ov.dispatchEvent(new MouseEvent('click', {bubbles: true}));
  }
  await J.sleep(1500);
}
J.click('#pl-rows [data-action="moderatePlayer"][data-args*="kick"]'); await J.sleep(1500);
// A custom command with an argument, run by Enter in its box, and one without.
const arg = document.querySelector('.custom-cmd .cc-arg');
if (arg) {
  J.type('.custom-cmd .cc-arg', 'de_dust2');
  arg.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true, cancelable: true}));
  await J.sleep(800);
}
return 1;
"""

SERVER_ACTIONS = r"""
// Stop and Restart ask first when players are on: "when empty" queues it and shows the banner.
for (const act of ['restart', 'stop']) {
  const b = Array.from(document.querySelectorAll('[data-action="serverAction"]'))
    .find(x => JSON.parse(x.getAttribute('data-args') || '[]')[0] === act);
  if (!b) continue;
  b.click(); await J.sleep(1200);
  const later = Array.from(document.querySelectorAll('body > div button')).find(x => /empty/i.test(x.textContent));
  if (later) { later.click(); await J.sleep(1200); }
  else J.settleDialogs(false, PW);
}
J.click('[data-action="bannerDoNow"]'); await J.sleep(400); J.settleDialogs(false, PW);
// The schedule: daily restart on, a new time, off; notify-when-empty both ways.
J.click('[data-action="toggleDailyRestart"]'); await J.sleep(500);
J.type('[data-action="setDailyRestartTime"]', '04:30'); await J.sleep(500);
J.click('[data-action="toggleDailyRestart"]'); await J.sleep(500);
J.click('[data-action="toggleNotifyEmpty"]'); await J.sleep(400);
J.click('[data-action="toggleNotifyEmpty"]'); await J.sleep(400);
J.click('[data-action="toggleAutostart"]'); await J.sleep(400);
J.click('[data-action="toggleAutostart"]'); await J.sleep(400);
return 1;
"""

# ── a server's files ───────────────────────────────────────────────────────────────────────────
FILES = r"""
const list = document.getElementById('file-list');
const pick = (type) => list && Array.from(list.querySelectorAll('[data-path]')).find(r => r.dataset.type === type);
let d = pick('dir'); if (d) { d.click(); await J.sleep(800); }
const crumb = document.querySelector('#breadcrumb [data-nav]'); if (crumb) { crumb.click(); await J.sleep(800); }
let f = pick('file'); if (f) { f.click(); await J.sleep(800); }
if (J.q('#editor')) {
  J.type('#editor', J.q('#editor').value + '\n# edited\n');
  J.q('#editor').scrollTop = 40; J.q('#editor').dispatchEvent(new Event('scroll'));
}
J.click('[data-action="saveFile"]'); await J.sleep(600);
J.click('[data-action="closeEditor"]'); await J.sleep(300);
const up = document.getElementById('upload-input');
if (up) {
  const dt = new DataTransfer();
  // Two that clash with what is there (a file, and a folder of the same name) and one that does not.
  dt.items.add(new File(['hello'], 'notes.txt', {type: 'text/plain', lastModified: Date.now()}));
  dt.items.add(new File(['x'], 'log', {type: 'text/plain', lastModified: Date.now() - 4e10}));
  dt.items.add(new File(['x=1'], 'fresh.cfg', {type: 'text/plain'}));
  up.files = dt.files;
  up.dispatchEvent(new Event('change', {bubbles: true}));
  await J.sleep(1200); J.settleDialogs(true, PW); await J.sleep(1500);
}
const upDir = document.getElementById('upload-dir-input');
if (upDir) {
  const dt = new DataTransfer();
  dt.items.add(new File(['a'], 'a.cfg', {type: 'text/plain'}));
  upDir.files = dt.files;
  upDir.dispatchEvent(new Event('change', {bubbles: true}));
  await J.sleep(1200); J.settleDialogs(true, PW); await J.sleep(1200);
}
// Delete: a file, Cancel then OK.
const del = () => document.querySelector('#file-list [data-action="delete"]');
if (del()) { del().click(); await J.sleep(300); J.settleDialogs(false, PW); }
if (del()) { del().click(); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1200); }
return 1;
"""

CRON = r"""
const sched = document.getElementById('cron-sched'), cmd = document.getElementById('cron-cmd');
if (!sched || !cmd) return 0;
for (const s of ['*/15 * * * *', '0 4 * * 1-5', '30 3 1,15 * *', '@reboot', 'bad cron']) {
  J.type('#cron-sched', s); await J.sleep(150);
}
J.type('#cron-sched', '0 5 * * *'); J.type('#cron-cmd', './mcserver backup');
J.q('#cron-form').dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
await J.sleep(800);
// Edit an existing job, then think better of it.
const edit = document.querySelector('#cron-list [data-action], #cron-list button');
if (edit) { edit.click(); await J.sleep(300); }
J.click('[data-action="cancelCronEdit"]'); await J.sleep(200);
return 1;
"""

GAME_CONFIG = r"""
// The config tabs: LinuxGSM settings form, the game's own file, and the raw editor.
for (const t of ['lgsm', 'game', 'raw']) { J.click('[data-tab="' + t + '"]'); await J.sleep(600); }
J.type('#game-cfg', (J.q('#game-cfg') || {}).value + '\n// jscov');
J.click('[data-action="saveGameCfg"]'); await J.sleep(600);
J.type('#cfg-raw', (J.q('#cfg-raw') || {}).value + '\n# jscov');
J.click('[data-action="saveRaw"]'); await J.sleep(600);
J.click('[data-tab="lgsm"]'); await J.sleep(300);
const f = document.getElementById('cfg-form');
if (f) { f.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true})); await J.sleep(800); }
// Backups of this server: schedule, now, and a delete (Cancel, then OK).
J.type('#bk-interval', 'daily'); await J.sleep(300);
J.type('#bk-keep', '3'); await J.sleep(300);
J.click('[data-action="backupNow"]'); await J.sleep(1200); J.settleDialogs(false, PW);
J.click('[data-action="deleteBk"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.click('[data-action="deleteBk"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(800);
// Mods: refresh the list, install one, remove one.
J.click('[data-action="loadMods"]'); await J.sleep(1500);
J.click('[data-action="modAction"]', 0); await J.sleep(1200); J.settleDialogs(true, PW); await J.sleep(600);
J.click('[data-action="modAction"]', 1); await J.sleep(1200); J.settleDialogs(true, PW); await J.sleep(600);
// Alerts: a test message, and save.
J.click('[data-action="testAlert"]'); await J.sleep(800);
J.click('[data-action="saveAlerts"]'); await J.sleep(800);
return 1;
"""


RENAME_OPEN = r"""
const btn = await J.waitFor('#file-list [data-path="%s"] [data-action="rename"]', 5000);
if (!btn) return {err: 'no Rename control on %s'};
btn.click(); await J.sleep(200);
const f = J.q('#file-list .fb-rename input');
if (!f) return {err: 'Rename opened no field'};
return {value: f.value, sel: [f.selectionStart, f.selectionEnd], focused: document.activeElement === f};
"""
RENAME_STATE = r"""
const f = J.q('#file-list .fb-rename input'), e = J.q('#file-list .fb-rename-err');
return {open: !!f, value: f ? f.value : null, err: e && e.style.display !== 'none' ? e.textContent : '',
        rows: Array.from(document.querySelectorAll('#file-list [data-path]')).map(r => r.dataset.path)};
"""
# The open field at a phone's width: no sideways scroll, a field wide enough to type in, and every
# part of the row (the error line too) inside the row.
RENAME_FIT = r"""
const row = J.q('#file-list .fb-renaming'), f = J.q('#file-list .fb-rename input');
if (!row || !f) return {err: 'no field open'};
const R = row.getBoundingClientRect(), parts = Array.from(row.querySelectorAll('.fb-rename input, .fb-rename button, .fb-rename-err'));
const out = parts.filter(p => p.offsetParent !== null).map(p => p.getBoundingClientRect())
  .filter(r => r.left < R.left - 0.5 || r.right > R.right + 0.5);
const w = el => el ? Math.round(el.getBoundingClientRect().width) : null;
return {vw: window.innerWidth, scroll: document.documentElement.scrollWidth, field: f.getBoundingClientRect().width,
        outside: out.length, row: w(row), box: w(row.querySelector('.fb-rename')),
        buttons: Array.from(row.querySelectorAll('.fb-rename button')).map(b => [w(b), Math.round(b.getBoundingClientRect().height)])};
"""


def _press(d, key, code, vk):
    """One real key press (keydown and keyup) into whatever has focus."""
    down = {"type": "keyDown", "key": key, "code": code, "windowsVirtualKeyCode": vk}
    d.cdp.call("Input.dispatchKeyEvent", down)
    d.cdp.call("Input.dispatchKeyEvent", dict(down, type="keyUp"))
    d.settle(quiet=0.3, limit=4.0)


def _expect(cond, what, got):
    """Raise, naming what the rename did not do, so the walk reports this flow as broken."""
    if not cond:
        raise RuntimeError("rename: %s (got %r)" % (what, got))


def files_rename(d):
    """Rename in the file browser with real keys: open, Escape, a taken name, then Enter.

    Then at 375px wide: the field fits the row, and a refusal's reason wraps inside it. A step that
    does not do what it should raises, and the walk reports this flow as broken.
    """
    d.goto("/server/1/files")
    got = d.run(RENAME_OPEN % ("notes.txt", "notes.txt")) or {}
    _expect(got.get("sel") == [0, 5] and got.get("focused"), "the stem is selected, focused", got)
    _press(d, "Escape", "Escape", 27)
    got = d.run(RENAME_STATE) or {}
    _expect(got.get("open") is False and "notes.txt" in got.get("rows", []), "Escape closes", got)
    d.run(RENAME_OPEN % ("notes.txt", "notes.txt"))
    d.run("J.q('#file-list .fb-rename input').select(); return 1;")
    d.keys("server.cfg\n")
    got = d.run(RENAME_STATE) or {}
    _expect(got.get("open") and "already exists" in got.get("err", ""), "a taken name is shown", got)
    _press(d, "Escape", "Escape", 27)
    d.run(RENAME_OPEN % ("notes.txt", "notes.txt"))
    d.keys("renamed\n")                     # typed over the selected stem: renamed.txt
    d.wait(1.0)
    got = d.run(RENAME_STATE) or {}
    _expect(not got.get("open") and "renamed.txt" in got.get("rows", [])
            and "notes.txt" not in got.get("rows", []), "Enter renames, the list refreshes", got)
    d.cdp.call("Emulation.setDeviceMetricsOverride",
               {"width": 375, "height": 812, "deviceScaleFactor": 2, "mobile": True})
    try:
        d.goto("/server/1/files")
        d.run(RENAME_OPEN % ("server.cfg", "server.cfg"))
        d.run("J.q('#file-list .fb-rename input').select(); return 1;")
        d.keys("a/b\n")
        fit = d.run(RENAME_FIT) or {}
        _expect(fit.get("vw") == 375 and fit.get("scroll", 999) <= 375 and fit.get("outside") == 0
                and fit.get("field", 0) >= 120, "at 375px the field and its error fit the row", fit)
        _press(d, "Escape", "Escape", 27)
    finally:
        d.cdp.call("Emulation.clearDeviceMetricsOverride")
        d.goto("/server/1/files")


def files_drop(d):
    """Drop files and a folder, from disk, onto the file browser; the upload asks and is let go."""
    src = os.path.join(d.tree, "jscov-drop")
    os.makedirs(os.path.join(src, "maps", "custom"), exist_ok=True)
    for rel, text in (("maps/custom/a.bsp", "x"), ("maps/readme.txt", "maps"),
                      ("notes.txt", "clash")):
        with open(os.path.join(src, rel), "w", encoding="utf-8") as fh:
            fh.write(text)
    d.drop_files("#file-browser", [os.path.join(src, "maps")])
    d.run(OK + "await J.sleep(2500);" + OK)
    d.drop_files("#file-browser", [os.path.join(src, "notes.txt")])
    d.run("await J.sleep(1200);" + OK + "await J.sleep(1200);")


# ── a host: its tabs, security, backups ────────────────────────────────────────────────────────
HOST_TABS = r"""
// Each section tab in turn, and back — the cards of each load when their tab is shown.
for (const t of ['controls', 'maintenance', 'security', 'overview']) {
  J.click('[data-mtab-btn="' + t + '"]'); await J.sleep(1500);
}
return 1;
"""

HOST_SECURITY = r"""
J.click('[data-mtab-btn="security"]'); await J.sleep(1200);
for (let i = 0; i < 3; i++) { J.click('[data-action="loadSecurityLog"]', i); await J.sleep(800); }
J.click('[data-action="loadSecurityBans"]'); await J.sleep(800);
J.click('[data-action="loadSecurityTopIps"]'); await J.sleep(1200);
// Block the top offender (Cancel, then OK), and unblock it again.
const blk = () => document.querySelector('[data-action="blockOffender"]');
if (blk()) { blk().click(); await J.sleep(300); J.settleDialogs(false, PW); }
if (blk()) { blk().click(); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1200); }
J.click('[data-action="unblockOffender"]'); await J.sleep(1200);
// Unban from a jail.
const unban = document.querySelector('#sec-bans button, [data-action="unbanIp"]');
if (unban) { unban.click(); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1000); }
// The threshold, auto-block, and the whitelist: a bad address, a good one, then remove it.
J.type('#sec-threshold', '7'); J.click('[data-action="saveThreshold"]'); await J.sleep(800);
J.click('[data-action="toggleAutoblock"]'); await J.sleep(800);
J.click('[data-action="toggleAutoblock"]'); await J.sleep(800);
for (const ip of ['not-an-ip', '198.51.100.44']) {
  J.type('#sec-wl-input', ip); J.click('[data-action="addWhitelist"]'); await J.sleep(900);
}
const wl = document.querySelector('[data-action="removeWhitelist"]');
if (wl) { wl.click(); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(900); }
return 1;
"""

HOST_CONTROLS = r"""
J.click('[data-mtab-btn="controls"]'); await J.sleep(1200);
// SSH: the port, with and without a bind address; each asks, and is cancelled then confirmed.
J.type('#ssh-port-input', '2222'); J.type('#ssh-bind-input', '');
J.click('[data-action="changeSshPort"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.type('#ssh-bind-input', '192.0.2.10');
J.click('[data-action="changeSshPort"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1200);
for (let i = 0; i < 3; i++) {
  J.click('[data-action="sshMode"]', i); await J.sleep(300); J.settleDialogs(false, PW);
}
// The panel's own binding (the panel host only): each choice of the select, then apply.
const sel = J.q('#panel-bind-select');
if (sel) {
  for (const o of Array.from(sel.options)) { J.type('#panel-bind-select', o.value); await J.sleep(150); }
  J.type('#panel-bind-custom', '127.0.0.1'); J.type('#panel-port-input', '5099');
  J.click('[data-action="changePanelBinding"]'); await J.sleep(300); J.settleDialogs(false, PW);
}
J.click('[data-action="closePanelPort"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1000);
J.click('[data-action="tsSshDisable"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(800);
// Ubuntu Pro: a token that is not one, then the services.
J.type('#upro-token', 'not-a-real-pro-token'); J.click('[data-action="_uproAttach"]'); await J.sleep(1200);
J.click('[data-action="_uproService"]'); await J.sleep(1200);
return 1;
"""

HOST_MAINTENANCE = r"""
J.click('[data-mtab-btn="maintenance"]'); await J.sleep(1200);
J.click('[data-action="checkUpdates"]'); await J.sleep(1500);
J.click('[data-action="runUpdates"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.click('[data-action="enableAutoUpdates"]'); await J.sleep(1200);
for (const a of ['runDiagnostics', 'checkDbHealth', 'optimizeDb', 'genDebugReport']) {
  J.click('[data-action="' + a + '"]'); await J.sleep(1500); J.settleDialogs(true, PW); await J.sleep(600);
}
J.click('[data-action="repairPanel"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.click('[data-action="repairDb"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.click('[data-action="checkPanelUpdate"]'); await J.sleep(1500);
return 1;
"""

BACKUPS = r"""
J.click('[data-mtab-btn="maintenance"]'); await J.sleep(1500);
// The panel's own backups: make one, then its settings, one field at a time.
J.click('[data-action="createBackup"]'); await J.sleep(2000);
J.type('#bk-keep', '9'); await J.sleep(500);
J.click('#bk-enabled'); await J.sleep(500); J.click('#bk-enabled'); await J.sleep(500);
// Encryption: a passphrase too short, a good one, then off again (it asks).
for (const p of ['short', 'a long enough passphrase']) {
  J.type('#bk-pass', p); J.click('[data-action="saveBackupPassphrase"]'); await J.sleep(1000);
}
J.click('[data-action="clearBackupPassphrase"]'); await J.sleep(300); J.settleDialogs(false, PW);
// Restore the newest (Cancel), then delete it (Cancel, then OK).
J.click('#bk-tbody [data-action="restoreBackup"]'); await J.sleep(400); J.settleDialogs(false, PW); await J.sleep(300);
J.settleDialogs(false, PW);
J.click('#bk-tbody [data-action="deleteBackup"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.click('#bk-tbody [data-action="deleteBackup"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1200);
// Game-file backups: a full run (it asks who is online), one server's, schedules, a delete.
J.click('#fb-auto-enabled'); await J.sleep(400); J.click('#fb-auto-enabled'); await J.sleep(400);
J.type('#fb-interval', 'weekly'); J.type('#fb-keep', '5'); await J.sleep(400);
// A full run asks who is online first: cancel it, then "when they leave", then "now".
for (const pick of ['#fbd-cancel', '#fbd-wait', '#fbd-now']) {
  J.click('[data-action="runFullBackup"]'); await J.sleep(1500);
  if (!J.click(pick)) J.settleDialogs(pick !== '#fbd-cancel', PW);
  await J.sleep(1200);
}
J.click('[data-action="backupOneGame"]'); await J.sleep(1200); J.settleDialogs(false, PW);
J.click('[data-action="backupOneGame"]'); await J.sleep(1200); J.settleDialogs(true, PW); await J.sleep(1500);
J.type('#gsi-1', 'weekly'); await J.sleep(600);
J.type('#gsk-1', '4'); await J.sleep(600);
J.click('[data-action="deleteGameBackup"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.click('[data-action="deleteGameBackup"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1200);
// Existing LinuxGSM installs on the host: scan, tick, import.
J.click('[data-action="scanExisting"]'); await J.sleep(2500);
const all = document.querySelector('[data-action="discToggleAll"]');
if (all) { all.checked = true; all.dispatchEvent(new Event('change', {bubbles: true})); }
J.click('[data-action="importExisting"]'); await J.sleep(2000); J.settleDialogs(true, PW); await J.sleep(1500);
return 1;
"""

# ── users, groups, settings, account, logs ────────────────────────────────────────────────────
USERS = r"""
// Edit each OTHER user in the shared modal (never the signed-in account: resetting its password
// would sign the rest of the walk out); reset one's password, which is shown once to copy.
const nameOf = b => { const s = b.closest('tr') && b.closest('tr').querySelector('strong');
                      return s ? s.textContent.trim() : ''; };
const others = Array.from(document.querySelectorAll('[data-action="openEditUser"]'))
  .filter(b => nameOf(b) !== ME);
for (let i = 0; i < others.length; i++) {
  others[i].click(); await J.sleep(500);
  J.type('#eu-display', 'Edited ' + i);
  const reset = J.q('#eu-reset-password'); if (reset && i === 0) { reset.checked = true; }
  const f = J.q('#edit-user-form');
  if (f) { f.requestSubmit(); await J.sleep(1200); }
  J.settleDialogs(false, PW);
}
J.click('[data-action="copyCredential"]'); await J.sleep(300);
// Add a user, and invite one.
const add = document.querySelector('form[action$="/users/add"]');
if (add) {
  J.type('form[action$="/users/add"] [name="username"]', 'jscov' + Date.now() % 100000);
  J.type('form[action$="/users/add"] [name="display_name"]', 'New User');
  add.requestSubmit(); await J.sleep(1500);
}
const inv = document.querySelector('form[action$="/users/invite"]');
if (inv) { J.type('#inv-note', 'for a friend'); inv.requestSubmit(); await J.sleep(1500); }
J.click('[data-action="copyCredential"]'); await J.sleep(300);
return 1;
"""

GROUPS = r"""
// The role presets in each group's form, then save one.
for (const role of ['moderator', 'admin', 'none', 'moderator']) {
  J.click('[data-role-preset="' + role + '"]'); await J.sleep(100);
}
const f = document.querySelector('form[action$="/groups/2/edit"]');
if (f) { f.requestSubmit(); await J.sleep(1200); }
return 1;
"""

SETTINGS = r"""
J.type('#s-accent-picker', '#224488'); await J.sleep(100);
J.type('#s-accent', '#336699'); await J.sleep(100);
J.type('#s-accent', 'not a colour'); await J.sleep(100);
return 1;
"""

LOGS = r"""
// Filters submit the form (a page load); the pager and a column sort are links.
J.type('#logs-q', 'login'); J.type('#filter-status', 'fail');
const f = J.q('#logs-q') && J.q('#logs-q').form;
if (f) f.requestSubmit();
return 1;
"""


def logs_pages(d):
    """Filter the audit log, sort it both ways, and open its second page."""
    d.run(LOGS)
    for q in ("?sort=action&dir=asc", "?sort=user&dir=desc&status=ok", "?page=2"):
        d.goto("/logs" + q)


def account_second_session(d):
    """Sign in once more from outside the browser, so the sessions list has one to revoke."""
    d.second_session()
    d.goto("/account")
    d.run("const b = Array.from(document.querySelectorAll('#sessions-list button, "
          "[id*=session] button')).find(x => /revoke/i.test(x.textContent));"
          "if (b) { b.click(); await J.sleep(1200); } return 1;")


# ── the host terminal ──────────────────────────────────────────────────────────────────────────
def terminal(d):
    """Type into the terminal, resize the window, and leave (which closes the session)."""
    d.run("await J.waitFor('.xterm-helper-textarea', 4000); await J.sleep(800);"
          "const t = J.q('.xterm-helper-textarea'); if (t) t.focus(); return 1;")
    d.keys("echo jscov\n")
    d.wait(1.0)
    d.cdp.call("Emulation.setDeviceMetricsOverride",
               {"width": 900, "height": 600, "deviceScaleFactor": 1, "mobile": False})
    d.wait(0.8)
    d.cdp.call("Emulation.clearDeviceMetricsOverride")
    d.wait(0.8)


# ── a host's firewall ──────────────────────────────────────────────────────────────────────────
FIREWALL = r"""
J.click('[data-action="refreshFirewall"]'); await J.sleep(1200);
// Open a port: none typed, a bad one, then a good one by Enter in the box.
J.click('[data-action="openPort"]'); await J.sleep(200);
J.type('#new-port', '99999'); J.click('[data-action="openPort"]'); await J.sleep(900);
J.type('#new-port', '27020'); J.type('#new-proto', 'udp'); J.type('#new-comment', 'jscov');
J.q('#new-port').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
await J.sleep(1200);
// Restrict one: to a source, and by rate — each on, then off.
J.type('#src-cidr', '198.51.100.0/24'); J.type('#src-port', '27015');
J.click('[data-action="allowFromSource"]'); await J.sleep(900);
J.click('[data-action="removeAllowFromSource"]'); await J.sleep(900);
J.type('#limit-port', '22');
J.click('[data-action="limitPort"]'); await J.sleep(900);
J.click('[data-action="unlimitPort"]'); await J.sleep(900);
// Block an address by Enter, then unblock one; sync a server's ports; remove a rule (OK).
J.type('#block-ip', '198.51.100.99');
J.q('#block-ip').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
await J.sleep(1200);
J.click('[data-action="unblockIp"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(900);
J.click('[data-action="syncPorts"]'); await J.sleep(1200);
J.click('[data-action="deleteGroup"]', 1); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1200);
return 1;
"""

# ── remote hosts, and Tailscale on them ────────────────────────────────────────────────────────
REMOTE_TS = r"""
// The Tailscale check for a host, and whatever its answer offers.
J.click('[data-ts-check]'); await J.waitFor('#ts-ssh, [data-install-ts], [data-action="migrateToTailscale"]', 5000);
await J.sleep(400);
J.click('[data-action="_showTsKeyAdv"]'); await J.sleep(200);
if (J.q('#ts-routes')) J.type('#ts-routes', '10.0.0.0/24');
J.click('[data-action="bootstrapTailscale"]'); await J.sleep(1000);     // no key: refused
if (J.q('#ts-auth-key')) J.type('#ts-auth-key', 'tskey-auth-jscov');
J.click('[data-action="bootstrapTailscale"]'); await J.sleep(1500);
J.click('[data-action="tailscaleUp"]'); await J.sleep(2000);
J.click('[data-install-ts]'); await J.sleep(2000);
J.click('[data-action="migrateToTailscale"]'); await J.sleep(300); J.settleDialogs(false, PW);
J.settleDialogs(false, PW); await J.sleep(300);
return 1;
"""

REMOTES = r"""
// Credentials: each way of signing in, in the add form and in an edit form.
for (const how of ['password', 'tailscale', 'key', 'local']) {
  J.type('#manage-remotes-auth_method', how); await J.sleep(100);
  J.type('#manage-remotes-auth_method-2', how); await J.sleep(100);
}
// Bootstrap a host: open it, run it (the host cannot be reached), read its log.
J.click('[data-ts-bootstrap]'); await J.sleep(800);
J.click('[data-action="runBootstrap"]'); await J.sleep(3000);
J.click('[data-action="toggleBsLog"]'); await J.sleep(200);
J.click('[data-action="dismissBootstrap"]'); await J.sleep(300);
J.settleDialogs(false, PW);
// Remove a host: Cancel.
J.click('.remove-remote-btn'); await J.sleep(300); J.settleDialogs(false, PW);
return 1;
"""


def remotes_tailscale(d):
    """Check Tailscale on a host that runs it, one waiting to be linked, and one without it."""
    for state in ("running", "stopped", "absent"):
        d.world(tailscale=state)
        d.goto("/remotes")
        d.run(REMOTE_TS)
    d.world(tailscale="running")


TAILSCALE_PAGE = r"""
if (J.q('#peer-host')) {
  J.type('#peer-host', '100.101.102.104');
  J.q('#peer-host').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));
  await J.sleep(1200);
  J.type('#peer-host', '192.0.2.250'); J.click('[data-action="checkPeer"]'); await J.sleep(1500);
}
J.click('#ts-install-btn'); await J.sleep(2500);
J.click('#ts-connect-btn'); await J.sleep(2500);
J.click('[data-action="tsCheckAgain"]'); await J.sleep(800);
if (J.q('#tailscale-mount')) { J.type('#tailscale-mount', '/lgsm'); }
J.click('[data-action="enableServe"]'); await J.sleep(1500);
J.click('[data-action="disableServe"]'); await J.sleep(300); J.settleDialogs(true, PW); await J.sleep(1500);
return 1;
"""


def tailscale_states(d):
    """Open the Tailscale page with it running, waiting to be linked, and not installed."""
    for state in ("running", "stopped", "absent"):
        d.world(tailscale=state)
        d.goto("/tailscale?refresh=1")
        d.run(TAILSCALE_PAGE)
    d.world(tailscale="running")
    d.goto("/tailscale?refresh=1")


# ── installing a server ───────────────────────────────────────────────────────────────────────
INSTALL = r"""
// Each host (the game list and the free port follow it), then games, then install one.
const hosts = J.q('#remote-select');
if (hosts) for (const o of Array.from(hosts.options)) { J.type('#remote-select', o.value); await J.sleep(500); }
const games = J.q('#game-type-select');
if (games) {
  for (const g of ['gmod', 'mc', 'cs2', 'rust']) { J.type('#game-type-select', g); await J.sleep(400); }
  J.type('#server-name-input', 'Jscov Install'); J.type('#port-input', '27025');
  const f = J.q('#install-form');
  if (f) { f.requestSubmit(); await J.sleep(3000); }
}
return 1;
"""


# ── before and after the walk: the setup wizard, two-factor sign-in ──────────────────────────
SETUP_TAILSCALE = r"""
await J.waitFor('#ts-box > *', 5000); await J.sleep(500);
for (const id of ['#ts-install', '#ts-up', '#ts-serve']) { if (J.click(id)) await J.sleep(2500); }
J.click('[data-action="tsRefresh"]'); await J.sleep(1000);
return 1;
"""

SETUP_REMOTE = r"""
for (const how of ['password', 'tailscale', 'key']) { J.type('#auth-method', how); await J.sleep(100); }
J.type('#setup-remote-name', 'Wizard VPS'); J.type('#setup-remote-host', '192.0.2.30');
const add = J.q('button[name="action"][value="add"]');
if (add) { add.click(); await J.sleep(2500); }    // the host cannot be reached: said so, same step
return 1;
"""


def setup_wizard(d):
    """Finish the setup wizard, which the seed leaves at its last two pages, as its owner would.

    Every other page redirects to it until it is done, so a wizard that did not finish is recorded
    as not reached — the whole walk would otherwise measure the wizard, page after page.
    """
    # Running last but one: finishing with Tailscale running and named sets up Serve and moves
    # the panel under /lgsm, which is a different walk (and one the reports would have to follow).
    for state in ("absent", "running", "stopped"):
        d.world(tailscale=state)
        d.goto("/setup")
        if not d.js("!!document.getElementById('ts-box')"):
            d.unreached.append(("/setup", "the wizard's Tailscale step did not render"))
            return
        d.run(SETUP_TAILSCALE)
    d.run("J.click('#ts-continue'); await J.sleep(1500); return 1;")
    d.goto("/setup")
    d.run(SETUP_REMOTE)
    d.goto("/setup")
    d.run("const b = J.q('button[name=\"action\"][value=\"skip\"]'); if (b) b.click();"
          "await J.sleep(1500); return 1;")
    d.world(tailscale="running")
    if not d.reached("/"):
        d.unreached.append(("/setup", "the wizard did not finish"))


OTP_NAG = """
J.click('[data-action="dismissOtpNagForever"]'); await J.sleep(300);""" + CANCEL + """
J.click('[data-action="dismissOtpNagForever"]'); await J.sleep(300);""" + OK + """
return 1;
"""


def otp_nag(d):
    """Bring back the two-factor reminder "Not now" hid, then turn it off for good."""
    d.run("try { sessionStorage.removeItem('otpNagHidden'); } catch (e) {} return 1;")
    d.goto("/account")
    d.run(OTP_NAG)


def users(d):
    """Edit, add and invite users: every account but the one the walk is signed in with."""
    d.run("const ME = %s;\n%s" % (json.dumps(d.user), USERS))


def two_factor(d):
    """Turn on two-factor sign-in with a code from the key shown, which ends on the backup codes.

    Last in the walk: the account needs a code to sign in from then on, and the harness signs in
    with the password alone.
    """
    if not d.reached("/account/2fa/enable"):
        return
    key = (d.js("(document.querySelector('code.text-info') || {}).textContent || ''") or "").strip()
    if not key:
        d.unreached.append(("/account/2fa/enable", "no key shown to enrol with"))
        return
    d.run("J.type('input[name=\"password\"]', PW); J.type('input[name=\"totp_code\"]', %s);"
          "J.q('input[name=\"totp_code\"]').form.requestSubmit(); await J.sleep(2000); return 1;"
          % json.dumps(pyotp.TOTP(key).now()))
    d.settle(quiet=0.5, limit=6.0)
    if not d.js("typeof CODES !== 'undefined' && CODES.length > 0"):
        raise RuntimeError("enrolling did not reach the backup codes page (at %s)" % d.path())
    d.run("J.click('[data-action=\"copyCodes\"]'); await J.sleep(300);"
          "J.click('[data-action=\"downloadCodes\"]'); await J.sleep(500); return 1;")


# ── the page lists ─────────────────────────────────────────────────────────────────────────────
FLOWS = {
    "/": [("palette", js(PALETTE)), ("filters", js(DASH_FILTERS)), ("bulk", js(DASH_BULK)),
          ("tags", js(DASH_TAGS)), ("layout", js(DASH_LAYOUT)), ("drag", dash_drag),
          ("hide-show", js(DASH_HIDE_SHOW))],
    "/server/1": [("console", js(CONSOLE)), ("players", js(PLAYERS)),
                  ("actions", js(SERVER_ACTIONS))],
    "/server/4": [("console", js(CONSOLE)), ("players", js(PLAYERS))],
    "/server/1/files": [("files", js(FILES)), ("drop", files_drop), ("cron", js(CRON)),
                        ("config", js(GAME_CONFIG)), ("rename", files_rename)],
    "/server-management": [("tabs", js(HOST_TABS)), ("security", js(HOST_SECURITY)),
                           ("controls", js(HOST_CONTROLS)), ("maintenance", js(HOST_MAINTENANCE)),
                           ("backups", js(BACKUPS))],
    "/remote/2/manage": [("tabs", js(HOST_TABS)), ("security", js(HOST_SECURITY)),
                         ("controls", js(HOST_CONTROLS))],
    "/remote/2/firewall": [("firewall", js(FIREWALL))],
    "/remote/3/firewall": [("firewall", js(FIREWALL))],
    "/remotes": [("remotes", js(REMOTES)), ("tailscale", remotes_tailscale)],
    "/tailscale": [("states", tailscale_states)],
    "/servers/install": [("install", js(INSTALL))],
    "/users": [("users", users)],
    "/groups": [("groups", js(GROUPS))],
    "/settings": [("settings", js(SETTINGS))],
    "/logs": [("logs", logs_pages)],
    "/account": [("sessions", account_second_session), ("otp-nag", otp_nag)],
    "/terminal/1": [("terminal", terminal)],
    "/terminal/2": [("terminal", terminal)],
}
