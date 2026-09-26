"""Page flows: what tools/js_coverage/walk.py does on a page after pressing every control once.

Each is the body of an async function run in the page, with the helpers as `J` (helpers.js). They
do what one press of each control cannot: type into the console and send it, walk into a folder and
open a file, drop files onto the file browser, drive the command palette from the keyboard. Every
step goes through the page's own handlers — a click, a key, a drop — never a panel function.

A flow that no longer finds its element does nothing and says nothing; the coverage it produced
drops, which is where a renamed element shows up.
"""

PALETTE = r"""
J.key(document, 'k', {ctrlKey: true}); await J.sleep(400);
const inp = document.getElementById('cmdk-input');
if (!inp) return 0;
for (const q of ['sur', 'fire', 'restart', 'zzzz-nothing', '']) {
  J.setValue(inp, q); inp.dispatchEvent(new Event('input', {bubbles: true})); await J.sleep(150);
  J.key(document, 'ArrowDown'); J.key(document, 'ArrowDown'); J.key(document, 'ArrowUp');
}
J.setValue(inp, 'restart'); inp.dispatchEvent(new Event('input', {bubbles: true})); await J.sleep(200);
const li = document.querySelector('.cmdk-item');
if (li) li.dispatchEvent(new MouseEvent('mousemove', {bubbles: true}));
J.key(document, 'Enter'); await J.sleep(300);
J.settleDialogs(false);
J.key(document, 'k', {ctrlKey: true}); await J.sleep(200);
J.setValue(inp, 'start'); inp.dispatchEvent(new Event('input', {bubbles: true})); await J.sleep(200);
const row = Array.from(document.querySelectorAll('.cmdk-item')).find(r => r.dataset.act === 'start');
if (row) row.click();
await J.sleep(300);
J.key(document, 'k', {ctrlKey: true}); await J.sleep(200); J.key(document, 'Escape');
J.key(document, 'k', {ctrlKey: true}); await J.sleep(200);
const box = document.getElementById('cmdk'); if (box) box.click();
return 1;
"""

DASHBOARD = r"""
await J.typeInto('main input[type="search"], main input[type="text"]', 'sur');
await J.typeInto('main input[type="search"], main input[type="text"]', 'zzzz');
return 1;
"""

CONSOLE = r"""
const out = document.getElementById('console-output');
const inp = document.getElementById('command-input');
const form = document.getElementById('command-form');
if (inp && form) {
  for (const c of ['status', 'say hello']) {
    J.setValue(inp, c); inp.dispatchEvent(new Event('input', {bubbles: true}));
    form.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
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
// The poller pushes new lines every few seconds: stay long enough to receive some.
await J.sleep(6000);
const say = document.getElementById('pl-say');
if (say) {
  J.setValue(say, 'hello everyone');
  say.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true, cancelable: true}));
  await J.sleep(400);
}
return 1;
"""

FILES = r"""
const list = document.getElementById('file-list');
const pick = (type) => list && Array.from(list.querySelectorAll('[data-path]')).find(r => r.dataset.type === type);
let d = pick('dir'); if (d) { d.click(); await J.sleep(800); }
const crumb = document.querySelector('#breadcrumb [data-nav]'); if (crumb) { crumb.click(); await J.sleep(800); }
let f = pick('file'); if (f) { f.click(); await J.sleep(800); }
const ed = document.getElementById('editor');
if (ed) { J.setValue(ed, ed.value + '\n# edited\n'); ed.dispatchEvent(new Event('input', {bubbles: true})); }
const fileSel = Array.from(document.querySelectorAll('[data-action="saveFile"]'))[0];
if (fileSel) { fileSel.click(); await J.sleep(600); }
const up = document.getElementById('upload-input');
if (up) {
  const dt = new DataTransfer();
  // Two that clash with what is there (a file, and a folder of the same name) and one that does not.
  dt.items.add(new File(['hello'], 'notes.txt', {type: 'text/plain', lastModified: Date.now()}));
  dt.items.add(new File(['x'], 'log', {type: 'text/plain', lastModified: Date.now() - 4e10}));
  dt.items.add(new File(['x=1'], 'fresh.cfg', {type: 'text/plain'}));
  up.files = dt.files;
  up.dispatchEvent(new Event('change', {bubbles: true}));
  await J.sleep(1200); J.settleDialogs(true); await J.sleep(1500);
}
const card = document.getElementById('file-browser');
if (card) {
  const dt2 = new DataTransfer();
  dt2.items.add(new File(['y'], 'dropped.txt', {type: 'text/plain'}));
  for (const t of ['dragenter', 'dragover', 'dragleave', 'dragenter', 'dragover', 'drop']) {
    card.dispatchEvent(new DragEvent(t, {bubbles: true, cancelable: true, dataTransfer: dt2}));
  }
  await J.sleep(1500);
}
const sched = document.getElementById('cron-sched'), cmd = document.getElementById('cron-cmd');
if (sched && cmd) {
  for (const s of ['*/15 * * * *', '0 4 * * 1-5', '30 3 1,15 * *', 'bad cron']) {
    J.setValue(sched, s); sched.dispatchEvent(new Event('input', {bubbles: true}));
    await J.sleep(150);
  }
  J.setValue(sched, '0 5 * * *'); sched.dispatchEvent(new Event('input', {bubbles: true}));
  J.setValue(cmd, './mcserver backup'); cmd.dispatchEvent(new Event('input', {bubbles: true}));
  document.getElementById('cron-form').dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
  await J.sleep(800);
}
return 1;
"""

FLOWS = {
    "/": [("palette", PALETTE), ("filters", DASHBOARD)],
    "/server/1": [("console", CONSOLE)],
    "/server/4": [("console", CONSOLE)],
    "/server/1/files": [("files", FILES)],
}
