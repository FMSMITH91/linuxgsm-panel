"""Part 90 of the unit suite: the thirteenth review's page and script fixes (builder C).

Held here, each against the code path the finding named:

* the remote Firewall page's Refresh: a reply that is not a reading (a 500 from the panel's catch-all,
  a 404/403 denial) is not painted as "UFW is not installed", "Inactive" and empty lists.
* every JSON error reply carries `error` as well as `message`, so a page's read that checks `error`
  (public SSH's mode label) does not paint one as a reading either.
* the status card's key icon only for a changed host key, not for a read cut off part-way.
* a live language switch past one element with unparseable data-i18n-vars.
* the OS-updates card's count coerced to a number at the innerHTML sink.
* a dropped folder whose listing or files cannot all be read: what was listed is kept, and the skip
  is said.

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. Scripts in node on this part's own fixtures.
"""
import json as _json90
import os

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part87 import _DOM87
from unit.part12 import (_P9_TRIPPED, _p9)
from panel.security import auth as _auth90

_TRIP90_START = len(_P9_TRIPPED)


def _read90(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _node90(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _cut_or90(src, head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Error replies carry `error`, and the Firewall page's Refresh does not paint them as a reading
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The panel's catch-all answered a raise inside remote_ufw_status as {success:false, message}: no
# `unreachable`, no `installed`, no `groups`. Refresh then said "UFW is not installed on this
# remote.", badge "Inactive", "No open ports yet." and "0 blocked" about a firewall nobody read.
# app.py's handler lives inside create_app, which this suite must not build (part12's note): smoke
# part04 drives its 500 and 404 replies. A permission denial is auth._deny's, driven here.
_rep90 = {}
with _p9.test_request_context("/api/remote/1/firewall", headers={"Accept": "application/json"}):
    _d90 = _auth90._deny("unit p90 denied", 403)
    _rep90["403"] = (_d90.status_code, _d90.get_json(silent=True) or {})
check("error replies: a permission denial carries `error` beside `message`, the same sentence (a "
      "read that checks `error` painted it as a reading)",
      _rep90["403"] == (403, {"success": False, "message": "unit p90 denied", "error": "unit p90 denied"}),
      repr(_rep90))
# The catch-all's 500 reply as it was before `error` (Refresh must not need that field to tell).
_rep90["500"] = (500, {"success": False, "message": "MSG-500"})

_FWJS90 = _read90("static", "js", "remote_firewall.js")
_name90 = "firewall refresh: a reply that is not a reading"
_out90 = _node90(_name90, _DOM87 + _SETTLE47 + (
    "global.remoteId = 7; let unlisted = null, toasts = [];\n"
    "global.toast = (m, k) => { toasts.push([m, k]); };\n"
    "global._fwUnlisted = m => { unlisted = m; };\n"
    "let painted = 0; global._fwRenderRules = () => { painted++; }; global._fwRenderBlocks = () => { painted++; };\n"
    + "".join(_cut_or90(_FWJS90, h) + "\n" for h in (
        "function refreshFirewall(", "function _r23c_fwNotRead(", "function _fwUnreadWhy(",
        "function _fwHostSaid(", "function _fwStatusNote("))
    + "(async () => {\n"
    "  const card = document.getElementById('ufw-status-note'), out = {};\n"
    "  const badge = document.getElementById('ufw-badge');\n"
    "  const steps = [['500', " + _json90.dumps(_rep90.get("500", (0, {}))[1]) + "],\n"
    "    ['bare', {success: false}], ['null', null],\n"
    "    ['cut', {unreachable: true, code: 'command_started', message: 'MSG-CUT'}],\n"
    "    ['key', {unreachable: true, code: 'host_key_mismatch', message: 'MSG-KEY'}],\n"
    "    ['good', {installed: true, enabled: true, groups: []}]];\n"
    "  for (const [k, d] of steps) {\n"
    "    answer(d); unlisted = null; toasts = []; painted = 0; badge.textContent = 'before';\n"
    "    refreshFirewall(); await settle();\n"
    "    const p = card.children[0], i = p ? p.children[0] : null;\n"
    "    out[k] = {badge: badge.textContent, note: card.textContent.trim(), icon: i ? i.className : null,\n"
    "              unlisted: unlisted, toasts: toasts.length, painted: painted};\n"
    "  }\n"
    "  console.log(JSON.stringify(out));\n"
    "})();\n"))
if _out90 is not None:
    _said90 = "MSG-500"
    _fallback90 = "The firewall could not be read, so its rules can't be shown."
    _o90 = _out90
    check("firewall refresh: the catch-all's 500 reply reads badge Unknown, its own sentence in the "
          "status card and both lists, and a toast — not \"UFW is not installed\", Inactive, empty lists",
          _o90.get("500") == {"badge": "Unknown", "note": _said90, "icon": "bi bi-exclamation-triangle",
                              "unlisted": _said90, "toasts": 1, "painted": 0}, repr(_o90))
    check("firewall refresh: ...a failure with no sentence, and a null body, say the page's own",
          all(_o90.get(k) == {"badge": "Unknown", "note": _fallback90, "icon": "bi bi-exclamation-triangle",
                              "unlisted": _fallback90, "toasts": 1, "painted": 0} for k in ("bare", "null")),
          repr(_o90))
    check("firewall refresh: the key icon is for a changed host key only — a read cut off part-way "
          "gets the warning icon; a good read still paints the lists",
          (_o90.get("key") or {}).get("icon") == "bi bi-key"
          and (_o90.get("cut") or {}).get("icon") == "bi bi-exclamation-triangle"
          and (_o90.get("cut") or {}).get("note") == "MSG-CUT"
          and (_o90.get("good") or {}).get("painted") == 2 and (_o90.get("good") or {}).get("badge") == "Active",
          repr(_o90))

# ...and public SSH's mode label, which checks `error`, reads a real denial reply as unknown.
_RMH90 = _read90("static", "js", "remote_manage_host.js")
_name90 = "public SSH label: an error reply"
_out90 = _node90(_name90, (
    "var SSH_LABELS = {allow: 'a', limit: 'l', off: 'o'};\n"
    + _cut_or90(_RMH90, "function sshModeLabel(") + "\n"
    "console.log(JSON.stringify([sshModeLabel(" + _json90.dumps(_rep90["403"][1])
    + "), sshModeLabel({installed: true, active: true, mode: 'allow'})]));\n"))
if _out90 is not None:
    check("public SSH label: a real denial reply reads \"unknown\" (it read \"not filtered — UFW is "
          "inactive\"); a reading still names its mode",
          _out90 == ["unknown", "a"], repr(_out90))


# (2. The page as loaded drew the key icon for a changed host key only. The standalone Firewall page is a
# redirect to the host page's Network tab now (ui-tidy-2), whose cards are painted by the refresh alone:
# its key-versus-warning icon is held in section 1 above.)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A live language switch past one element with unparseable data-i18n-vars
# ════════════════════════════════════════════════════════════════════════════════════════════════
_I18N90 = _read90("static", "js", "i18n.js")
_set90 = _I18N90[_I18N90.find("window.setLang = function"):]
_set90 = _cut_or90(_set90, "window.setLang = function") if _set90 else "/* MISSING setLang */"
_name90 = "live language switch: one bad data-i18n-vars"
_out90 = _node90(_name90, (
    "global.window = global;\n"
    "function mk(a){ return {a: a, textContent: 'old', getAttribute(k){ return k in this.a ? this.a[k] : null; },\n"
    "  setAttribute(){} }; }\n"
    "const els = [mk({'data-i18n-text': 'K {n}', 'data-i18n-vars': '{bad'}),\n"
    "             mk({'data-i18n-text': 'K {n}', 'data-i18n-vars': '{\"n\":2}'}), mk({'data-i18n-text': 'Plain'})];\n"
    "global.document = {documentElement: {}, body: {},\n"
    "  querySelectorAll: s => s === '[data-i18n-text]' ? els : []};\n"
    "function startObserver(){} function run(){}\n"
    "window.t = k => 'T:' + k; window.tf = (k, v) => 'T:' + k.replace('{n}', v.n);\n"
    + _set90 + "\n"
    "window.setLang('fr', {});\n"
    "console.log(JSON.stringify(els.map(e => e.textContent)));\n"))
if _out90 is not None:
    check("live language switch: an element with unparseable data-i18n-vars keeps its text, and every "
          "later one is still re-rendered (one shared try stopped them all)",
          _out90 == ["old", "T:K 2", "T:Plain"], repr(_out90))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The OS-updates card's count is a number at the sink
# ════════════════════════════════════════════════════════════════════════════════════════════════
_RM90 = _read90("static", "js", "remote_manage.js")
_name90 = "OS updates card: the count at the innerHTML sink"
_out90 = _node90(_name90, _DOM87 + (
    "function isSecurityPkg(){ return false; } global.setInstallUpdatesState = () => {};\n"
    + _cut_or90(_RM90, "function renderUpdates(") + "\n"
    + _cut_or90(_RM90, "function renderDeferred(") + "\n"
    "const out = [];\n"
    "for (const c of ['<b>x</b>', '2']) { renderUpdates({count: c, packages: []}, '');\n"
    "  out.push(document.getElementById('update-info').innerHTML); }\n"
    "console.log(JSON.stringify(out));\n"))
if _out90 is not None:
    check("OS updates card: a count that is not a number puts no markup in the card, and \"2\" still "
          "reads as 2 updates",
          isinstance(_out90, list) and len(_out90) == 2 and "<b>" not in _out90[0]
          and "System is up to date." in _out90[0] and "2 <span>updates available" in _out90[1],
          repr(_out90))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. A dropped folder that cannot all be read
# ════════════════════════════════════════════════════════════════════════════════════════════════
# readEntries' error callback resolved the folder with none of its children, so a listing that
# failed after its first batch dropped that batch too; and nothing said what was skipped.
_SF90 = _read90("static", "js", "server_files.js")
_drop90 = "card.addEventListener('drop', function(ev){"
_name90 = "file drop: an unreadable part of a dropped folder"
_out90 = _node90(_name90, _SETTLE47 + (
    "global.window = global; let toasts = [], uploaded = null, curDir = 'here';\n"
    "global.toast = (m, k) => toasts.push([m, k]);\n"
    "global.tfn = (n, one, many) => (n === 1 ? one : many).replace('{n}', n);\n"
    "global._uploadStatus = () => {}; global.uploadFiles = () => {};\n"
    "global.uploadEntries = (list, base) => { uploaded = [list.map(e => e.dir + '/' + e.file.name), base]; };\n"
    "const file = (name, ok) => ({isFile: true, name, file: (y, n) => ok ? y({name}) : n(new Error('x'))});\n"
    "const dir = (name, batches) => ({isDirectory: true, name, createReader: () => {\n"
    "  let i = 0; return {readEntries: (y, n) => { const b = batches[i++];\n"
    "    if (b === 'ERR') n(new Error('x')); else y(b || []); }}; }});\n"
    + _cut_or90(_SF90, "function _walkEntry(") + "\n"
    + _cut_or90(_SF90, "function _dropRoots(") + "\n"
    "let handler = null; const card = {addEventListener: (k, f) => { if (k === 'drop') handler = f; }};\n"
    + (_cut47(_SF90, _drop90) + ");" if _drop90 in _SF90 else "/* MISSING drop handler */") + "\n"
    "(async () => {\n"
    "  const root = dir('addon', [[file('a.txt', true), file('locked.bin', false)], 'ERR']);\n"
    "  handler({dataTransfer: {items: [{kind: 'file', webkitGetAsEntry: () => root}]}});\n"
    "  await settle(); await settle();\n"
    "  console.log(JSON.stringify({uploaded, toasts}));\n"
    "})();\n"))
if _out90 is not None:
    check("file drop: a folder whose second listing batch fails still uploads what the first listed, "
          "and a toast says 2 items (the locked file, the failed batch) were not read",
          _out90.get("uploaded") == [["addon/a.txt"], "here"]
          and _out90.get("toasts") == [["2 dropped items could not be read and are not uploaded.", "warning"]],
          repr(_out90))

check("part90: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP90_START, repr(_P9_TRIPPED[_TRIP90_START:][:6]))
