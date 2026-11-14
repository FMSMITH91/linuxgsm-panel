"""Part 195 of the unit suite: two cards' text, pinned for every state they draw.

Held here:
* remote_manage_backups.js fbSummary, the summary under "Automatic game backups": off (one kept,
  several kept, a blank box), and on for each interval the sentence names (1, 7, 14, 30) and one it
  does not, with no disk reading, an empty one, nothing free, a projection over the free space, over
  half of it and well under it, servers on several hosts with and without a reading, and without
  bkFmtBytes. Each one's markup is pinned whole.
* remote_manage_host.js renderUpdate, the panel's update card: not a git checkout (with the server's
  message and without), a failed check on a checkout, up to date (release and commit, commit only,
  neither), an update one or several commits behind with commit links, plain lines, a repo URL that
  is not one and changelog entries, an update with nothing listed, and no header or no card at all.
  Every element the card writes (status, Update button, the lists, the header, what it remembers)
  is pinned whole.

The pins are the output of the functions before they were split into helpers, so they hold the
split to drawing exactly what the single functions drew.

HOW IT RUNS. The functions are cut from the files and run in node over stand-in elements, with
stand-ins for the translation helpers that mark every sentence they were handed. Nothing else runs.
"""
import json as _json195
import os as _os195

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part47 import _cut47, _node47


def _read195(*parts):
    with open(_os195.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _region195(src, start, end):
    """`src` from `start` up to (not including) `end`, or a comment naming what is missing."""
    i, j = src.find(start), src.find(end)
    return src[i:j] if 0 <= i < j else "/* MISSING %s .. %s */" % (start, end)


def _cut_or195(src, head):
    """_cut47's statement, or a comment naming it, so the program fails BY NAME."""
    return _cut47(src, head) if head in src else "/* MISSING %s */" % head


def _line195(src, head):
    """The one line of `src` that starts at `head`, or a comment naming it."""
    i = src.find(head)
    return src[i:src.index("\n", i)] if i >= 0 else "/* MISSING %s */" % head


# Stand-ins: escaping that shows, translation that marks each sentence «…» with its values put in
# (html values as given, the rest escaped), and elements that record what is written to them.
_PRELUDE195 = (
    "global.window = global; global.MOUNT = '';\n"
    "global.escapeHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')\n"
    "  .replace(/\"/g, '&quot;').replace(/'/g, '&#39;');\n"
    "global.t = s => '«' + s + '»';\n"
    "global.tf = (k, v) => t(k).replace(/\\{(\\w+)\\}/g, (m, n) => v[n]);\n"
    "global.tfHtml = (k, v) => '«' + k.replace(/\\{(\\w+)\\}/g, (m, n) => (v && n in v)\n"
    "  ? ((v[n] && v[n].html !== undefined) ? v[n].html : escapeHtml(v[n])) : m) + '»';\n"
    "const mk = tag => ({tag, _h: '', textContent: '', style: {}, attrs: {}, kids: [],\n"
    "  set innerHTML(v) { this._h = v; if (v === '') this.kids = []; }, get innerHTML() { return this._h; },\n"
    "  appendChild(c) { this.kids.push(c); return c; }, setAttribute(k, v) { this.attrs[k] = v; },\n"
    "  removeAttribute(k) { delete this.attrs[k]; if (k === 'href') delete this.href; }});\n"
    "const ser = n => n.tag === '#text' ? n.textContent : '<' + n.tag\n"
    "  + ['href', 'target', 'rel', 'className'].filter(k => n[k] !== undefined)\n"
    "      .map(k => ' ' + k + '=' + n[k]).join('')\n"
    "  + Object.keys(n.attrs).sort().map(k => ' ' + k + '=' + n.attrs[k]).join('') + '>'\n"
    "  + (n.textContent || '') + n.kids.map(ser).join('') + '</' + n.tag + '>';\n")

_FB_RUN195 = (
    "function fbRun(st) {\n"
    "  const els = {'fb-auto-enabled': {checked: st.on}, 'fb-keep': {value: st.keep},\n"
    "               'fb-interval': {value: st.interval}};\n"
    "  if (!st.noEl) els['fb-summary'] = {innerHTML: 'untouched'};\n"
    "  global.document = {getElementById: id => els[id] || null};\n"
    "  if (st.disk === undefined) delete window._bkDisk; else window._bkDisk = st.disk;\n"
    "  window._bkMultiHost = st.multi;\n"
    "  global.bkFmtBytes = st.noFmt ? undefined : (b => (b / 1e9).toFixed(1) + ' GB');\n"
    "  fbSummary();\n"
    "  return st.noEl ? null : els['fb-summary'].innerHTML;\n"
    "}\n")

_PU_RUN195 = (
    "const PU_IDS = ['pu-status', 'pu-update-btn', 'pu-changes', 'pu-current', 'pu-changes-list', 'pu-notes',\n"
    "                'pu-notes-list', 'pu-notes-more', 'pu-commits'];\n"
    "function puRun(d, drop) {\n"
    "  const els = {};\n"
    "  PU_IDS.forEach(i => { if (!(drop || []).includes(i)) els[i] = mk('div'); });\n"
    "  global.document = {getElementById: id => els[id] || null, createElement: mk,\n"
    "                     createTextNode: s => ({tag: '#text', textContent: s})};\n"
    "  _r20cUpdateShown = 'before';\n"
    "  renderUpdate(d);\n"
    "  const o = {remembered: _r20cUpdateShown === d ? 'this answer' : String(_r20cUpdateShown)};\n"
    "  for (const [i, e] of Object.entries(els)) {\n"
    "    const w = {};\n"
    "    if (e.innerHTML) w.html = e.innerHTML;\n"
    "    if (e.style.display !== undefined) w.display = e.style.display;\n"
    "    if (e.textContent) w.text = e.textContent;\n"
    "    if (e.href !== undefined) w.href = e.href;\n"
    "    if (e.open !== undefined) w.open = e.open;\n"
    "    if (e.kids.length) w.kids = e.kids.map(ser).join('');\n"
    "    if (Object.keys(w).length) o[i] = w;\n"
    "  }\n"
    "  return o;\n"
    "}\n")

_FB_STATES195 = {
    "off, one kept": {"on": False, "keep": "1"},
    "off, three kept": {"on": False, "keep": "3"},
    "off, keep box blank": {"on": False, "keep": ""},
    "daily, no disk reading": {"on": True, "keep": "2", "interval": "1"},
    "weekly, one kept, nothing measured yet": {"on": True, "keep": "1", "interval": "7",
                                               "disk": {"free": 5e9, "est_cycle": 0}},
    "every 2 weeks, more than the free disk": {"on": True, "keep": "4", "interval": "14",
                                               "disk": {"free": 10e9, "est_cycle": 3e9}},
    "monthly, over half the free disk": {"on": True, "keep": "3", "interval": "30",
                                         "disk": {"free": 10e9, "est_cycle": 2e9}},
    "every 3 days, plenty free": {"on": True, "keep": "2", "interval": "3",
                                  "disk": {"free": 100e9, "est_cycle": 1e9}},
    "the recommendation equals keep": {"on": True, "keep": "2", "interval": "7",
                                       "disk": {"free": 5e9, "est_cycle": 1e9}},
    "nothing free read": {"on": True, "keep": "2", "interval": "7", "disk": {"free": 0, "est_cycle": 1e9}},
    "several hosts, measured": {"on": True, "keep": "2", "interval": "7", "multi": True,
                                "disk": {"free": 10e9, "est_cycle": 1e9}},
    "several hosts, nothing measured": {"on": True, "keep": "2", "interval": "7", "multi": True,
                                        "disk": {"free": 10e9, "est_cycle": 0}},
    "interval box blank": {"on": True, "keep": "5", "interval": "", "disk": {"free": 4e9, "est_cycle": 1e9}},
    "no byte formatter": {"on": True, "keep": "2", "interval": "7", "noFmt": True,
                          "disk": {"free": 1500, "est_cycle": 1000}},
    "no summary element": {"on": True, "keep": "2", "interval": "7", "noEl": True},
}

_PU_BASE195 = {"git": True, "current_version": "2026.11.13", "current_sha": "a8d76b0"}
_PU_STATES195 = {
    "not a git checkout, the server's message": [
        {"git": False, "message": "Not a <git> checkout", "current_sha": "a8d76b0"}, []],
    "not a git checkout, no message": [{"git": False}, []],
    "a failed check on a git: false answer reads up to date": [
        {"git": False, "check_failed": True, "current_sha": "a8d76b0"}, []],
    "up to date, release and commit": [dict(_PU_BASE195, update_available=False), []],
    "behind with nothing to install reads up to date": [dict(_PU_BASE195, update_available=False, behind=3), []],
    "up to date, commit only": [{"git": True, "update_available": False, "current_sha": "a8d76b0"}, []],
    "up to date, neither": [{"git": True, "update_available": False}, []],
    "one commit behind, links and notes": [dict(
        _PU_BASE195, update_available=True, behind=1, remote_version="2026.11.14", remote_sha="b1c2d3e",
        repo_url="https://example.com/o/r", target_sha="abcdef1234567", release_notes_more=2,
        changes=["abc1234 Fix the <b>thing</b> (#12) and #3", "not a sha line", "abcdef0 \t",
                 "zzzzzzz not hex"],
        release_notes=[{"category": "Fixed", "title": "A <i>fix</i>.", "body": "What it does."},
                       {"category": "Odd", "title": "No body.", "body": ""}]), []],
    "several behind, a repo URL that is not one": [dict(
        _PU_BASE195, update_available=True, behind=5, repo_url="http://example.com/o/r",
        changes=["abc1234 subject (#9)"]), []],
    "behind with nothing listed": [dict(_PU_BASE195, update_available=True, behind=2), []],
    "no header element": [dict(_PU_BASE195, update_available=False), ["pu-current"]],
    "no card": [dict(_PU_BASE195, update_available=True, behind=1), ["pu-status"]],
}


def _fb_prog195(src):
    """A node program printing fbSummary's markup for every state, from the backups file `src`."""
    return (_PRELUDE195 + _region195(src, "function fbSummary(", "function saveBackupSettings(") + "\n"
            + _FB_RUN195 + "const states = %s;\nconst out = {};\n"
            "for (const [k, st] of Object.entries(states)) out[k] = fbRun(st);\n"
            "console.log(JSON.stringify(out));\n" % _json195.dumps(_FB_STATES195))


def _pu_prog195(src):
    """A node program printing what renderUpdate wrote for every state, from the host file `src`."""
    return (_PRELUDE195 + _cut_or195(src, "function appendSubject(") + "\n"
            + _line195(src, "var _r20cNoteCats") + "\n" + _line195(src, "var _r20cHexSha") + "\n"
            + _cut_or195(src, "function renderReleaseNotes(") + "\n"
            + _region195(src, "var _r20cUpdateShown", "function checkPanelUpdate(") + "\n"
            + _PU_RUN195 + "const states = %s;\nconst out = {};\n"
            "for (const [k, st] of Object.entries(states)) out[k] = puRun(st[0], st[1]);\n"
            "console.log(JSON.stringify(out));\n" % _json195.dumps(_PU_STATES195))


# ── the pins: what the single functions drew ────────────────────────────────────────────────────
_FB_WANT195 = {
    "off, one kept": ("<i class=\"bi bi-info-circle\"></i> «Automatic backups are off — nothing runs on a "
                      "schedule. Use “Back up game servers now” for a one-off; only the latest backup per "
                      "server is kept.»"),
    "off, three kept": ("<i class=\"bi bi-info-circle\"></i> «Automatic backups are off — nothing runs on "
                        "a schedule. Use “Back up game servers now” for a one-off; the 3 most recent "
                        "backups per server are kept.»"),
    "off, keep box blank": ("<i class=\"bi bi-info-circle\"></i> «Automatic backups are off — nothing runs "
                            "on a schedule. Use “Back up game servers now” for a one-off; only the latest "
                            "backup per server is kept.»"),
    "daily, no disk reading": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is backed up "
                               "every day.» «The <strong>2</strong> newest backups are kept per server; "
                               "older ones are deleted automatically.» «(Override per server "
                               "below.)»<br><span class=\"text-warning\"><i class=\"bi "
                               "bi-exclamation-triangle\"></i> Daily full backups of game files eat disk "
                               "fast — keep a low “keep” count unless you have lots of free "
                               "space.</span><br><span class=\"text-secondary\">Run a backup once and this "
                               "will estimate the space each cycle uses and recommend a safe “keep”.</span>"),
    "weekly, one kept, nothing measured yet": ("<i class=\"bi bi-info-circle\"></i> «By default, each "
                                               "server is backed up once a week.» «The newest backup is "
                                               "kept per server; older ones are deleted automatically.» "
                                               "«(Override per server below.)»<br><span "
                                               "class=\"text-secondary\">Run a backup once and this will "
                                               "estimate the space each cycle uses and recommend a safe "
                                               "“keep”.</span>"),
    "every 2 weeks, more than the free disk": ("<i class=\"bi bi-info-circle\"></i> «By default, each "
                                               "server is backed up once every 2 weeks.» «The "
                                               "<strong>4</strong> newest backups are kept per server; "
                                               "older ones are deleted automatically.» «(Override per "
                                               "server below.)» «At the current size that's up to "
                                               "<strong>12.0 GB</strong> of backups (10.0 GB free "
                                               "now).»<br><span class=\"text-danger\"><i class=\"bi "
                                               "bi-exclamation-octagon\"></i> «This needs more than your "
                                               "free disk (10.0 GB) — backups will fail once it fills "
                                               "up.»</span><br><span class=\"text-secondary\"><i "
                                               "class=\"bi bi-lightbulb\"></i> «Recommended: keep ≤ "
                                               "<strong>1</strong> at ~3.0 GB per run (leaves comfortable "
                                               "headroom).»</span>"),
    "monthly, over half the free disk": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is "
                                         "backed up once a month.» «The <strong>3</strong> newest backups "
                                         "are kept per server; older ones are deleted automatically.» "
                                         "«(Override per server below.)» «At the current size that's up to "
                                         "<strong>6.0 GB</strong> of backups (10.0 GB free now).»<br><span "
                                         "class=\"text-warning\"><i class=\"bi "
                                         "bi-exclamation-triangle\"></i> This would use over half your "
                                         "free disk.</span><br><span class=\"text-secondary\"><i "
                                         "class=\"bi bi-lightbulb\"></i> «Recommended: keep ≤ "
                                         "<strong>2</strong> at ~2.0 GB per run (leaves comfortable "
                                         "headroom).»</span>"),
    "every 3 days, plenty free": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is backed "
                                  "up every 3 days.» «The <strong>2</strong> newest backups are kept per "
                                  "server; older ones are deleted automatically.» «(Override per server "
                                  "below.)» «At the current size that's up to <strong>2.0 GB</strong> of "
                                  "backups (100.0 GB free now).»"),
    "the recommendation equals keep": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is "
                                       "backed up once a week.» «The <strong>2</strong> newest backups are "
                                       "kept per server; older ones are deleted automatically.» «(Override "
                                       "per server below.)» «At the current size that's up to <strong>2.0 "
                                       "GB</strong> of backups (5.0 GB free now).»"),
    "nothing free read": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is backed up once "
                          "a week.» «The <strong>2</strong> newest backups are kept per server; older ones "
                          "are deleted automatically.» «(Override per server below.)» «At the current size "
                          "that's up to <strong>2.0 GB</strong> of backups.»"),
    "several hosts, measured": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is backed up "
                                "once a week.» «The <strong>2</strong> newest backups are kept per server; "
                                "older ones are deleted automatically.» «(Override per server "
                                "below.)»<br><span class=\"text-secondary\"><i class=\"bi "
                                "bi-hdd-network\"></i> Disk usage is shown per server below (they're on "
                                "different hosts).</span>"),
    "several hosts, nothing measured": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is "
                                        "backed up once a week.» «The <strong>2</strong> newest backups "
                                        "are kept per server; older ones are deleted automatically.» "
                                        "«(Override per server below.)»<br><span "
                                        "class=\"text-secondary\"><i class=\"bi bi-hdd-network\"></i> Disk "
                                        "usage is shown per server below (they're on different "
                                        "hosts).</span><br><span class=\"text-secondary\">Run a backup "
                                        "once and this will estimate the space each cycle uses and "
                                        "recommend a safe “keep”.</span>"),
    "interval box blank": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is backed up once "
                           "a week.» «The <strong>5</strong> newest backups are kept per server; older "
                           "ones are deleted automatically.» «(Override per server below.)» «At the "
                           "current size that's up to <strong>5.0 GB</strong> of backups (4.0 GB free "
                           "now).»<br><span class=\"text-danger\"><i class=\"bi "
                           "bi-exclamation-octagon\"></i> «This needs more than your free disk (4.0 GB) — "
                           "backups will fail once it fills up.»</span><br><span "
                           "class=\"text-secondary\"><i class=\"bi bi-lightbulb\"></i> «Recommended: keep "
                           "≤ <strong>1</strong> at ~1.0 GB per run (leaves comfortable headroom).»</span>"),
    "no byte formatter": ("<i class=\"bi bi-info-circle\"></i> «By default, each server is backed up once "
                          "a week.» «The <strong>2</strong> newest backups are kept per server; older ones "
                          "are deleted automatically.» «(Override per server below.)» «At the current size "
                          "that's up to <strong>2000 B</strong> of backups (1500 B free now).»<br><span "
                          "class=\"text-danger\"><i class=\"bi bi-exclamation-octagon\"></i> «This needs "
                          "more than your free disk (1500 B) — backups will fail once it fills "
                          "up.»</span><br><span class=\"text-secondary\"><i class=\"bi bi-lightbulb\"></i> "
                          "«Recommended: keep ≤ <strong>1</strong> at ~1000 B per run (leaves comfortable "
                          "headroom).»</span>"),
    "no summary element": None,
}
_PU_WANT195 = {
    "not a git checkout, the server's message": {
        "remembered": "this answer",
        "pu-status": {
            "html": "<i class=\"bi bi-info-circle\"></i> Not a &lt;git&gt; checkout",
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "? · a8d76b0",
        },
    },
    "not a git checkout, no message": {
        "remembered": "this answer",
        "pu-status": {
            "html": "<i class=\"bi bi-info-circle\"></i> Self-update unavailable (not a git checkout).",
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "?",
        },
    },
    "a failed check on a git: false answer reads up to date": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-success\"><i class=\"bi bi-check-circle\"></i> «You're up to date "
                     "(a8d76b0).»</span>"),
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "? · a8d76b0",
        },
    },
    "up to date, release and commit": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-success\"><i class=\"bi bi-check-circle\"></i> «You're up to "
                     "date: release 2026.11.13 (a8d76b0).»</span>"),
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "2026.11.13 · a8d76b0",
        },
    },
    "behind with nothing to install reads up to date": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-success\"><i class=\"bi bi-check-circle\"></i> «You're up to "
                     "date: release 2026.11.13 (a8d76b0).»</span>"),
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "2026.11.13 · a8d76b0",
        },
    },
    "up to date, commit only": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-success\"><i class=\"bi bi-check-circle\"></i> «You're up to date "
                     "(a8d76b0).»</span>"),
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "? · a8d76b0",
        },
    },
    "up to date, neither": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-success\"><i class=\"bi bi-check-circle\"></i> «You&#39;re up to "
                     "date.»</span>"),
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "?",
        },
    },
    "one commit behind, links and notes": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-warning\"><i class=\"bi bi-arrow-up-circle-fill\"></i> «Update "
                     "available: <strong data-no-i18n>2026.11.14 · b1c2d3e</strong> (1 commit "
                     "behind).»</span>"),
        },
        "pu-update-btn": {
            "display": "",
        },
        "pu-changes": {
            "display": "",
        },
        "pu-current": {
            "text": "2026.11.13 · a8d76b0",
        },
        "pu-changes-list": {
            "kids": ("<li><a href=https://example.com/o/r/commit/abc1234 target=_blank rel=noopener "
                     "noreferrer className=font-monospace data-no-i18n=>abc1234</a> Fix the <b>thing</b> "
                     "(<a href=https://example.com/o/r/pull/12 target=_blank rel=noopener noreferrer "
                     "data-no-i18n=>#12</a>) and <a href=https://example.com/o/r/pull/3 target=_blank "
                     "rel=noopener noreferrer data-no-i18n=>#3</a></li><li>not a sha line</li><li><a "
                     "href=https://example.com/o/r/commit/abcdef0 target=_blank rel=noopener noreferrer "
                     "className=font-monospace data-no-i18n=>abcdef0</a> \t</li><li>zzzzzzz not hex</li>"),
        },
        "pu-notes": {
            "display": "",
        },
        "pu-notes-list": {
            "kids": ("<li><details><summary><span className=badge wn-cat>«Fixed»</span> <span "
                     "data-no-i18n=>A <i>fix</i>.</span></summary><p className=wn-body data-no-i18n=>What "
                     "it does.</p></details></li><li><details><summary><span className=badge wn-cat "
                     "data-no-i18n=>Odd</span> <span data-no-i18n=>No body.</span></summary></details></li>"),
        },
        "pu-notes-more": {
            "display": "",
            "text": "«…and 2 more in the full changelog.»",
            "href": "https://example.com/o/r/blob/abcdef1234567/docs/CHANGELOG.md",
        },
        "pu-commits": {
            "open": False,
        },
    },
    "several behind, a repo URL that is not one": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-warning\"><i class=\"bi bi-arrow-up-circle-fill\"></i> «Update "
                     "available: <strong data-no-i18n>?</strong> (5 commits behind).»</span>"),
        },
        "pu-update-btn": {
            "display": "",
        },
        "pu-changes": {
            "display": "",
        },
        "pu-current": {
            "text": "2026.11.13 · a8d76b0",
        },
        "pu-changes-list": {
            "kids": "<li>abc1234 subject (#9)</li>",
        },
        "pu-notes": {
            "display": "none",
        },
        "pu-notes-more": {
            "display": "none",
        },
        "pu-commits": {
            "open": True,
        },
    },
    "behind with nothing listed": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-warning\"><i class=\"bi bi-arrow-up-circle-fill\"></i> «Update "
                     "available: <strong data-no-i18n>?</strong> (2 commits behind).»</span>"),
        },
        "pu-update-btn": {
            "display": "",
        },
        "pu-changes": {
            "display": "none",
        },
        "pu-current": {
            "text": "2026.11.13 · a8d76b0",
        },
        "pu-notes": {
            "display": "none",
        },
        "pu-notes-more": {
            "display": "none",
        },
        "pu-commits": {
            "open": True,
        },
    },
    "no header element": {
        "remembered": "this answer",
        "pu-status": {
            "html": ("<span class=\"text-success\"><i class=\"bi bi-check-circle\"></i> «You're up to "
                     "date: release 2026.11.13 (a8d76b0).»</span>"),
        },
        "pu-update-btn": {
            "display": "none",
        },
        "pu-changes": {
            "display": "none",
        },
    },
    "no card": {
        "remembered": "before",
    },
}

# ── the checks ──────────────────────────────────────────────────────────────────────────────────
_fb195 = _node47(_fb_prog195(_read195("panel", "static", "js", "remote_manage_backups.js")))
_pu195 = _node47(_pu_prog195(_read195("panel", "static", "js", "remote_manage_host.js")))
if _fb195 is None or _pu195 is None:
    skip("backups summary and update card text", "node is not installed here")
else:
    for _k195 in _FB_STATES195:
        check("backups summary: %s draws what it drew" % _k195,
              _fb195.get(_k195) == _FB_WANT195.get(_k195),
              repr((_fb195.get(_k195), _FB_WANT195.get(_k195), _fb195.get("error"))))
    for _k195 in _PU_STATES195:
        check("update card: %s draws what it drew" % _k195,
              _pu195.get(_k195) == _PU_WANT195.get(_k195),
              repr((_pu195.get(_k195), _PU_WANT195.get(_k195), _pu195.get("error"))))
