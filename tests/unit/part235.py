"""Part 235 of the unit suite: the Hosts list, the host page, Tailscale and the firewall cards use no style attributes.

The page policy's style-src-attr is 'none', so a style="..." attribute in markup, a style attribute set
from a script and a style.cssText assignment are all refused by the browser. These pages' templates
and scripts use classes instead, and their elements that start hidden carry data-start-hidden.

1. Source: none of the five templates or seven scripts holds a style attribute, a setAttribute('style')
   or a .cssText assignment.
2. The pages, through the app: /remotes, the panel host's page, a remote host's page and /tailscale
   render with no style attribute in their content, and every element that starts hidden there is
   marked data-start-hidden.
3. Markup the scripts build after load: each element that starts hidden is hidden through the CSSOM
   once inserted (start_hidden.js only sees the page as loaded), and the handler that shows it sets
   an explicit display; the full-backup players dialog takes classes, not cssText.
4. panel.css: every helper class these files use is defined, and every class in this part's section
   of panel.css is used.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; scripts run in node on a
stand-in DOM. Nothing reaches a host, the network or data/.
"""
import json as _json235
import os
import re as _re235
import shutil as _shutil235
import subprocess as _sp235  # nosec B404 - node on fixtures

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part12 import P9_ADMIN, P9_HOST, P9_LOCAL, _p9_arm, _p9_client, _p9_patch, _p9_restore_all
from unit.part47 import _cut47
from panel.ops import system_ops as _so235, tailscale_integration as _ts235

_TPL235 = ("remote_manage.html", "manage_remotes.html", "tailscale.html", "_firewall_panel.html",
           "_firewall_blocks.html")
_JS235 = ("remote_manage.js", "remote_manage_backups.js", "remote_manage_host.js", "manage_remotes.js",
          "tailscale.js", "setup_tailscale.js", "remote_firewall.js")
_STYLE_ATTR235 = _re235.compile(r"""\sstyle\s*=\s*["'\\]""")
_STYLE_SET235 = _re235.compile(r"""setAttribute\(\s*['"]style['"]|\.cssText\b|\.attr\(\s*['"]style['"]""")
_SECTION235 = "/* ── Strict CSP (B2): classes that replace inline style attributes ── */"
# The helper families this part's section defines: value-named single declarations and page classes.
_FAMILY235 = _re235.compile(r"^(fs-(r|em)\d+|mw-(r\d+|\d+px)|mh-(\d+px|\d+vh)|w-(0p|1p|r\d+|\d+px)|h-\d+px"
                            r"|minw-\d+px|minh-r\d+|tnum|ff-(ui)?mono|lh-15|ls-0|wb-all|op-80|cursor-pointer"
                            r"|mt-r015|dot-12px|rm-[a-z-]+|mr-[a-z-]+|ts-warn-card|sv-overlay|sv-card-540)$")


def _read235(*parts):
    """Return a repo file's text."""
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _source235():
    """No style attribute, setAttribute('style') or cssText in the five templates and seven scripts."""
    for name in _TPL235:
        text = _read235("panel", "templates", name)
        eq("strict CSP: %s holds no style attribute" % name, _STYLE_ATTR235.findall(text), [])
    for name in _JS235:
        text = _read235("panel", "static", "js", name)
        eq("strict CSP: %s builds no markup with a style attribute" % name, _STYLE_ATTR235.findall(text), [])
        eq("strict CSP: %s sets no style attribute and no style.cssText" % name, _STYLE_SET235.findall(text), [])


def _content235(html):
    """The page's own content: from base.html's last banner slot to the end of <main>."""
    i = html.find('id="os-updates-nag"></div>')
    j = html.find("</main>", i)
    return html[i:j] if i >= 0 and j > i else ""


def _start_hidden_tags235(html):
    """The id of each tag in `html` that carries data-start-hidden."""
    out = set()
    for tag in _re235.findall(r"<[a-z][^>]*>", html, _re235.S):
        if "data-start-hidden" in tag:
            m = _re235.search(r'\bid="([^"]+)"', tag)
            out.add(m.group(1) if m else tag[:40])
    return out


# The elements on each page that start hidden, by id (per-host ids end in the host's row id).
_HIDDEN_HOST235 = {"live-stale", "pu-changes", "pu-notes", "pu-notes-more", "pu-update-btn", "pu-log",
                   "bk-table-wrap", "bk-pass-off", "diag-integrity", "diag-integrity-clean",
                   "diag-integrity-unknown", "diag-integrity-bad", "diag-db-repair-btn", "diag-report-dl",
                   "diag-report-gh", "diag-report-text", "diag-report-posture-wrap",
                   "diag-autoupd-btn"}


def _pages235():
    """Render the four pages as an admin; return {path: (status, content)}."""
    _p9_arm(who="part235")
    _p9_patch(_so235, "get_server_status", lambda *a, **k: {})
    _p9_patch(_ts235, "panel_funnel_facts", lambda cfg: {})
    # /remotes and /tailscale read the node's whole Tailscale state: installed and running, no peers.
    _p9_patch(_ts235, "get_tailscale_info", lambda force_refresh=False: _ts235.TailscaleInfo(
        installed=True, running=True, backend_state="Running"))
    try:
        c = _p9_client(P9_ADMIN)
        out = {}
        for path in ("/remotes", "/remote/%d/manage" % P9_LOCAL, "/remote/%d/manage" % P9_HOST, "/tailscale"):
            r = c.get(path)
            out[path] = (r.status_code, _content235(r.get_data(as_text=True)))
        return out
    finally:
        _p9_restore_all()


def _rendered235():
    """The pages through the app: no style attribute, and what starts hidden is marked."""
    pages = _pages235()
    for path, (status, content) in pages.items():
        eq("strict CSP: %s renders (200) with its content found" % path, (status, bool(content)), (200, True))
        eq("strict CSP: %s renders no style attribute in its content" % path,
           _STYLE_ATTR235.findall(content), [])
    local = _start_hidden_tags235(pages["/remote/%d/manage" % P9_LOCAL][1])
    eq("strict CSP: the panel host's page marks every element that starts hidden data-start-hidden",
       sorted(_HIDDEN_HOST235 - local), [])
    remote = _start_hidden_tags235(pages["/remote/%d/manage" % P9_HOST][1])
    check("strict CSP: a remote host's page marks its stale-figures line and its history state data-start-hidden",
          "live-stale" in remote and bool({"hh-empty", "hh-charts"} & remote), sorted(remote))
    hosts = _start_hidden_tags235(pages["/remotes"][1])
    want = {"add-remote-form", "bootstrap-card-%d" % P9_HOST, "bs-dismiss-%d" % P9_HOST, "bs-log-%d" % P9_HOST}
    eq("strict CSP: /remotes marks the add form and each host's bootstrap card, dismiss link and log "
       "data-start-hidden", sorted(want - hosts), [])


def _node235(name, prog):
    """Run `prog` in node; its last stdout line as JSON, or None (named skip) without node."""
    node = _shutil235.which("node")
    if not node:
        skip(name, "no node on this machine")
        return None
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    r = _sp235.run([node, "-"], input=prog, capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607
    try:
        return _json235.loads((r.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"node failed": (r.stdout + r.stderr)[-600:]}


# A stand-in DOM: getElementById answers from a table of elements, each with a style object that
# records every property set on it, and innerHTML / insertAdjacentHTML parse just the ids out of the
# markup they are given, so an element built by a script becomes findable the way the page finds it.
_DOM235 = r"""
var byId = {}, cssTextSets = 0;
function El(tag, id){ this.tagName = String(tag).toUpperCase(); this.id = id || ''; this.attrs = {};
  this.children = []; this.className = ''; this.textContent = ''; var self = this;
  this.style = new Proxy({}, {set(o, k, v){ if (k === 'cssText') cssTextSets++; o[k] = v; return true; }});
  if (id) byId[id] = this; }
El.prototype.appendChild = function(c){ this.children.push(c); return c; };
El.prototype.setAttribute = function(k, v){ this.attrs[k] = v; };
El.prototype.removeAttribute = function(k){ delete this.attrs[k]; };
El.prototype.addEventListener = function(){}; El.prototype.remove = function(){ if (this.id) delete byId[this.id]; };
El.prototype.querySelector = function(){ return null; }; El.prototype.querySelectorAll = function(){ return []; };
function _ids(html){ var re = /\bid="([^"]+)"/g, m; while ((m = re.exec(html))) new El('div', m[1]); }
Object.defineProperty(El.prototype, 'innerHTML', {set(v){ this._html = v; _ids(v); }, get(){ return this._html; }});
El.prototype.insertAdjacentHTML = function(_w, html){ _ids(html); };
global.window = global; global.document = {getElementById: id => byId[id] || null,
  createElement: t => new El(t), createTextNode: s => ({text: s}), body: new El('body'),
  addEventListener(){}};
global.bootstrap = {Modal: function(){ this.show = function(){}; }};
global.t = s => s; global.escapeHtml = s => String(s);
global.tfHtml = (s, v) => s.replace(/\{(\w+)\}/g, (_, k) => (v[k] && v[k].html) || v[k]);
global._da = () => '';
"""


def _built235():
    """Markup built after load: hidden through the CSSOM once in, shown with an explicit display."""
    mr = _read235("panel", "static", "js", "manage_remotes.js")
    pj = _read235("panel", "static", "js", "panel.js")
    prog = (_DOM235
            + "".join(_cut47(mr, h) + "\n" for h in (
                "function _mrStartHidden(", "function renderAuthKeyForm(", "function showModal(",
                "function setModalBody(", "function showBootstrap("))
            + _cut47(pj, "window._showTsKeyAdv = function(") + "\n"
            + "var out = {};\n"
            # The Tailscale key form, as the dialog puts it in; the callers' hide is pinned below.
            "showModal('T', ''); setModalBody(renderAuthKeyForm(4, 'h')); _mrStartHidden('ts-key-adv');\n"
            "out.adv = byId['ts-key-adv'] && byId['ts-key-adv'].style.display;\n"
            "_showTsKeyAdv(); out.advShown = byId['ts-key-adv'] && byId['ts-key-adv'].style.display;\n"
            # Prepare & Secure: its progress and log start hidden.
            "showBootstrap(4, 'h');\n"
            "out.wrap = byId['bootstrap-progress-wrap'] && byId['bootstrap-progress-wrap'].style.display;\n"
            "out.log = byId['bootstrap-log'] && byId['bootstrap-log'].style.display;\n"
            "out.cssText = cssTextSets;\n"
            "console.log(JSON.stringify(out));\n")
    name = "strict CSP: the Hosts dialogs hide the elements they build through the CSSOM"
    got = _node235(name, prog)
    if got is None:
        return
    eq(name, (got.get("wrap"), got.get("log"), got.get("cssText")), ("none", "none", 0))
    eq("strict CSP: the Tailscale key form starts hidden and 'use a pre-auth key' shows it with display block",
       (got.get("adv"), got.get("advShown")), ("none", "block"))
    # Both places that put the form in hide it straight after: the Tailscale check's "installed, not
    # running" state (setModalBody) and the install path (insertAdjacentHTML).
    check("strict CSP: the Tailscale check hides the key form it puts in the dialog",
          _re235.search(r"html \+= renderAuthKeyForm\(remoteId, name\);.*?setModalBody\(html\);\n"
                        r"\s*_mrStartHidden\('ts-key-adv'\);", mr, _re235.S) is not None)
    check("strict CSP: the Tailscale install path hides the key form it inserts",
          _re235.search(r"insertAdjacentHTML\('afterend', extra\);[^\n]*\n\s*_mrStartHidden\('ts-key-adv'\);",
                        _cut47(mr, "function _installTailscaleNow(")) is not None)
    # Prepare & Secure shows them with an explicit display: '' would leave nothing to show by.
    run = _cut47(mr, "function _runBootstrapNow(")
    check("strict CSP: Prepare & Secure shows its progress and log with display block",
          "getElementById('bootstrap-progress-wrap').style.display = 'block'" in run
          and "logEl.style.display = 'block'" in run)


def _overlay235():
    """The full-backup players dialog: classes for the overlay and its card, no cssText."""
    bk = _read235("panel", "static", "js", "remote_manage_backups.js")
    prog = (_DOM235 + _cut47(bk, "function _discT(") + "\n" + _cut47(bk, "function fbPlayersDialog(") + "\n"
            "global.tfNodes = () => []; global.confirmDialog = () => {};\n"
            "fbPlayersDialog([{name: 'A', players: 2}]);\n"
            "var ov = document.body.children[0];\n"
            "console.log(JSON.stringify({ov: ov && ov.className, card: ov && ov.children[0] && ov.children[0].className,"
            " cssText: cssTextSets}));\n")
    name = "strict CSP: the full-backup players dialog's overlay and card take classes, not style.cssText"
    got = _node235(name, prog)
    if got is not None:
        eq(name, got, {"ov": "sv-overlay", "card": "card sv-card-540", "cssText": 0})


def _classes235():
    """Every helper class used is defined in panel.css, and every class of the section is used."""
    css = _read235("panel", "static", "css", "panel.css")
    section = css[css.index(_SECTION235):] if _SECTION235 in css else ""
    defined = set(_re235.findall(r"^\.([a-z0-9-]+)\s*\{", css, _re235.M))
    mine = set(_re235.findall(r"^\.([a-z0-9-]+)\s*\{", section, _re235.M))
    text = "".join(_read235("panel", "templates", n) for n in _TPL235)
    text += "".join(_read235("panel", "static", "js", n) for n in _JS235)
    used = set()
    for cls in _re235.findall(r"""class(?:Name)?\s*=\s*["']([^"']*)["']|el\(\s*'[a-z]+'\s*,\s*'([^']*)'""", text):
        for part in cls:
            used.update(w for w in part.split() if _FAMILY235.match(w))
    eq("strict CSP: every helper class the Hosts, host, Tailscale and firewall pages use is defined in panel.css",
       sorted(used - defined), [])
    check("strict CSP: panel.css has the section for these pages' classes", bool(mine), _SECTION235)
    eq("strict CSP: every class in that section of panel.css is used by one of these pages", sorted(mine - used), [])


_source235()
_rendered235()
_built235()
_overlay235()
_classes235()
