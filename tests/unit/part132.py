"""Part 132 of the unit suite: six tidy-ups of the host page and Settings (ui-tidy-2).

1. The auto-block threshold has ONE editor, on a host page's Security tab beside the Auto-block switch
   it governs. Settings › Sessions & Security shows the value and links there; its Save no longer
   writes the threshold (with the field gone, reading it with a default would have put every install
   back to 20). Who may change it is unchanged: a superadmin, on either route.
2. Every message that sent the user to "the host's Firewall page" names the host page's Network tab
   (where the firewall rules are now), in English, Spanish and French: no catalog key, template text or
   script string says "Firewall page" any more, and the sentences translate whole.
3. Phone order: on the Network tab the rules come right after the UFW badge, before the forms — the DOM
   order, so the keyboard and a screen reader go the same way; from 768px a grid puts them in a
   right-hand column as before.
4. Tab labels: below 768px the pills are icon-over-label with short labels for Host Controls and
   Maintenance, the full label kept for screen readers (visually hidden, never display:none).
5. The old /remote/<id>/firewall page redirects to the host page's Network tab (the panel host's to
   /server-management#network) after the page's own access checks, and reads nothing itself.
6. Blocked IPs (UFW) and the fail2ban bans are one "Blocked & banned IPs" area on the Security tab, each
   list keeping its actions; #fw-blocks, #sec-bans and the
   palette land on it, and the first opening of the Security tab reads the firewall.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed, as
part131 does. Nothing reaches a host or data/.
"""
import glob as _glob132
import json as _json132
import os
import re as _re132

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client,
                         _p9_patch, _p9_restore_all, _p9_rv)
from unit.part131 import _P131, _out131, _pages131
from panel.core import i18n as _i18n132
from panel.ops.ssh_manager import hosts as _hosts132
from panel.routes import admin_notifications as _an132
from panel.routes import manage_servers as _ms132
from panel.services import monitoring as _mon132

_TRIP132_START = len(_P9_TRIPPED)


def _read132(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The auto-block threshold: one editor, on the Security tab
# ════════════════════════════════════════════════════════════════════════════════════════════════
_saved132 = {}
_uit_th = {}
# A Settings save applies its session keys to the app live: "strong" protection would sign this part's
# later clients out (their sessions carry no identifier) and every later part's too. Put back after.
_UIT_LIVE = ("PERMANENT_SESSION_LIFETIME", "REMEMBER_COOKIE_DURATION", "SESSION_PROTECTION")
_uit_live_was = {k: _p9.config.get(k) for k in _UIT_LIVE}
try:
    _p9_arm(who="part132")
    _p9_patch(_an132, "update_config", lambda mutate: mutate(_saved132))
    _p9_patch(_mon132, "load_config", lambda: {"autoblock_threshold": 37})
    _uit_th["page"] = _p9_client(P9_ADMIN).get("/settings").get_data(as_text=True)
    # A save as the page now sends it, and one from a Settings tab opened before this change (it still
    # carries the old field): neither may move the threshold.
    for _k132, _form132 in (("now", {"site_title": "Unit 132"}),
                            ("stale", {"site_title": "Unit 132", "autoblock_threshold": "3"})):
        _saved132.clear()
        _r132 = _p9_client(P9_ADMIN).post("/settings/save", data=_form132)
        _uit_th[_k132] = (_r132.status_code, dict(_saved132))
        _p9.config.update(_uit_live_was)
    # Who may change it: the Settings save and the panel host's switch are superadmin-only, as before.
    _saved132.clear()
    _uit_th["viewer_settings"] = _p9_client(P9_VIEWER).post(
        "/settings/save", data={"autoblock_threshold": "3"}).status_code
    _uit_th["viewer_panel"] = _p9_client(P9_VIEWER).post(
        "/api/panel/security/autoblock", json={"enabled": True, "threshold": 3}).status_code
    _uit_th["viewer_saved"] = dict(_saved132)
finally:
    _p9.config.update(_uit_live_was)
    _p9_restore_all()

_pg132 = _uit_th.get("page", "")
check("auto-block threshold: Settings shows the value in force, with no field of its own to edit",
      'name="autoblock_threshold"' not in _pg132
      and _re132.search(r'<code id="s-autoblock">\s*37\s*</code>', _pg132) is not None,
      repr(_re132.findall(r'[^\n]*s-autoblock[^\n]*', _pg132)))
check("auto-block threshold: ...and links to its one editor, on the panel host's Security tab",
      'href="/server-management#sec-threshold"' in _pg132, "")
for _k132 in ("now", "stale"):
    _st132, _sv132 = _uit_th.get(_k132, (0, {}))
    check("auto-block threshold: a Settings save (%s form) saves the page's own settings and leaves the "
          "threshold alone (read with a default, it put every install back to 20)" % _k132,
          _st132 == 302 and _sv132.get("site_title") == "Unit 132" and "autoblock_threshold" not in _sv132,
          repr((_st132, _sv132)))
check("auto-block threshold: who may change it is unchanged — a non-superadmin is refused by the "
      "Settings save and the panel host's switch, and nothing is written",
      _uit_th.get("viewer_settings") in (302, 401, 403) and _uit_th.get("viewer_panel") in (401, 403)
      and not _uit_th.get("viewer_saved"), repr(_uit_th.get("viewer_settings")) + repr(_uit_th.get("viewer_panel")))

# The editor it links to: on the Security tab, editable by a superadmin, Save wired to saveThreshold.
_RM132 = _read132("templates", "remote_manage.html")
_top132 = _RM132[_RM132.find("<!-- Top offending IPs"):_RM132.find('<div id="sec-top">')]
check("auto-block threshold: the Security tab's Top offenders card holds the editor (a superadmin's "
      "field and Save; a disabled field for anyone else)",
      'data-mtab="security"' in _top132 and 'id="sec-threshold" value="20">' in _top132
      and 'data-action="saveThreshold"' in _top132 and "disabled" in _top132, _top132[:200])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Messages name the Network tab, not "the Firewall page"
# ════════════════════════════════════════════════════════════════════════════════════════════════
_CAT132 = {}
for _lang132 in ("es", "fr"):
    for _f132 in sorted(_glob132.glob(os.path.join(_root, "translations", _lang132, "*.json"))):
        with open(_f132, encoding="utf-8") as _fh132:
            _CAT132.setdefault(_lang132, {}).update(_json132.load(_fh132))
# Every translatable server message has a catalog key (the i18n gates hold that), so a key is where a
# sentence that still says "Firewall page" shows up, whichever file builds it.
_old_keys132 = sorted({k for c in _CAT132.values() for k in c if "irewall page" in k})
check("firewall wording: no message in the catalogs sends the user to \"the Firewall page\"",
      not _old_keys132 and len(_CAT132.get("es", {})) > 1000, repr(_old_keys132[:4]))
_net_keys132 = sorted(k for k in _CAT132.get("es", {}) if "host's Network tab" in k)
check("firewall wording: ...each names the host's Network tab, translated in Spanish and French with the "
      "tab's own name (Red / Réseau)",
      len(_net_keys132) >= 12
      and all("Red" in _CAT132["es"][k] and "Réseau" in _CAT132.get("fr", {}).get(k, "") for k in _net_keys132),
      repr([k for k in _net_keys132 if "Red" not in _CAT132["es"][k]
            or "Réseau" not in _CAT132.get("fr", {}).get(k, "")][:3]) + " of %d" % len(_net_keys132))


def _uit_strip(text, kind):
    """`text` without its comments (Jinja/HTML for a template, // and /* */ for a script)."""
    if kind == "html":
        return _re132.sub(r"\{#.*?#\}|<!--.*?-->", "", text, flags=_re132.S)
    return _re132.sub(r"/\*.*?\*/|(?<![:\\'\"])//[^\n]*", "", text, flags=_re132.S)


_uit_said = []
for _kind132, _pat132 in (("html", ("templates", "*.html")), ("js", ("static", "js", "*.js"))):
    for _f132 in sorted(_glob132.glob(os.path.join(_root, *_pat132))):
        with open(_f132, encoding="utf-8") as _fh132:
            if "irewall page" in _uit_strip(_fh132.read(), _kind132):
                _uit_said.append(os.path.basename(_f132))
check("firewall wording: no template text or script string says \"Firewall page\" (comments aside)",
      not _uit_said, repr(_uit_said))
# The sentences themselves, as a French viewer reads them: whole, with the tab named.
_fr132 = [_i18n132.translate("fr", s.template) for s in (
    _hosts132.UFW_UNREAD_NOTE, _ms132.FIREWALL_STEP_FAILED, _hosts132._r36b_rule_left_note(2022))]
check("firewall wording: the firewall-could-not-be-read note, the install's failed firewall step and an SSH "
      "move's rule-left note read in French, naming the Network tab",
      all("onglet Réseau" in t and "page Pare-feu" not in t for t in _fr132), repr(_fr132))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Phone order on the Network tab: the rules right after the UFW badge (ui-dense: on the heading)
# ════════════════════════════════════════════════════════════════════════════════════════════════
_CSS132 = _read132("static", "css", "panel.css")


def _uit_order(page, ids):
    """Where each of `ids` starts in `page`'s rendered HTML (-1: absent)."""
    html = _pages131.get(page, (0, ""))[1]
    return [html.find('id="%s"' % i) for i in ids]


for _page132 in ("local", "remote"):
    _o132 = _uit_order(_page132, ("ufw-badge", "fw-rules", "rules-list", "new-port", "src-cidr", "limit-port"))
    check("phone order (%s host page): the UFW badge, then Open Ports & Rules, then the forms — in the page's "
          "own order, which a phone shows as it is" % _page132,
          -1 not in _o132 and _o132 == sorted(_o132), repr(_o132))
_PART132 = _read132("templates", "_firewall_panel.html")
check("phone order: the rules card is the grid's right-hand column (fw-rules-card in .fw-layout)",
      '<div class="fw-layout">' in _PART132 and 'class="card mb-3 fw-rules-card"' in _PART132
      and "col-md-" not in _PART132, "")
_grid132 = _re132.search(r"@media \(width >= 768px\)\{\s*\.fw-layout\{([^}]*)\}(.*?)\n\}", _CSS132, _re132.S)
check("phone order: from 768px the rules sit in a second column beside the forms, spanning every row, "
      "with no card stretched to its row (the desktop layout as before)",
      _grid132 is not None and "grid-template-columns:5fr 7fr" in _grid132.group(1)
      and "align-items:start" in _grid132.group(1)
      and _re132.search(r"\.fw-layout > \.fw-rules-card\{\s*grid-column:2;\s*grid-row:1 / -1;", _grid132.group(2))
      is not None, repr(_grid132.group(0)[:300] if _grid132 else None))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Tab labels that fit a phone, the full label kept for screen readers
# ════════════════════════════════════════════════════════════════════════════════════════════════
for _page132 in ("local", "remote"):
    _html132 = _pages131.get(_page132, (0, ""))[1]
    _pills132 = dict(_re132.findall(r'data-mtab-btn="(\w+)">(.*?)</button>', _html132))
    check("tab labels (%s host page): Host Controls and Maintenance carry the full label and a short one "
          "hidden from screen readers; the other three are short already" % _page132,
          '<span class="mtab-full">Host Controls</span><span class="mtab-short" aria-hidden="true">Controls'
          '</span>' in _pills132.get("controls", "")
          and '<span class="mtab-full">Maintenance</span><span class="mtab-short" aria-hidden="true">Maint.'
              '</span>' in _pills132.get("maintenance", "")
          and sorted(_pills132) == ["controls", "maintenance", "network", "overview", "security"],
          repr(_pills132))
_tabs132 = _CSS132[_CSS132.find("#mtab-nav .mtab-short{ display:none; }"):]
_narrow132 = _re132.search(r"@media \(width <= 767\.98px\)\{(.*?)\n\}", _tabs132, _re132.S)
_full132 = _re132.search(r"#mtab-nav \.mtab-full\{([^}]*)\}", _narrow132.group(1) if _narrow132 else "")
check("tab labels: the short label is hidden on a desktop and shown below 768px, where the full one is "
      "visually hidden (still read out: clipped, not display:none) and the pills share the bar",
      _narrow132 is not None and _full132 is not None
      and "#mtab-nav .mtab-short{ display:inline; }" in _narrow132.group(1)
      and "#mtab-nav > .nav-item{ flex:1 1 auto; }" in _narrow132.group(1)
      and "clip:rect(0, 0, 0, 0)" in _full132.group(1) and "display:none" not in _full132.group(1),
      repr(_narrow132.group(0)[:200] if _narrow132 else None))
check("tab labels: the short labels are in the es and fr catalogs",
      all(k in _CAT132.get(lang, {}) for lang in ("es", "fr") for k in ("Controls", "Maint.")), "")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The old Firewall page's URL: a redirect to the Network tab, behind the page's own checks
# ════════════════════════════════════════════════════════════════════════════════════════════════
_uit_fw = {}
_uit_reads = []


def _uit_ufw_read(remote):
    """remote_ufw_status's stand-in: counts a read the redirect must not make."""
    _uit_reads.append(remote)
    return {}


try:
    _p9_arm(who="part132")
    _p9_patch(_p9_rv, "remote_ufw_status", _uit_ufw_read)
    _uit_who = (("remote", P9_ADMIN, P9_HOST), ("local", P9_ADMIN, P9_LOCAL), ("viewer", P9_VIEWER, P9_HOST),
                ("viewer_local", P9_VIEWER, P9_LOCAL), ("missing", P9_ADMIN, 990132))
    for _k132, _uid132, _rid132 in _uit_who:
        _r132 = _p9_client(_uid132).get("/remote/%d/firewall" % _rid132)
        _uit_fw[_k132] = (_r132.status_code, _r132.headers.get("Location", ""))
finally:
    _p9_restore_all()
check("old Firewall URL: a remote's redirects to its host page's Network tab, the panel host's to "
      "/server-management#network",
      _uit_fw.get("remote", (0, ""))[0] == 302
      and _uit_fw["remote"][1].endswith("/remote/%d/manage#network" % P9_HOST)
      and _uit_fw.get("local", (0, ""))[0] == 302 and _uit_fw["local"][1].endswith("/server-management#network"),
      repr(_uit_fw))
# A refusal is the panel's own (_deny: a page request is sent home with a flash, as the page's was).
check("old Firewall URL: ...a user without the right to manage the host, and a host that does not exist, "
      "are refused as the page refused them — never redirected on to the host page",
      all(_uit_fw.get(k, (0, ""))[0] in (302, 403, 404) and "#network" not in _uit_fw[k][1]
          and "manage" not in _uit_fw[k][1] for k in ("viewer", "viewer_local", "missing"))
      and _uit_fw.get("missing", (0, ""))[0] == 404, repr(_uit_fw))
check("old Firewall URL: ...and the redirect reads no firewall (the tab reads it when it opens)",
      _uit_reads == [], repr(len(_uit_reads)))
check("old Firewall URL: the standalone template is gone, and nothing renders or links to it",
      not os.path.exists(os.path.join(_root, "templates", "remote_firewall.html"))
      and "remote_firewall.html" not in _read132("panel", "routes", "remote_vps.py"), "")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Blocked & banned IPs together on the Security tab
# ════════════════════════════════════════════════════════════════════════════════════════════════
_KEPT132 = ("sec-keptout", "fw-blocks", "blocks-list", "blocks-count", "blocks-inactive-note", "block-ip",
            "block-result", "sec-bans")
for _page132 in ("local", "remote"):
    _p132 = _P131.get(_page132)
    _where132 = {i: (_p132.where.get(i, "<absent>") if _p132 else "<no page>") for i in _KEPT132}
    check("blocked & banned (%s host page): Blocked IPs and the fail2ban bans are both in the Security tab's "
          "area, and the tab is offered" % _page132,
          _p132 is not None and "security" in _p132.buttons and set(_where132.values()) == {"security"},
          repr(_where132))
    _acts132 = _p132.actions.get("security", set()) if _p132 else set()
    check("blocked & banned (%s host page): each list keeps its own actions there — Block IP and Refresh "
          "for UFW, Refresh for fail2ban; unblock and unban are drawn per row by their scripts" % _page132,
          {"blockIp", "refreshFirewall", "loadSecurityBans", "loadSecurityTopIps"}
          <= _acts132, repr(sorted(_acts132)))
    _html132 = _pages131.get(_page132, (0, ""))[1]
    _o132 = _uit_order(_page132, ("sec-keptout", "fw-blocks", "sec-bans"))
    check("blocked & banned (%s host page): under one heading, the UFW list then the fail2ban list"
          % _page132, -1 not in _o132 and _o132 == sorted(_o132)
          and "Blocked &amp; banned IPs</h2>" in _html132[_o132[0]:_o132[1]], repr(_o132))
    _hrefs132 = {(h, t) for h, t in (_p132.hrefs if _p132 else [])}
    check("blocked & banned (%s host page): nothing on the Network tab links to a Blocked IPs card of its "
          "own, and Top offenders' link lands beside the list" % _page132,
          ("#fw-blocks", "network") not in _hrefs132 and ("#fw-blocks", "security") in _hrefs132,
          repr(sorted(h for h in _hrefs132 if h[0].startswith("#"))))
_PAL132 = _read132("static", "js", "palette.js")
check("blocked & banned: the palette finds Blocked IPs (\"block\" found only the Firewall row, which opens "
      "the Network tab), for the panel host and every remote",
      "page: '/server-management', hash: 'fw-blocks'" in _PAL132 and "{ hash: 'fw-blocks'," in _PAL132
      and "allow deny block network" not in _PAL132, "")
_RMJS132 = _read132("static", "js", "remote_manage.js")
_kept132 = _RMJS132.partition("function _uitKeptOutChanged(){")[2].partition("\n}")[0]
check("blocked & banned: a block or unblock from Top offenders repaints the Blocked IPs list beside it",
      _RMJS132.count("_uitKeptOutChanged(); })") == 2
      and "loadSecurityTopIps();" in _kept132 and "refreshFirewall();" in _kept132, repr(_kept132))
if _out131 is not None:
    check("blocked & banned: the Security tab's first opening reads the firewall (its Blocked IPs), once — "
          "the Network tab opened after reads nothing more",
          (_out131.get("sec") or {}).get("first") == 1 and _out131["sec"].get("again") == 1
          and _out131["sec"].get("active") == ["security"], repr(_out131.get("sec")))
    check("blocked & banned: a link to #fw-blocks opens the Security tab, scrolls to the card and reads",
          _out131.get("blocks") == {"reads": 1, "active": ["security"], "scrolled": ["fw-blocks"]},
          repr(_out131.get("blocks")))

# ── END: keep this last ──────────────────────────────────────────────────────────────────────────
check("part132: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP132_START, repr(_P9_TRIPPED[_TRIP132_START:][:6]))
