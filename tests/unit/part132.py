"""Part 132 of the unit suite: six tidy-ups of the host page and Settings (ui-tidy-2).

1. The auto-block threshold has ONE editor, on a host page's Security tab beside the Auto-block switch
   it governs. Settings › Sessions & Security shows the value and links there; its Save no longer
   writes the threshold (with the field gone, reading it with a default would have put every install
   back to 20). Who may change it is unchanged: a superadmin, on either route.
2. Every message that sent the user to "the host's Firewall page" names the host page's Network tab
   (where the firewall rules are now), in English, Spanish and French: no catalog key, template text or
   script string says "Firewall page" any more, and the sentences translate whole.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed, as
part131 does. Nothing reaches a host or data/.
"""
import glob as _glob132
import json as _json132
import os
import re as _re132

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch,
                         _p9_restore_all)
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
