"""Part 132 of the unit suite: six tidy-ups of the host page and Settings (ui-tidy-2).

1. The auto-block threshold has ONE editor, on a host page's Security tab beside the Auto-block switch
   it governs. Settings › Sessions & Security shows the value and links there; its Save no longer
   writes the threshold (with the field gone, reading it with a default would have put every install
   back to 20). Who may change it is unchanged: a superadmin, on either route.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed and every host call stubbed, as
part131 does. Nothing reaches a host or data/.
"""
import os
import re as _re132

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_patch,
                         _p9_restore_all)
from panel.routes import admin_notifications as _an132
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
