"""Part 145 of the unit suite: `details` shows all of its output, and its secrets only to those who may.

A Details dialog (2026-11-05) ended at "Memory" on a lone "S": _run_sync_action cut every
read-only action's reply at 600 characters. LinuxGSM's `details` is the one command that prints
passwords unmasked (fn_info_messages_password_strip skips DETAILS), and that cut was all that kept
them from a VIEW_CONSOLE-only member. Held here:

* the reply carries the whole output, to the page's (scrolling) dialog;
* a member without MANAGE_SERVERS gets every labelled secret, its value anywhere else and the
  start command line masked; an administrator gets the output as LinuxGSM printed it;
* the audit row is masked whoever ran it; the form route's flash (the session cookie) stays short.
"""
from unit.part01 import check
from unit.part12 import (P9_ADMIN, P9_GS, P9_VIEWER, _P9_TRIPPED, _p9, _p9_audit, _p9_client,
                         _p9_patch, _p9_patch_sm, _p9_restore_all)
from panel.db.models import GameServer, User, db
from panel.routes import server_detail as _sd145

_TRIP145_START = len(_P9_TRIPPED)

# The shape of a real `details` (measured on the test host: four games, column -t padding, the
# separator lines), with invented secrets.
_DETAILS145 = "\n".join(
    ["Distro Details", "=" * 40, "Distro:     Ubuntu 24.04.5 LTS", "",
     "Server Resource", "=" * 40] + ["Physical:   32GB 3.9GB 27GB line %d" % i for i in range(40)] + [
     "", "Counter-Strike Server Details", "=" * 40,
     "Server name:              p145 server",
     "Server password enabled:  true",
     "Server password:          pw-p145-alpha",
     "RCON password:            rc-p145-bravo",
     "Admin password:           NOT SET",
     "Auth Token:               tok-p145-charlie",
     "Maxplayers:               16", "",
     "Command-line Parameters", "=" * 40,
     "./srcds_run -game csgo +sv_setsteamaccount GSLT145DELTA +rcon_password rc-p145-bravo",
     " +sv_password pw-p145-alpha", "",
     "Ports", "=" * 40, "> Game  inbound  27015  udp",
     "the end: rc-p145-bravo was here"])
_SECRETS145 = ("pw-p145-alpha", "rc-p145-bravo", "tok-p145-charlie", "GSLT145DELTA")

# ── the masker on its own ─────────────────────────────────────────────────────────────────────────
_m145 = _sd145._dtl_mask_secrets(_sd145._clean_action_output(_DETAILS145))
check("details masking: no secret survives anywhere — labelled, repeated, or on the command line",
      not [s for s in _SECRETS145 if s in _m145], repr([s for s in _SECRETS145 if s in _m145]))
check("details masking: the labels stay, with the mask where their value was",
      "RCON password: ********" in _m145 and "Server password: ********" in _m145
      and "Auth Token: ********" in _m145, repr(_m145[-900:]))
check("details masking: an unset field and an on/off flag are left as LinuxGSM printed them",
      "Admin password: NOT SET" in _m145 and "Server password enabled: true" in _m145, repr(_m145[-900:]))
check("details masking: the start command line is replaced by one line that says why, and the next "
      "section is kept", _sd145._DTL_CMDLINE_HIDDEN in _m145 and "+sv_password" not in _m145
      and "> Game inbound 27015 udp" in _m145, repr(_m145[-500:]))
check("details masking: output with no secrets in it comes back unchanged",
      _sd145._dtl_mask_secrets("Distro: Ubuntu\nMem: 32GB") == "Distro: Ubuntu\nMem: 32GB")

# ── through the action path ───────────────────────────────────────────────────────────────────────
try:
    _p9_patch_sm("run_as_game_user", lambda remote, user, action, **k: (_DETAILS145, "", 0))
    _p9_patch(_sd145, "_after_power_action", lambda *a, **k: None)
    with _p9.app_context():
        _g145 = db.session.get(GameServer, P9_GS)
        _admin145 = db.session.get(User, P9_ADMIN)
        _viewer145 = db.session.get(User, P9_VIEWER)
        _as_admin145 = str(_sd145._run_sync_action(_p9, _g145, _g145.remote, "details", _admin145, None)[1])
        _audit_admin145 = _p9_audit("details_server").detail
        _as_viewer145 = str(_sd145._run_sync_action(_p9, _g145, _g145.remote, "details", _viewer145, None)[1])
        _as_bot145 = str(_sd145._run_sync_action(_p9, _g145, _g145.remote, "details", None, "p145-bot")[1])
    _form145 = _p9_client(P9_ADMIN).post("/server/%d/action" % P9_GS, data={"action": "details"})
    with _p9_client(P9_ADMIN) as _c145:
        _c145.post("/server/%d/action" % P9_GS, data={"action": "details"})
        with _c145.session_transaction() as _s145:
            _flashes145 = [m for _cat, m in _s145.get("_flashes", [])]
finally:
    _p9_restore_all()

check("details reply: the whole output reaches the dialog, not its first 600 characters "
      "(one ended at 'Memory' on a lone 'S')",
      len(_as_admin145) > 2000 and _as_admin145.rstrip().endswith("the end: rc-p145-bravo was here"),
      repr((len(_as_admin145), _as_admin145[-80:])))
check("details reply: an administrator (MANAGE_SERVERS, who can open the configs) sees it unmasked",
      all(s in _as_admin145 for s in _SECRETS145), repr([s for s in _SECRETS145 if s not in _as_admin145]))
check("details reply: a VIEW_CONSOLE-only member gets the whole output with every secret masked",
      not [s for s in _SECRETS145 if s in _as_viewer145] and "the end: ******** was here" in _as_viewer145
      and _sd145._DTL_CMDLINE_HIDDEN in _as_viewer145,
      repr([s for s in _SECRETS145 if s in _as_viewer145]))
check("details reply: a caller that is not a panel user is masked too",
      not [s for s in _SECRETS145 if s in _as_bot145], repr([s for s in _SECRETS145 if s in _as_bot145]))
check("details audit row: masked even when an administrator ran it (the log's readers are not the runner)",
      isinstance(_audit_admin145, str) and _audit_admin145 and not [s for s in _SECRETS145 if s in _audit_admin145],
      repr(_audit_admin145))
check("details from the form route: the flash (carried in the session cookie) stays short",
      _form145.status_code == 302 and _flashes145
      and all(len(str(m)) <= _sd145._DTL_FLASH_MAX for m in _flashes145),
      repr((_form145.status_code, [len(str(m)) for m in _flashes145])))
check("part145: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP145_START, repr(_P9_TRIPPED[_TRIP145_START:]))
