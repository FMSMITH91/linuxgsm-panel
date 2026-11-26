"""Part 290 of the unit suite: permissions on routes (security scan of 2026-11-22).

1. Re-trusting a host's SSH key is superadmin-only: the next connection pins whatever machine answers
   and signs in with the host's saved credential, often the panel's own key. A delegated host admin
   is refused (403, the pin kept) and the host page tells them why next to a disabled button.
2. Scheduled Tasks run any command as the game account: adding, changing, deleting or running one needs
   EDIT_FILES as well as MANAGE_SERVERS, a failed task's output needs VIEW_FILES, and Run now runs only
   a line read back from the account's crontab. The card keeps its form, disabled, and says why.
3. A delegated host admin's add-remote connection test, and their edit of a host's address or port, may
   not aim at a loopback, private, link-local or tailnet address (every record of a name checked), and
   the test dials the address that was checked. A superadmin is not limited.
4. A console command that sets a secret (`rcon_password X`) is kept in the audit log, and in the command
   form's notice, with its value masked; the game is still sent it as typed.
5. A console (or terminal) socket opened with an API token fails its per-tick credential check once the
   token has expired, not only when it is revoked.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host-facing call a
route makes is a stand-in. Nothing reaches a host, /etc or data/.
"""
import os as _os290
from datetime import timedelta as _td290

from unit.part01 import check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_GS, P9_HOST, _p9, _p9_arm, _p9_audit_count, _p9_client,
                         _p9_host_row, _p9_patch, _p9_patch_sm, _p9_quiet_lookups, _p9_restore_all, _p9_set_host)
from unit.part131 import _STATUS131
from panel.core.clock import utcnow as _now290
from panel.db.models import (AuditLog as _Audit290, CustomCommand as _CC290, Group as _Group290,
                             RemoteServer as _Remote290, User as _User290, db as _db290)
from panel.ops import system_ops as _so290, tailscale_integration as _ts290
from panel.ops.ssh_manager import _core as _core290
from panel.core.validation import ip_address_or_none as _ip290
from panel.routes import (_shared as _sh290, remote_vps as _rv290, remotes as _rm290, server_detail as _sd290,
                          server_files as _sf290)
from panel.security import auth as _auth290
from panel.services import console_secrets as _csec290


def _user290(name, perms, hosts=(), servers=()):
    """A non-superadmin in one group holding `perms` on `hosts` (RemoteServer ids) and `servers`. -> (uid, gid)."""
    from panel.db.models import GameServer as _GS290
    with _p9.app_context():
        grp = _Group290(name=name, description="", is_default=False)
        grp.set_permissions(list(perms))
        grp.servers.extend(_db290.session.get(_Remote290, h) for h in hosts)
        grp.game_servers.extend(_db290.session.get(_GS290, s) for s in servers)
        _db290.session.add(grp)
        _db290.session.flush()
        u = _User290(username=name, password_hash=_os290.urandom(8).hex(), display_name=name,
                     is_superadmin=False, is_active=True)
        u.groups.append(grp)
        _db290.session.add(u)
        _db290.session.commit()
        return u.id, grp.id


def _drop290(uid, gid):
    with _p9.app_context():
        for model, rid in ((_User290, uid), (_Group290, gid)):
            row = _db290.session.get(model, rid)
            if row is not None:
                _db290.session.delete(row)
        _db290.session.commit()


def _j290(resp):
    return resp.get_json(silent=True) or {}


# ── 1. Re-trust host key: superadmin-only ─────────────────────────────────────────────────────────
_PIN290 = "AAAAC3NzaC1lZDI1NTE5AAAAIP290pinnedkeyp290pinnedkeyp290pinnedkey"
_hk290 = {}
_d1_290 = None
try:
    _p9_arm(who="part290")
    _trips290 = len(_P9_TRIPPED)
    _closed290 = []
    _p9_patch(_rv290, "close_connection", lambda remote: _closed290.append(remote.id))
    _p9_patch(_so290, "get_server_status", lambda *a, **k: _STATUS131)
    _p9_patch(_ts290, "panel_funnel_facts", lambda cfg: {})
    _p9_patch(_core290, "run_privileged", lambda *a, **k: ("", "", 1))
    _p9_patch(_core290, "run_command", lambda *a, **k: ("", "", 1))
    _saved_key290 = _p9_host_row(P9_HOST).host_key
    _d1_290 = _user290("p290_hosts", [_auth290.MANAGE_REMOTES, _auth290.VIEW_SERVERS], hosts=[P9_HOST])
    _D290 = _p9_client(_d1_290[0])
    _p9_set_host(P9_HOST, host_key="ssh-ed25519 " + _PIN290)
    _audits290 = _p9_audit_count("retrust_hostkey")
    _r = _D290.post("/api/remote/%d/retrust-hostkey" % P9_HOST)
    _hk290["delegate"] = (_r.status_code, _j290(_r).get("success"), _j290(_r).get("message", ""),
                          _p9_host_row(P9_HOST).host_key, _p9_audit_count("retrust_hostkey") - _audits290,
                          list(_closed290))
    _page290 = _D290.get("/remote/%d/manage" % P9_HOST)
    _hk290["delegate_page"] = (_page290.status_code, _page290.get_data(as_text=True))
    _pageA290 = _p9_client(P9_ADMIN).get("/remote/%d/manage" % P9_HOST)
    _hk290["admin_page"] = (_pageA290.status_code, _pageA290.get_data(as_text=True))
    _r = _p9_client(P9_ADMIN).post("/api/remote/%d/retrust-hostkey" % P9_HOST)
    _hk290["admin"] = (_r.status_code, _j290(_r).get("success"), _p9_host_row(P9_HOST).host_key,
                       _p9_audit_count("retrust_hostkey") - _audits290, list(_closed290))
    _hk290["trips"] = len(_P9_TRIPPED) - _trips290
finally:
    _p9_restore_all()
    if _d1_290:
        _drop290(*_d1_290)
    _p9_set_host(P9_HOST, host_key=_saved_key290)
_d290 = _hk290.get("delegate", (None,) * 6)
eq("retrust host key: a delegated MANAGE_REMOTES admin on the host is refused (403), the pin is kept, "
   "nothing is audited and no connection is dropped",
   _d290[:2] + _d290[3:], (403, False, "ssh-ed25519 " + _PIN290, 0, []))
check("retrust host key: ...and the refusal says only a superadmin can, and why",
      _d290[2] == _rv290.RETRUST_SUPERADMIN_ONLY and "superadmin" in _d290[2], repr(_d290[2]))
eq("retrust host key (control): a superadmin clears the pin, the row is audited and the cached connection dropped",
   _hk290.get("admin"), (200, True, "", 1, [P9_HOST]))
_dp290 = _hk290.get("delegate_page", (None, ""))
_ap290 = _hk290.get("admin_page", (None, ""))
check("retrust host key: the delegate's host page shows the button disabled with the sentence saying why, "
      "and no live Re-trust action",
      _dp290[0] == 200 and 'data-action="retrustHostKey"' not in _dp290[1]
      and 'disabled aria-describedby="hostkey-why"' in _dp290[1]
      and _rv290.RETRUST_SUPERADMIN_ONLY in _dp290[1], repr(_dp290[0]))
check("retrust host key (control): a superadmin's host page keeps the working Re-trust button",
      _ap290[0] == 200 and 'data-action="retrustHostKey"' in _ap290[1] and "hostkey-why" not in _ap290[1],
      repr(_ap290[0]))
eq("part290 retrust: nothing reached a real transport", _hk290.get("trips"), 0)
