"""Part 227 of the unit suite: an optional SSH host key fingerprint on the Add and Edit host forms.

* Add host with a fingerprint: the first connection's key must have it (SHA256, as `ssh-keygen -lf`
  prints it) or the host is refused, before the credential is sent, and no row is stored; a match
  stores that key as the pin. A malformed fingerprint is refused before anything connects; a blank
  one keeps trust on first use.
* Edit host with a fingerprint: compared with the pin when there is one (a mismatch changes nothing
  on the row), and checked against the host itself when nothing is pinned, its key then pinned.

HOW IT RUNS. Through the real routes on part12's Flask app, with its transport tripwire armed and a
stand-in SSH client whose connect() asks the real host key policy first and records a credential only
when that policy let it through, the order paramiko keeps. Nothing reaches a host or the checkout's data/.
"""
import base64 as _b64227
import hashlib as _hash227
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part10 import _Over
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from panel.core.config import encrypt_secret as _enc227
from panel.core.validation import host_key_fingerprint_arg as _fp_arg227
from panel.db.models import RemoteServer as _RS227, db as _db227
from panel.ops.ssh_manager import hosts as _hosts227

_trips227 = len(_P9_TRIPPED)
_CRED227 = "p227-stand-in-credential"
_RAW227 = b"p227 host key bytes"
_KEY227 = "ssh-ed25519 " + _b64227.b64encode(_RAW227).decode()
# Worked out here, apart from the code under test: SHA256 of the key blob, base64 without padding.
_FP227 = "SHA256:" + _b64227.b64encode(_hash227.sha256(_RAW227).digest()).decode().rstrip("=")
_OTHER227 = "SHA256:" + _b64227.b64encode(_hash227.sha256(b"another key").digest()).decode().rstrip("=")
_HDR227 = {"Accept": "application/json"}
_SENT227 = []
_ROWS227 = []


class _Key227:
    """The key the stand-in server presents."""

    def get_name(self):
        """Return the key type."""
        return "ssh-ed25519"

    def get_base64(self):
        """Return the key blob in base64."""
        return _KEY227.split()[1]


class _Client227:
    """A stand-in paramiko.SSHClient: the host key policy is asked before the credential goes out."""

    def __init__(self):
        """Start with no policy."""
        self.policy = None

    def set_missing_host_key_policy(self, policy):
        """Keep the policy, as paramiko does."""
        self.policy = policy

    def connect(self, host, port=22, username="", password=None, **kw):
        """Ask the policy about the presented key (it may raise), then record what was sent."""
        self.policy.missing_host_key(self, host, _Key227())
        _SENT227.append((host, password))

    def close(self):
        """Nothing to close."""


def _arm227():
    """The tripwire, then the stand-in client for ssh_test_connection only."""
    _p9_arm(who="part227")
    _p9_patch(_hosts227, "paramiko", _Over(_hosts227.paramiko, SSHClient=_Client227))
    del _SENT227[:]


def _add227(host, fingerprint):
    """Post the Add host form for `host` with `fingerprint`; (status, message, row or None).

    What the stand-in server was sent is cleared first, so each case reads only its own.
    """
    del _SENT227[:]
    r = _p9_client(P9_ADMIN).post("/remotes/add", headers=_HDR227, data={
        "name": host.split(".")[0], "host": host, "ssh_port": "22", "ssh_user": "root",
        "auth_method": "password", "credential": _CRED227, "setup_type": "existing",
        "host_key_fingerprint": fingerprint})
    with _p9.app_context():
        # host is stored encrypted (models' encrypted columns), so it is compared after reading.
        row = next((r for r in _RS227.query.all() if r.host == host), None)
        if row is not None:
            _ROWS227.append(row.id)
        got = NS(host_key=row.host_key) if row is not None else None
    return r.status_code, _p9_json(r).get("message") or "", got


def _adds227():
    """The Add host form, through the route."""
    code, msg, row = _add227("p227a.example.invalid", "256 %s root@p227a (ED25519)" % _FP227)
    eq("fingerprint: Add host with the ssh-keygen -lf line of the right key stores that key as the pin",
       (row and row.host_key, _SENT227), (_KEY227, [("p227a.example.invalid", _CRED227)]))
    code, msg, row = _add227("p227b.example.invalid", _OTHER227)
    eq("fingerprint: Add host refuses a host whose key has another fingerprint, sends it no credential and "
       "stores no row", (code, row, _SENT227, "does not match the fingerprint entered" in msg,
                         _FP227 in msg), (400, None, [], True, True))
    code, msg, row = _add227("p227c.example.invalid", "MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48")
    eq("fingerprint: Add host refuses a fingerprint that is not SHA256 before anything connects",
       (code, row, _SENT227, msg.startswith("Host key fingerprint must be SHA256")), (400, None, [], True))
    code, msg, row = _add227("p227d.example.invalid", "")
    eq("fingerprint: Add host with the field empty still trusts and pins the first key (TOFU)",
       (row and row.host_key, len(_SENT227)), (_KEY227, 1))


def _host227(name, pin):
    """A remote row on `name` with pin `pin`; its id."""
    with _p9.app_context():
        r = _RS227(name=name.split(".")[0], host=name, port=22, username="root", auth_method="password",
                   auth_credential=_enc227(_CRED227), is_online=True, host_key=pin)
        _db227.session.add(r)
        _db227.session.commit()
        _ROWS227.append(r.id)
        return r.id


def _edit227(rid, fingerprint, name):
    """Post the Edit host form with a new `name` and `fingerprint`; (status, message, name, pin)."""
    del _SENT227[:]
    r = _p9_client(P9_ADMIN).post("/remotes/%d/edit" % rid, headers=_HDR227, data={
        "name": name, "ssh_port": "22", "auth_method": "password", "host_key_fingerprint": fingerprint})
    with _p9.app_context():
        row = _db227.session.get(_RS227, rid)
        return r.status_code, _p9_json(r).get("message") or "", row.name, row.host_key


def _edits227():
    """The Edit host form, through the route."""
    rid = _host227("p227e.example.invalid", _KEY227)
    got = _edit227(rid, _OTHER227, "p227e-renamed")
    eq("fingerprint: Edit refuses a fingerprint the pinned key does not have, names both, and changes nothing",
       (got[0], got[2], got[3], _FP227 in got[1] and _OTHER227 in got[1], _SENT227), (400, "p227e", _KEY227, True, []))
    got = _edit227(rid, _FP227, "p227e-renamed")
    eq("fingerprint: Edit with the pinned key's fingerprint saves without connecting",
       (got[0], got[2], _SENT227), (200, "p227e-renamed", []))
    rid = _host227("p227f.example.invalid", "")
    got = _edit227(rid, _OTHER227, "p227f-renamed")
    eq("fingerprint: Edit of a host with no pin asks the host, and a key with another fingerprint is refused "
       "before the credential is sent, with nothing pinned or renamed",
       (got[0], got[2], got[3], len(_SENT227), "does not match the fingerprint entered" in got[1]),
       (400, "p227f", "", 0, True))
    got = _edit227(rid, _FP227, "p227f-renamed")
    eq("fingerprint: Edit of a host with no pin pins the key that matched",
       (got[0], got[2], got[3], len(_SENT227)), (200, "p227f-renamed", _KEY227, 1))


def _parse227():
    """The field's parser."""
    eq("fingerprint: the field takes the fingerprint alone, padded or with ssh-keygen's whole line; blank is "
       "blank; a short one or MD5 is refused",
       [_fp_arg227(t) for t in (_FP227, _FP227 + "=", "256 %s c (ED25519)" % _FP227, "  ", _FP227[:-1],
                                "MD5:aa:bb", "x" * 600)],
       [_FP227, _FP227, _FP227, "", None, None, None])


def _cleanup227():
    """Remove this part's rows."""
    with _p9.app_context():
        for rid in _ROWS227:
            row = _db227.session.get(_RS227, rid)
            if row is not None:
                _db227.session.delete(row)
        _db227.session.commit()


try:
    for _section227 in (_adds227, _edits227, _parse227):
        _arm227()
        try:
            _section227()
        finally:
            _p9_restore_all()
finally:
    _cleanup227()
check("fingerprint: nothing in this part reached a real transport (part12's tripwire)",
      len(_P9_TRIPPED) == _trips227)
