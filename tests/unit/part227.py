"""Part 227 of the unit suite: an optional SSH host key fingerprint on the Add and Edit host forms.

* Add host with a fingerprint: the first connection's key must have it (SHA256, as `ssh-keygen -lf`
  prints it) or the host is refused, before the credential is sent, and no row is stored; a match
  stores that key as the pin. A malformed fingerprint is refused before anything connects; a blank
  one keeps trust on first use.
* Edit host with a fingerprint: compared with the pin when there is one (a mismatch changes nothing
  on the row), and checked against the host itself when nothing is pinned, its key then pinned.
* The fuzz image's base is pinned as tag@sha256, the form Renovate's dockerfile manager tracks, and
  that manager's file pattern matches that Dockerfile and no workflow; Dependabot has no docker entry.
* A root install that still has the wide sudo grant (system service, no helper, `sudo -n true`
  allowed) says so on the panel host's page, with the command that narrows it: the root-owned
  installer when it is there, else GitHub's, never the panel's own checkout. A host with the helper
  is never asked the sudo probe.

HOW IT RUNS. Through the real routes on part12's Flask app, with its transport tripwire armed and a
stand-in SSH client whose connect() asks the real host key policy first and records a credential only
when that policy let it through, the order paramiko keeps. Nothing reaches a host or the checkout's data/.
"""
import base64 as _b64227
import hashlib as _hash227
import json as _json227
import os as _os227
import re as _re227
from types import SimpleNamespace as NS

from unit.part01 import check, eq
from unit.part10 import _Over
from unit.part12 import (P9_ADMIN, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from panel.core.config import encrypt_secret as _enc227
from panel.core.validation import host_key_fingerprint_arg as _fp_arg227
from panel.db.models import RemoteServer as _RS227, db as _db227
from panel.ops import system_ops as _so227, tailscale_integration as _ts227
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


# What get_server_status answers for the pages here (part131's stand-in has the same fields).
_STATUS227 = {"has_sudo": True, "ufw": {"enabled": True, "rules": []},
              "tailscale_ssh": {"enabled": False, "running": True}, "tailscale_ssh_allowed": False,
              "tailscale_interface": "tailscale0", "tailscale_ufw_allowed": False, "updates": {}, "uptime": ""}
_ROOT227 = _os227.path.dirname(_os227.path.dirname(_os227.path.dirname(_os227.path.abspath(__file__))))
# FROM <registry/image>:<tag>@sha256:<64 hex>: Docker pulls by the digest, Renovate looks the tag up.
_FROM_PIN227 = _re227.compile(r"^FROM [a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}(?: AS \w+)?$")


def _unpinned_froms227(text):
    """The FROM lines of a Dockerfile's text that are not tag@sha256."""
    return [ln for ln in text.splitlines() if ln.startswith("FROM ") and not _FROM_PIN227.match(ln)]


def _read227(*parts):
    """Read a repository file as text."""
    with open(_os227.path.join(_ROOT227, *parts), encoding="utf-8") as fh:
        return fh.read()


def _b3_renovate227():
    """Renovate's built-in dockerfile manager stays off B3's build file."""
    rules = _json227.loads(_read227(".github", "renovate.json")).get("packageRules") or []
    off = [r for r in rules if r.get("matchManagers") == ["dockerfile"] and r.get("enabled") is False
           and r.get("matchFileNames") == ["panel/addon_images/b3/Containerfile"] and len(r) == 4]
    eq("ci images: Renovate's built-in dockerfile manager is off for B3's build file (it read the tagless base "
       "digest as python:latest), so only the custom 3.15-slim manager proposes its base", len(off), 1)


def _docker_pins227():
    """The fuzz image's base pin and the Renovate manager that keeps it current."""
    froms = _unpinned_froms227(_read227(".clusterfuzzlite", "Dockerfile"))
    pats = (_json227.loads(_read227(".github", "renovate.json")).get("dockerfile") or {}).get("managerFilePatterns")
    # Renovate's patterns are JavaScript regexes between slashes; the body reads the same in Python.
    rx = [_re227.compile(p[1:-1]) for p in pats or []]
    reads = [f for f in (".clusterfuzzlite/Dockerfile", ".github/workflows/ci.yml", "Dockerfile")
             if any(r.search(f) for r in rx)]
    eq("ci images: the fuzz image's FROM is tag@sha256 (Renovate can propose its digest) and Renovate's "
       "dockerfile manager reads that file alone; Dependabot has no docker entry to propose it twice",
       (froms, reads, "package-ecosystem: \"docker\"" in _read227(".github", "dependabot.yml")),
       ([], [".clusterfuzzlite/Dockerfile"], False))
    eq("ci images: ...and a FROM by digest alone, or by tag alone, is caught (control)",
       len(_unpinned_froms227("FROM gcr.io/a/b@sha256:%s\nFROM gcr.io/a/b:v1\nFROM gcr.io/a/b:v1@sha256:%s\n"
                              % ("a" * 64, "b" * 64))), 2)


def _grant_page227(system, helper, sudo, root_copy=False):
    """Render the panel host's two pages as a superadmin with this grant; (notes, sudo probes, commands)."""
    probes = []

    def _probe(force=False):
        probes.append(1)
        return sudo
    real_stat = _os227.stat

    def _stat(path, *a, **k):
        if path.endswith("linuxgsm-panel/install.sh"):
            if not root_copy:
                raise FileNotFoundError(path)
            return NS(st_uid=0)
        return real_stat(path, *a, **k)
    _p9_patch(_so227, "_is_system_service", lambda: system)
    _p9_patch(_so227, "_helper_present", lambda recheck=False: helper)
    _p9_patch(_so227, "_check_sudo", _probe)
    _p9_patch(_so227, "os", _Over(_os227, stat=_stat))
    # The pages' host reads (status, Funnel), answered as part177 answers them.
    _p9_patch(_so227, "get_server_status", lambda *a, **k: dict(_STATUS227))
    _p9_patch(_ts227, "panel_funnel_facts", lambda cfg: {})
    c = _p9_client(P9_ADMIN)
    pages = [c.get("/server-management"), c.get("/remote/%d/manage" % P9_LOCAL)]
    html = [p.get_data(as_text=True) if p.status_code == 200 else "status %d" % p.status_code for p in pages]
    cmds = [_re227.search(r'id="wide-sudo-note".*?<code[^>]*>([^<]*)</code>', h, _re227.S) for h in html]
    return (["wide-sudo-note" in h for h in html], len(probes),
            [m.group(1).replace("&amp;", "&") if m else None for m in cmds])


def _wide_grant227():
    """The wide-grant notice, through both panel-host pages."""
    curl = "curl -fsSL %s | sudo bash" % _so227._INSTALL_URL
    eq("sudo grant: a root install with no helper and passwordless sudo is told on both panel host pages, with "
       "GitHub's installer piped to sudo when no root-owned copy is there",
       _grant_page227(True, False, True)[0::2], ([True, True], [curl, curl]))
    got = _grant_page227(True, False, True, root_copy=True)[2]
    eq("sudo grant: ...and the root-owned installer when it is there, never the panel's own checkout",
       (got, any(str(_so227.PANEL_DIR) in (c or "") for c in got)),
       (["cd / && sudo bash /usr/local/lib/linuxgsm-panel/install.sh"] * 2, False))
    eq("sudo grant: the narrow grant (helper present) shows no notice and never runs the sudo probe",
       _grant_page227(True, True, True)[:2], ([False, False], 0))
    eq("sudo grant: a per-user install (no system service) shows no notice and never runs the sudo probe",
       _grant_page227(False, False, True)[:2], ([False, False], 0))
    eq("sudo grant: no helper and sudo refused (no grant at all) shows no notice",
       _grant_page227(True, False, False)[0], [False, False])


def _cleanup227():
    """Remove this part's rows."""
    with _p9.app_context():
        for rid in _ROWS227:
            row = _db227.session.get(_RS227, rid)
            if row is not None:
                _db227.session.delete(row)
        _db227.session.commit()


try:
    for _section227 in (_adds227, _edits227, _parse227, _docker_pins227, _b3_renovate227, _wide_grant227):
        _arm227()
        try:
            _section227()
        finally:
            _p9_restore_all()
finally:
    _cleanup227()
check("fingerprint: nothing in this part reached a real transport (part12's tripwire)",
      len(_P9_TRIPPED) == _trips227)
