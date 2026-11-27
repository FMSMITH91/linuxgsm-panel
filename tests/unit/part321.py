"""Part 321 of the unit suite: CI's apt step, the tunnel's closed ports.

1. CI: the unit legs' apt step takes the runner image's own packages.microsoft.com source out of apt's list before
   `apt-get update` (that repository answered 403 and failed the whole leg), and only that source; the step's own
   loop is run over a scratch sources folder.
2. Tunnel mode closes ports 80 and 443 whatever becomes of the tunnel: a token the provider refuses ended the apply
   before its firewall step, and the public rules stayed open while the saved mode said tunnel. The answer says so.

HOW IT RUNS. part12's app and its database for the routes; every host call at ssh_manager's seams (part12's
tripwire is armed, so nothing reaches a host). The workflow is read as text (part06's run-block reader).
"""
import os
import shutil as _shutil321
import subprocess as _sp321  # nosec B404 - bash over the workflow's own loop, in a scratch folder
import tempfile as _tf321
from types import SimpleNamespace as _NS321

from flask import g as _g321

from unit.part01 import _root, check, eq
from unit.part06 import _wf_run_block
from unit.part12 import _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_restore_all
from panel.core import config as _cfg321
from panel.core.clock import utcnow as _utcnow321
from panel.db.models import (RemoteServer as _Remote321, User as _User321, Website as _Site321,
                             WebsiteDomain as _Dom321, WebsiteProxy as _Proxy321, db as _db321)
from panel.ops.ssh_manager import websites as _sw321
from panel.routes import websites as _w321

_TOKEN321 = "k" * 40
_ROWS321 = {"sites": [], "remotes": [], "users": []}
_REC321 = {"ports": [], "apply": []}
# The sentence a failed tunnel-mode apply ends with, pinned as written (a revert of the fix has no such name).
_CLOSED321 = "Ports 80 and 443 are closed: in tunnel mode visitors come in only through the tunnel."


class _Client321:
    def __init__(self, uid):
        self.c = _p9_client(uid)

    def post(self, *a, **k):
        _g321.pop("_login_user", None)
        return self.c.post(*a, **k)

    def get(self, *a, **k):
        _g321.pop("_login_user", None)
        return self.c.get(*a, **k)


def _rows321():
    r = _Remote321(name="p321-host", host="127.0.0.1", port=22, username="u", auth_method="key", auth_credential="",
                   is_local=True, public_ip="198.51.100.121")
    su = _User321(username="p321-super", password_hash=os.urandom(8).hex(), is_superadmin=True, is_active=True)
    _db321.session.add_all([r, su])
    _db321.session.commit()
    _ROWS321["remotes"].append(r.id)
    _ROWS321["users"].append(su.id)
    return _NS321(host=r, su=su)


def _site321(st, name, kind="static", **kw):
    extra = {"php_version": "8.4"} if kind in ("php", "wordpress") else {}
    s = _Site321(remote_id=st.host.id, name=name, kind=kind, state="running",
                 proxy_secret=_cfg321.encrypt_secret(_TOKEN321), **dict(extra, **kw))
    _db321.session.add(s)
    _db321.session.flush()
    s.account, s.port = "ws%d" % s.id, 20500 + s.id % 400
    _db321.session.add(_Dom321(website_id=s.id, domain="%s.example.org" % name, is_primary=True,
                               verified_at=_utcnow321(), dns_state="matching"))
    _db321.session.commit()
    _ROWS321["sites"].append(s.id)
    return s


# ── 1. CI: apt without the runner image's Microsoft source ────────────────────────────────────────
_APT_STEP321 = "Install zsh and systemd-journal-remote"


def _apt_body321():
    with open(os.path.join(_root, ".github", "workflows", "ci.yml"), encoding="utf-8") as fh:
        return _wf_run_block(fh.read(), _APT_STEP321)


def _apt_loop321(body):
    """The step's lines from its `for src in` loop to its `done`, or "" when it has none."""
    lines = body.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("for src in /etc/apt/sources.list.d/")), None)
    if start is None:
        return ""
    end = next((i for i in range(start, len(lines)) if lines[i].strip() == "done"), None)
    return "\n".join(lines[start:end + 1]) + "\n" if end is not None else ""


def _s1_ci():
    body = _apt_body321()
    code = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    upd = next((i for i, ln in enumerate(code) if "apt-get update" in ln), -1)
    loop_at = next((i for i, ln in enumerate(code) if ln.startswith("for src in /etc/apt/sources.list.d/")), -1)
    eq("CI (ci.yml, the unit legs' apt step): a loop over apt's source files runs BEFORE `apt-get update`",
       (loop_at >= 0, upd >= 0, 0 <= loop_at < upd), (True, True, True))
    d = _tf321.mkdtemp(prefix="lgsm-unit-p321-apt-")
    try:
        src, aside = os.path.join(d, "sources.list.d"), os.path.join(d, "aside")
        os.makedirs(src)
        os.makedirs(aside)
        files = {"microsoft-prod.list": "deb [arch=amd64,armhf,arm64] https://packages.microsoft.com/ubuntu/24.04/prod "
                                        "noble main\n",
                 "azure-cli.sources": "Types: deb\nURIs: https://packages.microsoft.com/repos/azure-cli/\n",
                 "ubuntu.sources": "Types: deb\nURIs: http://azure.archive.ubuntu.com/ubuntu/\nSuites: noble\n",
                 "esm.list": "deb https://esm.ubuntu.com/apps/ubuntu noble-apps-security main\n"}
        for name, text in files.items():
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        loop = _apt_loop321(body).replace("/etc/apt/sources.list.d", src).replace("sudo ", "")
        r = _sp321.run(["bash", "-c", loop], env={"PATH": os.environ.get("PATH", ""), "RUNNER_TEMP": aside},
                       capture_output=True, text=True, timeout=60, check=False)  # nosec B603 B607 - bash, fixed
        got = (r.returncode, sorted(os.listdir(src)), sorted(os.listdir(aside)))
    finally:
        _shutil321.rmtree(d, ignore_errors=True)
    eq("CI (the step's own loop, run over a scratch sources folder): every source file naming packages.microsoft.com "
       "(one-line and deb822) is moved out of apt's list; the Ubuntu archive's and Ubuntu Pro's stay (control)",
       got, (0, ["esm.list", "ubuntu.sources"], ["azure-cli.sources", "microsoft-prod.list"]))


# ── 2. Tunnel mode closes the public ports ────────────────────────────────────────────────────────
def _seams321(tunnel_answer):
    def ports(remote, proxy, enabled):
        _REC321["ports"].append((proxy.exposure_mode, _sw321.wanted_rules(proxy, enabled)))
        return True, _sw321.OK_PORTS

    def apply(remote, text, sites=(), proxy=None, start_it=False):
        _REC321["apply"].append(text)
        return True, _sw321.OK_APPLIED
    _p9_patch(_sw321, "ports_apply", ports)
    _p9_patch(_sw321, "proxy_apply", apply)
    _p9_patch(_sw321, "proxy_stop", lambda *a, **k: (True, _sw321.OK_PROXY_STOPPED))
    _p9_patch(_sw321, "tunnel_apply", lambda *a, **k: tunnel_answer)


def _save321(st, exposure):
    _REC321["ports"], _REC321["apply"] = [], []
    r = _Client321(st.su.id).post("/websites/proxy/settings", json={"host_id": st.host.id, "exposure": exposure})
    row = _Proxy321.query.filter_by(remote_id=st.host.id).first()
    _db321.session.refresh(row)
    return r, row


def _s2_tunnel(st):
    _site321(st, "p321-tun", enabled=True)
    _seams321((True, _sw321.OK_TUNNEL))
    r, _row = _save321(st, {"exposure_mode": "public"})
    eq("tunnel ports (control, POST /websites/proxy/settings in public mode): ports 80 and 443 open to everyone, the "
       "proxy applied, no word of closed ports",
       (r.status_code, _REC321["ports"], len(_REC321["apply"]), _CLOSED321 in (_p9_json(r).get("message") or "")),
       (200, [("public", [(None, "80"), (None, "443")])], 1, False))
    _seams321((False, _sw321.TUNNEL_REFUSED))
    r, row = _save321(st, {"exposure_mode": "tunnel", "tunnel_provider": "cloudflare", "tunnel_token": "t" * 60})
    msg = _p9_json(r).get("message") or ""
    eq("tunnel ports (POST /websites/proxy/settings to tunnel mode with a token the provider refuses): the public "
       "rules are taken away all the same (the firewall wants none in tunnel mode), the answer says why it failed AND "
       "that the ports are closed, and last_error keeps the tunnel's own sentence alone",
       (r.status_code, _REC321["ports"], msg.startswith(_sw321.TUNNEL_REFUSED), msg.endswith(_CLOSED321),
        row.exposure_mode, row.last_error),
       (502, [("tunnel", [])], True, True, "tunnel", _sw321.TUNNEL_REFUSED))
    _seams321((False, _sw321.TUNNEL_REFUSED))
    r = _Client321(st.su.id).post("/websites/proxy/apply", json={"host_id": st.host.id})
    eq("tunnel ports (POST /websites/proxy/apply in tunnel mode, the token still refused): the ports are closed again "
       "and the answer says so", (r.status_code, [m for m, _w in _REC321["ports"]][-1:],
                                  (_p9_json(r).get("message") or "").endswith(_CLOSED321)),
       (502, ["tunnel"], True))


# ── running it ────────────────────────────────────────────────────────────────────────────────────
def _cleanup321():
    _db321.session.rollback()
    remotes = _ROWS321["remotes"] or [0]
    sites = set(_ROWS321["sites"]) | {s.id for s in _Site321.query.filter(_Site321.remote_id.in_(remotes)).all()}
    for d in _Dom321.query.filter(_Dom321.website_id.in_(sorted(sites) or [0])).all():
        _db321.session.delete(d)
    for model in (_Proxy321,):
        for p in model.query.filter(model.remote_id.in_(remotes)).all():
            _db321.session.delete(p)
    for model, ids in ((_Site321, sorted(sites)), (_User321, _ROWS321["users"]), (_Remote321, _ROWS321["remotes"])):
        for i in ids:
            row = _db321.session.get(model, i)
            if row is not None:
                _db321.session.delete(row)
    _db321.session.commit()


def _ran321(step, *args):
    """Run one section: True when it ran to the end, else False (the traceback kept in _ran321.last)."""
    import traceback
    try:
        step(*args)
        _ran321.last = ""
        return True
    except Exception:  # noqa: BLE001 - a section that raises is reported by name and the rest still run
        _db321.session.rollback()
        _ran321.last = traceback.format_exc()[-1500:]
        return False


_ran321.last = ""
_trips321 = len(_P9_TRIPPED)
check("part321: _s1_ci ran to the end", _ran321(_s1_ci), _ran321.last)
with _p9.app_context():
    try:
        _p9_arm(who="part321")
        _st321 = _rows321()
        for _sec321 in (_s2_tunnel,):
            check("part321: %s ran to the end" % _sec321.__name__, _ran321(_sec321, _st321), _ran321.last)
        eq("part321: nothing reached a host (part12's tripwire)", _P9_TRIPPED[_trips321:], [])
    finally:
        _p9_restore_all()
        _w321._STATUS.clear()
        _cleanup321()
