"""Part 285 of the unit suite: review pass 36's security fixes.

1. Discord: both senders cut a long message without splitting what the escaping made: a code block
   or span cut in two is escaped as plain text, and an escape is never cut from its character.
2. Settings > HTTPS certificate, Let's Encrypt: the auto-renew switch is saved only with a certificate
   put in, never by a refused request, and the install's audit row names it and a change to it.
3. The SSH pool: the liveness probe of one host's pooled client runs outside the lock every host's
   connection takes, so a host stalling a key re-exchange holds up only its own callers.
4. World reset reads a LinuxGSM config by an allow-list: a line in any form the reader does not model
   (getopts or wait -p naming a variable from a value, which the old per-construct refusals missed)
   refuses the plan, and the line forms in LinuxGSM's own configs still plan.
5. The helper's entry: an OSError from the checked read (the code file, or a directory on the way, is a
   symlink) refuses, exit 1, and runs nothing; the code file is never read again by its path.
6. The Account page's recent security changes are the account's own, matched by its id: an account
   created with, or renamed to, a freed name is not shown the previous holder's events.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; Discord's HTTP post is a
stand-in; the helper's entry runs over this part's own scratch trees, this account standing in for
root. Nothing reaches a host, /etc or data/.
"""
import datetime as _dt285
import json as _json285
import os
import shutil as _sh285
import tempfile as _tf285
import eventlet as _ev285
from eventlet import event as _evt285, semaphore as _sem285
from types import SimpleNamespace as _NS285

from unit.part01 import check, eq
from unit.part245 import _install245
from unit.part275 import _bash_port275, _vh_plan275
from unit.part284 import _code284, _entry284
from unit.part12 import P9_ADMIN, _p9, _p9_arm, _p9_audit, _p9_client, _p9_patch, _p9_restore_all
from panel.db.models import AuditLog as _Audit285, User as _User285, db as _db285
from panel.security import auth as _auth285
from panel.ops import system_ops as _so285
from panel.ops.ssh_manager import _core as _core285
from panel.routes import tls_cert as _tls285
from panel.services import notifications as _n285, tls_own as _own285

# A webhook and a bot channel of the shapes the senders accept; no request leaves this process.
_HOOK285 = "https://discord.com/api/webhooks/123456/p285"
_BOT285 = "B" * 50
_CHANNEL285 = "112233445566778899"


# ── 1. Discord ────────────────────────────────────────────────────────────────────────────────────
def _discord_bodies285(text):
    """The `content` each sender (webhook, then bot) posts for `text`, through a stand-in _post."""
    sent = []
    _p9_patch(_n285, "_post", lambda url, data, headers, **k: sent.append(_json285.loads(data.decode())) or (True, ""))
    try:
        _n285.send_discord(_HOOK285, text)
        _n285.discord_bot_send(_BOT285, _CHANNEL285, text)
    finally:
        _p9_restore_all()
    return [b["content"] for b in sent]


def _rendered_live285(body):
    """Whether `body` holds markdown Discord would render: an unpaired fence or backtick, or a trailing backslash."""
    plain = _n285._DC_CODE_RE.sub("", body)
    return ("`" in plain.replace("\\`", "")) or (len(body) - len(body.rstrip("\\"))) % 2 == 1


# A code block that starts before the cut and ends after it: cut there, its unescaped content (a masked
# link, a heading) was left behind an opening fence that nothing closed.
_FENCE285 = "x" * 1880 + "```\n[Sign in](https://evil.example/x)\n# Head\n```"
_SPAN285 = "y" * 1890 + "`[Sign in](https://evil.example/x)`"
_ESC285 = "a" * 1899 + "*bold*"
_cut285 = {name: _discord_bodies285(t) for name, t in (("fence", _FENCE285), ("span", _SPAN285), ("escape", _ESC285))}
eq("discord cut: neither sender leaves a code block or span cut open, or a backslash cut from what it escapes",
   {k: [(len(b) <= 1900, _rendered_live285(b)) for b in v] for k, v in _cut285.items()},
   {k: [(True, False)] * 2 for k in _cut285})
check("discord cut: ...a cut block's text is shown escaped (no live masked link), and the text before it is kept",
      all(b.startswith("x" * 1880 + "\\`\\`\\`\n\\[Sign in\\]") for b in _cut285["fence"])
      and all(b == "a" * 1899 for b in _cut285["escape"]), repr([b[-40:] for v in _cut285.values() for b in v]))
_short285 = _discord_bodies285("`!status` and ```\n[x](y)\n``` *p285*")
eq("discord cut (control): a message that fits keeps its code as code and is escaped as before",
   _short285, ["`!status` and ```\n[x](y)\n``` \\*p285\\*"] * 2)


# ── 2. The Let's Encrypt auto-renew switch ────────────────────────────────────────────────────────
_CFG285 = {}
_PUT285 = []


def _le_post285(form, fetched=("", ""), refusal=""):
    """POST the Let's Encrypt form with the copy's outcome as given: (the switch saved, installs, last audit).

    `fetched` is fetch_letsencrypt's (chain, why); `refusal` what the check says of the copy. The
    config is a dict, the copy, check, install and restart stand-ins: nothing is written or restarted.
    """
    _CFG285.clear()
    _CFG285.update({"tls_le_autorenew": True})
    _PUT285.clear()
    _p9_arm(who="part285")
    for mod in (_own285, _tls285):
        _p9_patch(mod, "load_config", lambda: dict(_CFG285))
        _p9_patch(mod, "update_config", lambda mutate: mutate(_CFG285))
    chain, why = fetched
    _p9_patch(_own285, "fetch_letsencrypt", lambda name: (chain, b"p285-key", why))
    _p9_patch(_own285, "check", lambda c, k, names: _NS285(refusal=refusal, notes=[], chain=["p285-leaf"]))
    _p9_patch(_own285, "install", lambda checked, source, le_name="": _PUT285.append((source, le_name)))
    _p9_patch(_own285, "summary", lambda c: {"subject": "panel.example.com", "issuer": "p285 CA",
                                             "not_after": "2027-01-01", "fingerprint": "ab" * 32})
    _p9_patch(_so285, "restart_panel", lambda delay_seconds=2: (True, "ok"))
    try:
        r = _p9_client(P9_ADMIN).post("/settings/tls/letsencrypt", data=dict(form, le_name="panel.example.com"))
        last = _p9_audit("tls_cert_install")
        return r.status_code, _CFG285.get("tls_le_autorenew"), list(_PUT285), last.id, last.detail
    finally:
        _p9_restore_all()


_le_before285 = _p9_audit("tls_cert_install").id
_le_nocopy285 = _le_post285({}, fetched=(b"", "p285: no such certificate"))
_le_badcopy285 = _le_post285({}, fetched=(b"p285-chain", ""), refusal="p285: the key is not the certificate's")
eq("tls auto-renew: a request refused (no copy, or a copy the check refuses) leaves the switch as it was and "
   "installs nothing", [(st, saved, put, last == _le_before285) for st, saved, put, last, _d in
                        (_le_nocopy285, _le_badcopy285)], [(302, True, [], True)] * 2)
_le_off285 = _le_post285({}, fetched=(b"p285-chain", ""))
_le_same285 = _le_post285({"le_autorenew": "on"}, fetched=(b"p285-chain", ""))
eq("tls auto-renew: with a certificate put in, the switch is saved, and the install's audit row names it and "
   "says when it changed", [(saved, put, detail.rsplit(", ", 1)[-1]) for _s, saved, put, _l, detail in
                            (_le_off285, _le_same285)],
   [(False, [("letsencrypt", "panel.example.com")], "auto-renew turned off"),
    (True, [("letsencrypt", "panel.example.com")], "auto-renew on")])


# ── 3. The SSH pool's liveness probe ─────────────────────────────────────────────────────────────
class _Transport285:
    """A pooled client's transport: send_ignore waits on `gate` (a stalled key re-exchange) when given."""

    def __init__(self, gate=None):
        self.gate = gate

    def is_active(self):
        return True

    def send_ignore(self):
        if self.gate is not None:
            self.gate.wait()


class _Client285:
    def __init__(self, gate=None):
        self.transport = _Transport285(gate)

    def get_transport(self):
        return self.transport

    def close(self):
        """Nothing to close: no socket was opened."""


def _host285(name):
    return _NS285(id=None, username="p285", host=name, port=22, auth_method="password", is_local=False)


def _pool_probe285():
    """(the quick host's client while the stalled host's probe waits, the stalled host's client afterwards).

    The stalled host's probe waits on an event set only after the quick host's lookup has had two
    seconds: through the lock, the quick lookup would wait for the whole stall.
    """
    gate = _evt285.Event()
    slow, quick = _Client285(gate), _Client285()
    keys = [_core285._conn_key("p285", h, 22) for h in ("p285-stalled.example", "p285-quick.example")]
    _p9_patch(_core285, "_conn_lock", _sem285.Semaphore(1))
    _p9_patch(_core285, "_open_client", lambda server: (_ for _ in ()).throw(ConnectionError("p285: no new client")))
    _core285._connections.update(zip(keys, (slow, quick)))
    got = None
    try:
        stalled = _ev285.spawn(_core285.get_connection, _host285("p285-stalled.example"))
        _ev285.sleep(0)
        with _ev285.Timeout(2, False):
            got = _core285.get_connection(_host285("p285-quick.example"))
        gate.send(True)
        return got is quick, stalled.wait() is slow
    finally:
        if not gate.ready():
            gate.send(True)
        for k in keys:
            _core285._connections.pop(k, None)
        _p9_restore_all()


eq("ssh pool: a host whose pooled connection stalls (a key re-exchange it never finishes) does not hold up "
   "another host's connection, and its own caller still gets its client", _pool_probe285(), (True, True))


class _DeadTransport285(_Transport285):
    def is_active(self):
        return False


def _pool_dead285():
    """(the client get_connection answers, what the pool holds after) for a pooled client whose transport is dead."""
    dead, fresh = _Client285(), _Client285()
    dead.transport = _DeadTransport285()
    key = _core285._conn_key("p285", "p285-dead.example", 22)
    _p9_patch(_core285, "_open_client", lambda server: fresh)
    _p9_patch(_core285, "_keep_warm", lambda client: None)
    _core285._connections[key] = dead
    try:
        got = _core285.get_connection(_host285("p285-dead.example"))
        return got is fresh, _core285._connections.get(key) is fresh
    finally:
        _core285._connections.pop(key, None)
        _p9_restore_all()


eq("ssh pool (control): a pooled client whose transport is dead is dropped and replaced by a new one",
   _pool_dead285(), (True, True))


# ── 4. World reset's config reader ───────────────────────────────────────────────────────────────
# Each sets port through a variable named by another value, with no line spelling `port=`: builtins
# that write the variable they are given (getopts, bash 5.1's wait -p) were not among the commands the
# old per-construct refusals listed.
_UNMODELLED285 = ('p="port"\ngetopts "a" "$p"\n', 'p="port"\ntrue & wait -p "$p"\n')
eq("world reset allow-list: bash changes port through each of these configs (bash itself)",
   [_bash_port275(c) != "2456" for c in _UNMODELLED285], [True] * len(_UNMODELLED285))
eq("world reset allow-list (the caller): Valheim's plan is refused for each, saying the line is not a plain "
   "assignment", [(plan, "not a plain assignment" in str(why)) for plan, why in map(_vh_plan275, _UNMODELLED285)],
   [(None, True)] * len(_UNMODELLED285))
# Line forms taken from LinuxGSM's own config-default files (lgsm/config-default/config-lgsm/*/_default.cfg);
# qlserver's $(…) line sets executable there, a key this plan reads in the plain form only, so it sets
# another name here.
_LGSM_LINES285 = (
    '[ -n "${LGSM_LOGDIR}" ] && logdir="${LGSM_LOGDIR}" || logdir="${rootdir}/log"\n'
    "steampass=''\n"
    'serverbin=$([ "$(uname -m)" == "x86_64" ] && echo -e "./run_server_x64.sh" || echo -e "./run_server_x86.sh")\n'
    'workshoploadmods="${workshopmods:+ -workshop \'${workshopmods}\'}"\n'
    'backupdate="$(date \'+%Y-%m-%d-%H:%M:%S\')"\n'
    'serverpassword="" # Minimum password length is 5.\n')
_lgsm285 = _vh_plan275(_LGSM_LINES285)
check("world reset allow-list (control): Valheim's plan is still made beside the line forms LinuxGSM's own configs "
      "use (a [ -n ] test, single quotes, $(…), ${x:+…} with quotes inside, a trailing comment)",
      bool(_lgsm285[0]) and _lgsm285[1] is None, repr(_lgsm285)[:300])


# ── 5. The helper's entry: an OSError from the checked read ──────────────────────────────────────
_T285 = _tf285.mkdtemp(prefix="lgsm-unit-p285-")


def _entry_tree285(name):
    """A tree install_helper_code filled with a stand-in helper: (top, lib, the marker it creates when run)."""
    top = os.path.join(_T285, name)
    lib = os.path.join(top, "lib")
    os.makedirs(lib)
    marker = os.path.join(top, "ran")
    helper = os.path.join(top, "stand-in-helper")
    with open(helper, "w", encoding="utf-8") as fh:
        fh.write(_code284(marker, "RAN285"))
    _install245(lib, helper)
    return top, lib, marker


def _entry_oserror285():
    """{case: (rc, ran, a marker made, "could not be read" said)} for a code file and a directory that are links.

    "code link": panel-helper-code.py is a link to planted code (which makes its own marker) and its pyc
    is gone. "dir link": the entry is given a directory on the way that links to the real one. The
    checked read opens with O_NOFOLLOW, so each is an OSError (ELOOP); read again by its path, the
    code would run.
    """
    got = {}
    top, lib, marker = _entry_tree285("code-link")
    planted = os.path.join(top, "planted.py")
    with open(planted, "w", encoding="utf-8") as fh:
        fh.write(_code284(os.path.join(top, "planted-ran"), "PLANTED285"))
    os.remove(os.path.join(lib, "panel-helper-code.pyc"))
    os.remove(os.path.join(lib, "panel-helper-code.py"))
    os.symlink(planted, os.path.join(lib, "panel-helper-code.py"))
    rc, out, err = _entry284(top, lib)
    got["code link"] = (rc, bool(out.strip()), os.path.exists(marker) or os.path.exists(os.path.join(top, "planted-ran")),
                        "could not be read" in err)
    top, lib, marker = _entry_tree285("dir-link")
    os.symlink(lib, os.path.join(top, "lib-link"))
    rc, out, err = _entry284(top, os.path.join(top, "lib-link"))
    got["dir link"] = (rc, bool(out.strip()), os.path.exists(marker), "could not be read" in err)
    rc, out, _err = _entry284(top, lib)
    got["control"] = (rc, out.strip(), os.path.exists(marker))
    return got


try:
    _eo285 = _entry_oserror285()
finally:
    _sh285.rmtree(_T285, ignore_errors=True)
eq("helper entry: a code file, or a directory on the way, that is a link fails the checked read (OSError): "
   "exit 1, saying it could not be read, and neither the code nor what the link names runs",
   {k: v for k, v in _eo285.items() if k != "control"},
   {"code link": (1, False, False, True), "dir link": (1, False, False, True)})
eq("helper entry (control): the same tree read through its real directory runs the code", _eo285["control"],
   (0, "RAN285", True))


# ── 6. Recent security changes, by account ───────────────────────────────────────────────────────
# A stored hash no password matches: these accounts are only signed in through the test client.
_NOHASH285 = "!p285"


def _ago285(minutes):
    """Now plus `minutes`, as the audit log and the user table store a time (naive UTC)."""
    return _dt285.datetime.now(_dt285.timezone.utc).replace(tzinfo=None) + _dt285.timedelta(minutes=minutes)


def _user285(name, created=0):
    """A new account named `name`, created `created` minutes from now; its id."""
    with _p9.app_context():
        u = _User285(username=name, password_hash=_NOHASH285, display_name=name, is_active=True,
                     created_at=_ago285(created))
        _db285.session.add(u)
        _db285.session.commit()
        return u.id


def _drop_user285(uid):
    with _p9.app_context():
        u = _db285.session.get(_User285, uid)
        if u is not None:
            _db285.session.delete(u)
            _db285.session.commit()


def _audit_as285(uid, action):
    """The real writer's row for `action` on account `uid`, as its own route writes it (target: the username)."""
    with _p9.app_context():
        u = _db285.session.get(_User285, uid)
        _auth285.log_action(u, action, target=u.username)


def _legacy285(name, action, minutes):
    """A row from before AuditLog.target_user_id existed (no id), `minutes` from now, about the name `name`."""
    with _p9.app_context():
        _db285.session.add(_Audit285(username=name, action=action, target=name, success=True, ip_address="192.0.2.85",
                                     timestamp=_ago285(minutes)))
        _db285.session.commit()


def _shown285(uid):
    """The labels of the Account page's "Recent security changes" for account `uid`."""
    page = _p9_client(uid).get("/account").get_data(as_text=True)
    _head, _sep, rest = page.partition('id="acct-changes"')
    return [] if not _sep else [li.split("</span>")[0] for li in rest.split("</ul>")[0].split("<li><span>")[1:]]


def _rename285(uid, name):
    """Rename account `uid` to `name` through the Users page's edit route; its status."""
    return _p9_client(P9_ADMIN).post("/users/%d/edit" % uid, data={"username": name, "is_active": "on",
                                                                 "display_name": "p285 renamed"},
                                     headers={"X-Requested-With": "XMLHttpRequest"}).status_code


def _account_history285():
    got = {}
    _p9_arm(who="part285")
    first = _user285("p285-alice")
    made = [first]
    try:
        _audit_as285(first, "password_changed")
        got["own"] = _shown285(first)
        _drop_user285(first)
        _legacy285("p285-alice", "2fa_disabled", -30)       # the old holder's, from before the column
        again = _user285("p285-alice")
        made.append(again)
        got["recreated"] = _shown285(again)
        bob = _user285("p285-bob", created=-60)            # older than carol's row: only the rename bounds it
        made.append(bob)
        _legacy285("p285-carol", "password_changed", -30)   # a deleted carol's, from before the column
        got["renamed"] = (_rename285(bob, "p285-carol"), _shown285(bob))
        _legacy285("p285-carol", "2fa_enabled", 1)           # written since bob holds the name
        got["legacy since"] = _shown285(bob)
        dave = _user285("p285-dave")
        made.append(dave)
        _audit_as285(dave, "password_changed")
        got["own renamed"] = (_rename285(dave, "p285-dave2"), _shown285(dave))
        return got
    finally:
        _p9_restore_all()
        for uid in made:
            _drop_user285(uid)


_hist285 = _account_history285()
eq("account history: an account created with a freed name, or renamed to one, is not shown the previous "
   "holder's security events (by id, and an older row only since the account took the name)",
   (_hist285["recreated"], _hist285["renamed"]), ([], (200, [])))
eq("account history (control): an account's own events are shown, by id and from an older row written since it "
   "took the name, and still after it is renamed", (_hist285["own"], _hist285["legacy since"], _hist285["own renamed"]),
   (["Password changed"], ["Two-factor authentication turned on"], (200, ["Password changed"])))
