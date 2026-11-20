"""Part 285 of the unit suite: review pass 36's security fixes.

1. Discord: both senders cut a long message without splitting what the escaping made: a code block
   or span cut in two is escaped as plain text, and an escape is never cut from its character.
2. Settings > HTTPS certificate, Let's Encrypt: the auto-renew switch is saved only with a certificate
   put in, never by a refused request, and the install's audit row names it and a change to it.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; Discord's HTTP post is a
stand-in. Nothing reaches a host, /etc or data/.
"""
import json as _json285
from types import SimpleNamespace as _NS285

from unit.part01 import check, eq
from unit.part12 import P9_ADMIN, _p9_arm, _p9_audit, _p9_client, _p9_patch, _p9_restore_all
from panel.ops import system_ops as _so285
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
