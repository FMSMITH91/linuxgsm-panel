"""Part 285 of the unit suite: review pass 36's security fixes.

1. Discord: both senders cut a long message without splitting what the escaping made: a code block
   or span cut in two is escaped as plain text, and an escape is never cut from its character.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; Discord's HTTP post is a
stand-in. Nothing reaches a host, /etc or data/.
"""
import json as _json285

from unit.part01 import check, eq
from unit.part12 import _p9_patch, _p9_restore_all
from panel.services import notifications as _n285

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
