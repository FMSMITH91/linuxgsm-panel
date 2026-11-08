"""Part 157 of the unit suite: the twenty-fifth review's page-script and test-gate fixes (builder D).

Held here, each against the code path the finding named:

* the Mods section of Files & Config for a game with no LinuxGSM mods: it says so, instead of
  "Loading mods…" for good under its own tab.

HOW IT RUNS. Scripts in node on this part's own fixtures (part87's DOM stand-in, part99's runner).
"""
from unit.part01 import check
from unit.part99 import _SF99, _js99


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The Mods section for a game with no LinuxGSM mods installer
# ════════════════════════════════════════════════════════════════════════════════════════════════
# #483 split Files & Config into sections: _uis_sfShow sets the chosen section's cards to
# display:''. The unsupported answer hid the whole card with the same property, so opening the
# Mods tab (always there) showed the card again with "Loading mods…", and nothing replaced it.
_name157 = "mods: a game with no LinuxGSM mods"
_out157 = _js99(_name157, (
    "var serverId = 1; function _tr(s){ return s; } function esc(s){ return escapeHtml(s); }\n"
    "function modsMsg(){}\n"), ("function modLabel(", "function modRow(", "function _r26c_modsDraw(",
                                "function loadMods("), (
    "  const out = {}, card = document.getElementById('mods-card');\n"
    "  const load = document.getElementById('mods-loading'), body = document.getElementById('mods-body'),\n"
    "    uns = document.getElementById('mods-unsupported');\n"
    "  for (const [k, d] of [['none', {supported: false}], ['some', {available: [{id: 'm1', name: 'M'}],\n"
    "                                                                installed: []}]]) {\n"
    "    card.style.display = ''; load.style.display = ''; body.style.display = 'none';\n"
    "    uns.style.display = 'none';\n"
    "    reply(d); const drew = await loadMods(true);\n"
    "    out[k] = {drew, card: card.style.display, load: load.style.display, body: body.style.display,\n"
    "              uns: uns.style.display}; }\n"
    "  console.log(JSON.stringify(out));\n"), _SF99)
if _out157 is not None:
    check("mods: a game with no LinuxGSM mods installer gets the card's own \"doesn't have any mods\" "
          "line, the loading line hidden, and the card left to the section tabs (it hid the card, which "
          "the Mods tab showed again with \"Loading mods…\" for good)",
          _out157.get("none") == {"drew": True, "card": "", "load": "none", "body": "none", "uns": ""},
          repr(_out157))
    check("mods: ...while a game with mods still draws its rows",
          _out157.get("some") == {"drew": True, "card": "", "load": "none", "body": "", "uns": "none"},
          repr(_out157))
