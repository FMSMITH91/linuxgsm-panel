"""Part 161 of the unit suite: the twenty-sixth review's console and branch-switch fixes (builder C).

Held here, each against the code path the finding named:

* the console keeps the OLD log's last lines that land while a replacing read is out. The poller can
  push them after the re-prime's (or Load older's) read began and before the host's read saw the
  new log (a Restart's `mv` falling inside the read): they were wiped with nothing to bring them
  back, and Load older put them back by their text BELOW the new log. The page's own functions run
  in node on part158's stand-in console, with the real _rebuild* helpers in place of its no-ops.
* the local echo of a command sent while the page stands nowhere in the log (after Load older, a poll
  while the socket is down) was untagged, so a read after a Restart wiped it; it now takes the log of
  the page's newest line.
* "Switch to main" with no signed release among the walked commits (unsigned, or no release key, or
  the signatures could not be fetched) said none of them "passed its automated checks", though none
  was judged by them. It now says none is a signed release this host could verify, in es/fr too;
  signed commits that failed CI still get the old answer.
"""
import json as _json161

from panel.core import i18n as _i18n161
from panel.ops import system_ops as _so161
from unit.part01 import check, skip
from unit.part12 import _p9_patch, _p9_restore_all
from unit.part47 import _cut47, _node47
from unit.part158 import _DOM158, _FUNCS158, _SD158

# The pushes a replacing read puts back (Load older), real here: part158 stands them in as no-ops,
# and a later function declaration of the same name wins.
_REBUILD161 = ("function _rebuildNotePush(", "function _rebuildMark(", "function _rebuildHasRun(",
               "function _rebuildRestore(")


def _harness161():
    """part158's console functions plus the real _rebuild* ones, after its stand-ins; None if one is gone."""
    heads = _FUNCS158 + _REBUILD161
    if any(h not in _SD158 for h in heads):
        return None
    parts = [_cut47(_SD158, h) + (");" if h.startswith("socket.on(") else "") for h in heads]
    return (_DOM158 + "var _rebuildPushes = [], _rebuildSeq = 0, _REBUILD_KEEP = 2000;\n"
            + "\n".join(parts) + "\n")


_PROG161 = (
    "(async () => { const out = {};\n"
    # Primed from the log (inode 11), a push goes on in it; Clear empties the page.
    "  answer({lines: rows(['a1', 'a2']), at: [0, 11, 20]}); refreshConsole(true); await settle();\n"
    "  push(['a3'], [1, 11, 30]); clearConsole();\n"
    # The re-prime's read goes out with nothing on the page; the old log's last lines land while
    # it is out, then the host's read sees the new log (inode 12).
    "  refreshConsole(false); push(['b1', 'b2'], [1, 11, 50]);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'c1']), at: [0, 12, 20]}); await settle();\n"
    "  out.empty = shown(); out.emptyLines = _consoleLines.slice();\n"
    # The same with an old-log line already on the page when the read went out.
    "  push(['c2'], [2, 12, 30]); clearConsole(); push(['c3'], [2, 12, 40]); refreshConsole(false);\n"
    "  push(['c4'], [2, 12, 50]);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'd1']), at: [0, 13, 20]}); await settle();\n"
    "  out.held = shown();\n"
    # Load older while the server restarts: the old log's last line, then a line of the new log the
    # window also holds, both land while the read is out.
    "  push(['d2'], [3, 13, 30]); loadMoreConsole(null);\n"
    "  push(['d3'], [3, 13, 40]); push(['e2'], [4, 14, 30]);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'e1', 'e2']), at: [0, 14, 30]}); await settle();\n"
    "  out.older = shown(); out.olderAt = _logAt;\n"
    # Load older again: the page stands nowhere in the log now (a window does not say where each of
    # its lines ends), so the log it knew is the one its lines came from.
    "  loadMoreConsole(null); push(['e3'], [5, 14, 40]);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'f1']), at: [0, 15, 20]}); await settle();\n"
    "  out.again = shown(); out.againAt = _logAt;\n"
    # A command sent while the page stands nowhere in the log, then a Restart, then Load older: its
    # echo is of the log the page's lines came from, so it stays with them.
    "  send('ping'); push(['[ INFO ] Restarting', 'g1'], [6, 16, 20]); loadMoreConsole(null);\n"
    "  answer({lines: rows(['[ INFO ] Restarting', 'g1', 'g2']), at: [0, 16, 30]}); await settle();\n"
    "  out.echo = shown().slice(-6);\n"
    "  console.log(JSON.stringify(out)); })();\n")

_h161 = _harness161()
check("console r38c: the functions part161 runs are all still in server_detail.js", _h161 is not None,
      [h for h in _FUNCS158 + _REBUILD161 if h not in _SD158])
_out161 = _node47(_h161 + _PROG161) if _h161 is not None else None
if _h161 is not None and _out161 is None:
    skip("console r38c: the old log's lines that land while a replacing read is out", "node is not installed here")
elif _out161 is not None:
    check("console r38c: after Clear, the old log's last lines that land while the re-prime's read is "
          "out stay above the new log's window (they were wiped for good)",
          _out161.get("empty") == ["b1", "b2", "[ INFO ] Restarting", "c1"]
          and _out161.get("emptyLines") == ["b1", "b2", "[ INFO ] Restarting", "c1"],
          _json161.dumps(_out161))
    check("console r38c: ...and with a line of that log already on the page, its next line that lands "
          "during the read stays with it (it was wiped)",
          _out161.get("held") == ["c3", "c4", "[ INFO ] Restarting", "d1"], _json161.dumps(_out161))
    check("console r38c: Load older while the server restarts keeps the old log's last line above the "
          "new log, once, and the new log's line once (it was put back below the new log)",
          _out161.get("older") == ["c3", "c4", "[ INFO ] Restarting", "d1", "d2", "d3",
                                   "[ INFO ] Restarting", "e1", "e2"],
          _json161.dumps(_out161))
    check("console r38c: ...and Load older again, the page standing nowhere in the log, keeps the line "
          "of the log its lines came from that lands during the read (it was wiped)",
          _out161.get("olderAt") is None
          and _out161.get("again") == ["c3", "c4", "[ INFO ] Restarting", "d1", "d2", "d3",
                                       "[ INFO ] Restarting", "e1", "e2", "e3", "[ INFO ] Restarting", "f1"],
          _json161.dumps(_out161))
    check("console r38c: a command sent while the page stands nowhere in the log (after Load older) keeps "
          "its echo through a Restart and the next Load older (it was untagged and wiped)",
          _out161.get("againAt") is None
          and _out161.get("echo") == ["[ INFO ] Restarting", "f1", "> ping", "[ INFO ] Restarting", "g1", "g2"],
          _json161.dumps(_out161))

# ── The branch switch's answer when no walked commit is a signed release ─────────────────────────
_C161 = ("a3" * 20, "a2" * 20, "a1" * 20)


def _git161(args, timeout=45):
    del timeout
    return (" ".join(_C161), "", 0) if args[:2] == ["rev-list", "--first-parent"] else ("", "", 0)


def _gate161(signed):
    """A _release_gate_for stand-in: a commit is a signed release when it is in `signed`."""
    return lambda branch: (lambda sha: sha in signed)


_sw161 = {}
try:
    _p9_patch(_so161, "_git", _git161)
    _p9_patch(_so161, "_remote_ci_state", lambda sha: "failing")
    for _k161, _signed161 in (("unsigned", frozenset()), ("failing", frozenset(_C161))):
        _p9_patch(_so161, "_release_gate_for", _gate161(_signed161))
        _sw161[_k161] = _so161._verified_branch_target("main")
finally:
    _p9_restore_all()
_why161 = _sw161.get("unsigned", ("x", ""))[1]
check("branch switch r38c: with no signed release among main's recent commits the switch says none is a "
      "signed release this host could verify, not that none passed its automated checks (none was judged)",
      _sw161.get("unsigned", ("x",))[0] == "" and "is a signed release this host could verify" in _why161
      and "automated checks" not in _why161, repr(_sw161))
check("branch switch r38c: ...and a Spanish or French viewer reads it in their language",
      isinstance(_why161, _i18n161.Sentence)
      and _i18n161.fill(_i18n161.translate("es", _why161.template), **_why161.vals).startswith(
          "No se cambió: ninguna de las versiones recientes de 'main' es una versión firmada")
      and _i18n161.fill(_i18n161.translate("fr", _why161.template), **_why161.vals).startswith(
          "Non basculé : aucune des versions récentes de « main » n'est une version signée"),
      repr(_why161))
check("branch switch r38c: ...while signed commits that failed their checks still say none passed (control)",
      _sw161.get("failing", ("x",))[0] == "" and "passed its automated checks" in _sw161["failing"][1],
      repr(_sw161))
