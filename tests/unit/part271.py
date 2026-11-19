"""Part 271 of the unit suite: test-only fixes of review pass 33.

1. The i18n catalog gate looks a shown text up exactly as i18n.js does: a plain text is never
   covered by a status-marked key, nor one mark by another.
2. The workflow readers the CI gates share see every job id GitHub accepts (digits, underscores,
   capitals, quotes, a trailing comment), and the Harden-Runner reader every allowed host.

Nothing here reaches a host.
"""
import json as _json271
import os
import sys as _sys271
import tempfile as _tf271

from unit.part01 import check, eq
from unit.part05 import _root
from unit.part29 import _job29, _jobs29
from unit.part223 import _egress223


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The catalog gate reads a text the way i18n.js looks it up, mark and all
# ════════════════════════════════════════════════════════════════════════════════════════════════
_sys271.path.insert(0, os.path.join(_root, "tools"))
try:
    import i18n_scan as _scan271
finally:
    _sys271.path.remove(os.path.join(_root, "tools"))


def _mark_gate271():
    """The JS gate over a fixture whose only keys carry a check mark."""
    with _tf271.TemporaryDirectory(prefix="p271i-") as td:
        js, tr = os.path.join(td, "js"), os.path.join(td, "tr")
        os.makedirs(js)
        os.makedirs(os.path.join(tr, "es"))
        with open(os.path.join(js, "a.js"), "w", encoding="utf-8") as fh:
            fh.write("msg('Your settings were saved','x');\n"
                     "msg('✗ Could not save it now','x');\n"
                     "msg('✓ The schedule was saved','x');\n")
        with open(os.path.join(tr, "es", "a.json"), "w", encoding="utf-8") as fh:
            _json271.dump({"✓ Your settings were saved": "x", "✓ Could not save it now": "x",
                           "✓ The schedule was saved": "x"}, fh)
        return sorted(_scan271.missing_js("es", js_dir=js, translation_dir=tr))


eq("i18n gate: a plain JS message, or one under another mark, is not covered by a check-marked key "
   "(i18n.js never tries one for it); the same mark is (control)",
   _mark_gate271(), ["Could not save it now", "Your settings were saved"])
check("i18n gate: in_catalog follows i18n.js: whole text, then the rest of a marked text only",
      [_scan271.in_catalog(t, c) for t, c in (
          ("Saved", {"✓ Saved": 1}), ("✗ Saved", {"✓ Saved": 1}),
          ("✓ Saved", {"Saved": 1}), ("✓ Saved", {"✓ Saved": 1}), ("Saved", {"Saved": 1}))]
      == [False, False, True, True, True])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The workflow readers see every job id GitHub accepts, and every allowed host
# ════════════════════════════════════════════════════════════════════════════════════════════════
_WF271 = ("name: x\non: push\njobs:  # the jobs\n  py_X9:\n    runs-on: a\n  b2:  # a note\n    runs-on: b\n"
          "  # a comment between jobs\n  \"q1\":\n    runs-on: c\nenv:\n  not_a_job: 1\n")
eq("workflow reader: a job id with a digit, an underscore or a capital, one whose key line ends in a "
   "comment, a quoted one, and a jobs: line with a comment are all read; a key after jobs is not",
   _jobs29(_WF271), ["py_X9", "b2", "q1"])
eq("workflow reader: ...and each such job's block is found, ending before the next job or top-level key",
   [_job29(_WF271, j) for j in ("b2", "q1")], ["  b2:  # a note\n    runs-on: b\n", "  \"q1\":\n    runs-on: c\n"])
_EGR271 = ("    steps:\n      - name: Harden Runner\n        uses: x\n        with:\n          egress-policy: block\n"
           "          allowed-endpoints: >\n            github.com:443 one.example:443\n"
           "              two.example:443\n      - uses: y\n        with:\n          z: three.example:443\n")
eq("harden-runner reader: two hosts on a line and a deeper-indented one are all read, and nothing past the "
   "step is", _egress223(_EGR271), ("block", ["github.com:443", "one.example:443", "two.example:443"]))
eq("harden-runner reader: ...and an inline list given before the policy",
   _egress223("        with:\n          allowed-endpoints: 'github.com:443 one.example:443'\n"
              "          egress-policy: block\n      - run: z\n"), ("block", ["github.com:443", "one.example:443"]))
