#!/usr/bin/env python3
"""Static lint of every data-action control in the templates.

base.html's dispatcher calls ``window[data-action](...data-args)``, resolving ``"@self"`` to the
clicked element. Two ways a button silently breaks, both invisible until someone clicks it:

  1. the handler doesn't exist  -> ``typeof fn !== 'function'`` -> the click does NOTHING;
  2. the handler takes a DOM-element param (btn/cb/el/...) but the button's data-args omit ``"@self"``
     -> the param is ``undefined`` and the handler throws on ``.innerHTML``/``.disabled`` before doing
     anything (exactly the "Send test" bug: data-args=["telegram"] for testChannel(channel, btn)).

This test fails on either across every template, so a mis-wired button can't ship. Static-only (no
browser); run directly:  python tests/template_actions_test.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"

# Param names that, by this codebase's convention, are a DOM element passed via "@self".
ELEMENT_PARAMS = {"btn", "cb", "el", "elem", "checkbox", "input", "button", "target", "chk", "node", "link"}
# DOM-node methods/props — used to confirm a param is really treated as an element.
_ELEM_MEMBER = (r"\.(innerHTML|outerHTML|disabled|checked|value|closest|classList|dataset|"
                r"getAttribute|setAttribute|removeAttribute|querySelector|querySelectorAll|"
                r"appendChild|focus|blur|remove|style|textContent|parentNode|children)\b")

results = []


def check(cond, name, detail=""):
    results.append((bool(cond), name, detail))


srcs = {p.name: p.read_text(encoding="utf-8") for p in sorted(TEMPLATES.glob("*.html"))}

# ── 1. gather every global function definition: name -> (params, body) ──
_DEFS = [
    re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{"),
    re.compile(r"(?:window\.)?([A-Za-z_$][\w$]*)\s*=\s*function\s*\(([^)]*)\)\s*\{"),
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(([^)]*)\)\s*=>"),
]
defs = {}
for src in srcs.values():
    for pat in _DEFS:
        for m in pat.finditer(src):
            name = m.group(1)
            params = [p.strip().split("=")[0].strip() for p in m.group(2).split(",") if p.strip()]
            defs.setdefault(name, (params, src[m.end():m.end() + 3000]))
defined = set(defs)

# Actions a template wires up with its OWN delegated listener (closest('[data-action="x"]'))
# instead of the global window[name] dispatcher — those don't need a global function.
_DELEGATED = re.compile(r"""\[data-action=["']([A-Za-z_$][\w$]*)["']\]""")
delegated = {m.group(1) for src in srcs.values() for m in _DELEGATED.finditer(src)}
handled = defined | delegated

# ── 2. gather every data-action usage: (name, parsed_args_or_None, where) ──
_STATIC = re.compile(r'data-action="([A-Za-z_$][\w$]*)"([^>]*)')
_DATA_ARGS = re.compile(r"data-args='(\[.*?\])'")
_DA = re.compile(r"_da\(\s*'([A-Za-z_$][\w$]*)'\s*(?:,\s*(\[[^\]]*\]))?\s*\)")
uses = []


def _is_real_attr(src, start):
    """True when this data-action match is a real HTML attribute — not a `[data-action=...]` selector
    string, and not inside a // comment (both appear in the templates' inline JS)."""
    if start > 0 and src[start - 1] == "[":
        return False
    line_start = src.rfind("\n", 0, start) + 1
    return "//" not in src[line_start:start]


def _parse_args(raw):
    """Best-effort JSON parse of a simple args array; None if it holds JS expressions we can't
    statically resolve (those still get the handler-exists check, just not the @self check)."""
    if raw is None:
        return None
    try:
        return json.loads(raw.replace("&#39;", "'").replace("'", '"'))
    except (ValueError, TypeError):
        return None


for fname, src in srcs.items():
    for m in _STATIC.finditer(src):
        if not _is_real_attr(src, m.start()):
            continue
        am = _DATA_ARGS.search(m.group(2))
        uses.append((m.group(1), _parse_args(am.group(1) if am else None), fname))
    for m in _DA.finditer(src):
        uses.append((m.group(1), _parse_args(m.group(2)), fname))

# ── Check 1: every referenced handler is actually defined (or template-delegated) ──
missing = sorted({n for n, _, _ in uses if n not in handled})
check(not missing, "every data-action handler is defined",
      "undefined handler(s): %s" % ", ".join(missing))

# ── Check 2: a handler's DOM-element param is passed "@self" ──
mismatches = []
for name, args, where in uses:
    if name not in defs or args is None:
        continue
    params, body = defs[name]
    for i, p in enumerate(params):
        if p not in ELEMENT_PARAMS:
            continue
        if not re.search(r"\b" + re.escape(p) + _ELEM_MEMBER, body):
            continue   # the param isn't actually used as a DOM node here
        got = args[i] if i < len(args) else "<missing>"
        if got != "@self":
            mismatches.append("%s (%s): element arg '%s' (position %d) must be \"@self\", got %r"
                              % (name, where, p, i, got))
check(not mismatches, "element-arg handlers receive @self", "; ".join(mismatches))

# ── report ──
passed = sum(1 for c, _, _ in results if c)
for c, name, detail in results:
    print("%s  %s%s" % ("PASS" if c else "FAIL", name, "" if c else "  -> " + detail))
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if passed == len(results) else 1)
