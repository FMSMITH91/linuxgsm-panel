#!/usr/bin/env python3
"""Find user-visible template strings the DOM translator will never be able to translate.

base.html hands the browser the active language's catalog and then WALKS THE DOM, swapping every
text node (and title/placeholder/aria-label) whose exact whitespace-collapsed text is a catalog
key. Nothing is wrapped in t() — a string is translated if, and only if, it appears in the catalog
verbatim. That makes "is this string translated?" a question static analysis can answer, which is
what this module does: it renders each template's markup the way the browser will see it and
reports every translatable string that has no catalog entry.

It mirrors the runtime walker's rules exactly, because a gate that tests something *near* the
runtime behaviour is a gate that reports strings which are actually fine and misses ones that
aren't:

  • SKIP_TAGS below is base.html's `SKIP` map. <code> and <pre> are in it, which is why
    `<code>sv_maxclients</code>` needs no translation and must not be reported.
  • `data-no-i18n` skips the element AND its subtree — the marker for user-authored text
    (server names, tags) and for technical literals that must stay verbatim in every language.
  • Only title, placeholder and aria-label are translated attributes (base.html's `ATTRS`).

Jinja is resolved to what the browser would receive:

  • `{# … #}` is dropped — the browser never sees it.
  • `{% … %}` SPLITS a text run, because each branch renders as its own text node:
    `{% if x %}Super Admin{% else %}Standard{% endif %}` is two nodes, two catalog keys.
  • `{{ … }}` makes the text run it sits in DYNAMIC. This is the subtle one: Jinja emits one
    contiguous text run, so `Edit User: {{ u.name }}` reaches the browser as the single node
    "Edit User: bob" — a node whose text is different for every user and therefore can never
    match a catalog key. Such a string is UNREACHABLE, not merely untranslated, and no catalog
    entry can fix it; the template has to put the static half in its own element. Those are
    reported separately so they aren't mistaken for a missing translation.

Usage:
    python tools/i18n_scan.py            # report gaps against the es catalog
    python tools/i18n_scan.py --all      # also list the strings that ARE covered
"""
import glob
import html
import json
import os
import re
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(ROOT, "templates")
TRANSLATION_DIR = os.path.join(ROOT, "translations")

# base.html's SKIP map. Content inside these never reaches the translator.
SKIP_TAGS = {"script", "style", "textarea", "code", "pre", "noscript"}
# base.html's ATTRS list.
I18N_ATTRS = ("title", "placeholder", "aria-label")

# Sentinels chosen from the C0 range: they cannot occur in template source, so they survive the
# HTML parse without colliding with real content.
_SPLIT = "\x01"    # a {% … %} tag: ends one text node, starts the next
_DYNAMIC = "\x02"  # a {{ … }} expression: whatever run contains it is per-request text

_HAS_LETTER = re.compile(r"[A-Za-z]")


def _resolve_jinja(src):
    """Turn template source into markup carrying _SPLIT / _DYNAMIC where Jinja tags were."""
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    # The title block renders into <head><title>, and the runtime walker only ever walks
    # document.body — so nothing in it is translatable and reporting it would be reporting a gap
    # no catalog entry could close.
    src = re.sub(r"\{%\s*block title\s*%\}.*?\{%\s*endblock\s*%\}", "", src, flags=re.S)
    src = re.sub(r"\{%.*?%\}", _SPLIT, src, flags=re.S)
    src = re.sub(r"\{\{.*?\}\}", _DYNAMIC, src, flags=re.S)
    return src


def is_translatable(text):
    """Could this string plausibly be a catalog key?

    It could if it has a letter and isn't a lone character.
    """
    text = text.strip()
    return bool(text) and len(text) > 1 and bool(_HAS_LETTER.search(text))


class _Walker(HTMLParser):
    """Collects the strings the runtime translator would try to look up, plus the unreachable ones.

    `strings` and `dynamic` map text -> set of "why"/context labels, so a report can say where a
    string came from without a second pass over the file.
    """

    def __init__(self):
        # convert_charrefs=True decodes entities for us, so `Files &amp; Config` is compared as
        # "Files & Config" — the text the browser actually puts in the node, and the form the
        # catalog stores. Comparing the escaped source instead reports every &amp; as a gap.
        HTMLParser.__init__(self, convert_charrefs=True)
        self.strings = {}
        self.dynamic = {}
        # EVERY open element, not just the ones that opened a skip. The skip used to be tracked
        # as a stack of skipping tags alone, popped whenever the closing tag matched its top —
        # so a <div data-no-i18n> containing a plain nested <div> ended its skip region at the
        # INNER close, and everything after it was collected. Verified:
        #   <div data-no-i18n><div>x</div>Leaked text</div>  ->  {'Leaked text'}
        #   <div data-no-i18n><span>x</span>Safe text</div>  ->  {}
        # The runtime walker recurses the real DOM and cannot make that mistake, and this file's
        # contract is that it mirrors the runtime's rules exactly.
        self._open = []           # names of every currently-open non-void element
        self._skip_at = None      # len(self._open) when the innermost skip began; None = not skipping

    # Void elements never close, so they must not push onto the skip stack.
    _VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "param", "source", "track", "wbr"}

    def handle_starttag(self, tag, attrs):
        attr_map = dict(attrs)
        skips = tag in SKIP_TAGS or "data-no-i18n" in attr_map
        # `skips`, not just the enclosing depth: base.html's walker returns on a skipped element
        # BEFORE it reaches the attribute loop, so an element's own data-no-i18n exempts its
        # title/placeholder too. Testing only the outer depth reported placeholders as gaps that
        # the runtime never even looks at.
        if self._skip_at is None and not skips:
            self._collect_attrs(attr_map)
        if tag in self._VOID:
            return                # never closes, so it opens no region
        self._open.append(tag)
        if skips and self._skip_at is None:
            self._skip_at = len(self._open)   # the depth this skip region starts at

    def _collect_attrs(self, attr_map):
        """Record the element's translatable attributes (title, placeholder...) as "@name"."""
        for name in I18N_ATTRS:
            value = attr_map.get(name)
            if value is None or _DYNAMIC in value or _SPLIT in value:
                continue   # server-side t() already handled it, or it is per-request text
            value = html.unescape(value).strip()
            if is_translatable(value):
                self.strings.setdefault(value, set()).add("@" + name)

    def handle_endtag(self, tag):
        if tag in self._VOID or tag not in self._open:
            return                # a stray close, or one for an element that never opened
        # Unwind to the matching open tag: browsers close implicitly-open elements the same way,
        # and an unbalanced template must not leave the walker permanently skipping (or never).
        while self._open and self._open.pop() != tag:
            pass
        if self._skip_at is not None and len(self._open) < self._skip_at:
            self._skip_at = None              # left the element that opened the skip

    def handle_data(self, data):
        if self._skip_at is not None:
            return
        for run in data.split(_SPLIT):
            collapsed = re.sub(r"\s+", " ", run.replace(_DYNAMIC, "\x00")).strip()
            if not is_translatable(collapsed):
                continue
            if "\x00" in collapsed:
                # A static phrase welded to per-request text: one node, never a catalog key.
                for part in collapsed.split("\x00"):
                    part = part.strip(" \t ")
                    if is_translatable(part):
                        self.dynamic.setdefault(part, set()).add("text")
            else:
                self.strings.setdefault(collapsed, set()).add("text")


# A quoted literal inside a {{ }} expression: `{{ 'Regenerate token' if t else 'Generate token' }}`,
# a macro's label argument (`sort_th('target', 'Target')`). It renders as the whole text of its
# node as often as not, and _resolve_jinja turned it into _DYNAMIC, so it was never asked for:
# those labels showed in English on translated pages while the gate passed.
_EXPR_LITERAL = re.compile(r"'([^'\\\n]*)'|\"([^\"\\\n]*)\"")
# A URL builder's arguments are endpoint and parameter names, never text a person reads.
_URL_CALL = re.compile(r"\b(?:url_for|asset_url)\([^()]*\)")


def _is_expr_label(text):
    """Does a literal from a {{ }} expression read as a label: capitalised, a word, not code?"""
    return bool(re.match(r"^[A-Z][A-Za-z]", text) and not _JS_CODEY.search(text)
                and "%" not in text and text == text.strip())


def _expression_labels(source):
    """Every label-like quoted literal inside the {{ }} expressions of template `source`."""
    source = re.sub(r"\{#.*?#\}", "", source, flags=re.S)
    out = set()
    for expr in re.findall(r"\{\{(.*?)\}\}", source, flags=re.S):
        for m in _EXPR_LITERAL.finditer(_URL_CALL.sub("", expr)):
            text = m.group(1) if m.group(1) is not None else m.group(2)
            if _is_expr_label(text):
                out.add(text)
    return out


def scan_template(path):
    """(translatable strings, unreachable-because-dynamic strings) for one template file."""
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    walker = _Walker()
    walker.feed(_resolve_jinja(source))
    walker.close()
    for text in _expression_labels(source):
        walker.strings.setdefault(text, set()).add("expr")
    return walker.strings, walker.dynamic


def scan_templates(template_dir=TEMPLATE_DIR):
    """{string: {template: {contexts}}} for every template, plus the same shape for dynamic ones."""
    found, dynamic = {}, {}
    for path in sorted(glob.glob(os.path.join(template_dir, "*.html"))):
        name = os.path.basename(path)
        strings, dyn = scan_template(path)
        for text, why in strings.items():
            found.setdefault(text, {})[name] = why
        for text, why in dyn.items():
            dynamic.setdefault(text, {})[name] = why
    return found, dynamic


# ── The other half: strings the JAVASCRIPT builds ─────────────────────────────────────────────
# Everything the JS writes into the page goes through the same MutationObserver, so a toast, a
# button label or a confirm dialog is translated on exactly the same terms as template text: it
# needs a catalog entry, verbatim. Nothing warns when it has none — the host Specs card showed
# "Memory" in Spanish and "Operating System" in English side by side for that reason.
JS_DIR = os.path.join(ROOT, "static", "js")
# Put this on a line to exempt its literals — the JS twin of data-no-i18n, for a string that is
# a command, an identifier or a fragment of markup rather than something a person reads.
JS_IGNORE = "i18n-ignore"

# Anything with these in it is code (a selector, a URL, markup, a template placeholder), not prose.
_JS_CODEY = re.compile(r"[<>{}$=;#/\\]")


def _js_strings(source):
    """Every string literal in a JS file, as (text, line). Comments and their contents excluded."""
    return [(text, line) for text, line, _at in _js_strings_at(source)]


def _js_strings_at(source):
    """Every string literal in a JS file, as (text, line, index of its opening quote)."""
    return [(text, line, start) for text, line, start, _end in _js_string_spans(source)]


def _js_string_spans(source):
    """Every string literal in a JS file, as (text, line, index of its opening quote, index past it).

    A hand-rolled scanner rather than a regex over the whole file: a regex cannot tell the `//` of
    a line comment from the one inside "https://ntfy.sh", and stripping comments first is exactly
    how a URL in a string silently ate the rest of its line. Regex literals are stepped over as
    ordinary operators, which is safe here because none in this tree contains a quote.
    """
    out, i, line, n = [], 0, 1, len(source)
    while i < n:
        c = source[i]
        if c == "\n":
            line += 1; i += 1
        elif c == "/" and source[i + 1:i + 2] in ("/", "*"):
            end = _comment_end(source, i)
            line += source.count("\n", i, end); i = end
        elif c in "'\"`":
            start, start_line = i, line
            text, i, line = _read_js_string(source, i, line)
            out.append((text, start_line, start, i))
        else:
            i += 1
    return out


def _comment_end(source, i):
    """Where the comment opening at source[i] ends: a // AT its newline, a /* just past its */."""
    n = len(source)
    if source[i + 1] == "/":
        end = source.find("\n", i)
        return n if end < 0 else end
    end = source.find("*/", i + 2)
    return n if end < 0 else end + 2


def _read_js_string(source, i, line):
    """Read the literal whose opening quote is at source[i]: (its text, the index past it, line)."""
    quote, buf, n = source[i], [], len(source)
    i += 1
    while i < n and source[i] != quote:
        if source[i] == "\\" and i + 1 < n:
            char, i = _decode_js_escape(source, i)
            buf.append(char)
            continue
        if source[i] == "\n":
            line += 1
        buf.append(source[i])
        i += 1
    return "".join(buf), i + 1, line


def _decode_js_escape(source, i):
    """The character the backslash escape at source[i] stands for, and the index just past it."""
    # DECODE the escape rather than keeping the letter after the backslash:
    # — is an em dash in the string the browser builds, and treating it as
    # the four characters "u2014" produced catalog keys that matched nothing.
    esc = source[i + 1]
    if esc == "u" and re.match(r"[0-9a-fA-F]{4}", source[i + 2:i + 6]):
        return chr(int(source[i + 2:i + 6], 16)), i + 6
    return {"n": "\n", "t": "\t", "r": "\r"}.get(esc, esc), i + 2


def is_js_ui_text(text):
    """Does this literal read like a WHOLE thing a person sees?

    Conservative on purpose. Gating on a guess means false positives demand pointless translations, so this only claims a
    literal that looks like prose: at least two words, opening with a capital, and free of the
    punctuation that marks a selector, URL or markup fragment.

    It also has to be translatable ON ITS OWN. A literal that is one half of a concatenation —
    'Switch the panel to branch "' + name — reaches the DOM welded to per-request text, exactly
    like the {{ }} case in templates, and no catalog entry can ever match the node it lands in.
    Those end in a dangling quote, bracket or colon, so they are left out rather than gated on.
    """
    return bool(
        " " in text
        and re.match(r"^[A-Z]", text)
        and re.search(r"[A-Za-z]{3}", text)
        and not _JS_CODEY.search(text)
        and text == text.strip()
        and "\n" not in text
        and not re.search(r'[("“:]$', text)
    )


# One capitalised word is too often a key name ('Escape'), a class or an identifier to claim on its
# own, so is_js_ui_text leaves it out — and with it every one-word label: the UFW badge's
# "Inactive", the confirm button "Unblock", the toasts "Deleted" and "Sent", the busy label
# "Retrying…". Claimed here only where the code puts it in front of a person: a toast, a
# textContent or innerHTML write, a confirm or busy label, or nags.js's element builders.
_JS_UI_WORD = re.compile(r"^[A-Z][a-z]+(?:…|\.\.\.)?$")
_JS_UI_SLOT = re.compile(r"(?:\btoast\([^;]*|\btextContent\s*=\s*[^;]*|\binnerHTML\s*=\s*[^;]*"
                         r"|\bconfirmLabel\s*:\s*|\bbusy[A-Za-z]*\s*[:=]\s*[^;]*"
                         r"|\b_rbButton\(\s*|\b_rbEl\([^;]*)$")


def is_js_ui_word(text, before):
    """Is this one-word literal a label, given the source just `before` it?"""
    return bool(_JS_UI_WORD.match(text) and _JS_UI_SLOT.search(before))


# A literal handed to t() (or a file's own wrapper for it, _discT) is a string the code itself says
# a person reads, whatever its shape: lower-case ("player is connected to"), one word, or a branch
# of a ternary inside the call. Matched as "an open t( call with no unbalanced bracket since".
_JS_T_CALL = re.compile(r"""\b(?:t|_discT)\((?:[^;'"()]|'[^'\n]*'|"[^"\n]*"|\([^()]*\))*$""")


def is_js_t_arg(text, before):
    """Is this literal an argument of t() / _discT(), given the source just `before` it?"""
    # Not the right-hand side of a comparison: t(action === 'stop' ? … : …) chooses by 'stop'.
    return bool(re.search(r"[A-Za-z]{2}", text) and not _JS_CODEY.search(text)
                and not re.search(r"[=!]==?\s*$", before) and _JS_T_CALL.search(before))


# An innerHTML-built literal: the text of a WHOLE element inside it (`<th>Mods</th>`, an icon then
# `Scan failed.</span>`) reaches the page as its own text node, translated on the same terms as any
# other — and _JS_CODEY drops the whole literal for its `<`, so none of it was ever asked for. That
# is how a dialog built as one innerHTML string stayed English for every viewer (review 2026-10-11,
# the players dialog; 117 such strings had no entry). Only an element's whole text counts: prose at
# a literal's edge is spliced to a value and no catalog key can match it.
_JS_MARKUP_TEXT = re.compile(r"(?:<(?!/)[^<>]*>|</i>)([^<>]+)</[a-zA-Z0-9]+>")


def js_markup_texts(text):
    """The user-visible whole-element texts inside an innerHTML-built literal."""
    out = []
    for m in _JS_MARKUP_TEXT.finditer(text):
        seg = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()
        if seg and (is_js_ui_text(seg) or _JS_UI_WORD.match(seg)):
            out.append(seg)
    return out


# A value the code writes into the page as ONE text node, whatever its shape: a confirm dialog's
# body (bodyText) and its password prompt (requireLabel) are set with textContent (panel.js
# _cdFillBody). The prose rules above guess at fragments, and left these out for a trailing colon
# ("Enter your account password to confirm:"), a slash ("the Tailscale IP/DNS name.") or a
# paragraph break — all English bodies on a translated page. Claimed only when the value is
# literal from end to end (_js_literal_runs), and whitespace-collapsed, as i18n.js looks it up.
_JS_TEXT_SLOT = re.compile(r"\b(?:bodyText|requireLabel)\s*:\s*$")


def _js_literal_runs(source):
    """The literals of a JS file grouped into `'…' + '…'` runs: [(spans, standalone)].

    A sentence split over several literals for line length reaches the page as ONE string, so it
    has to be judged — and looked up — whole: judged literal by literal, each half was a fragment
    (it ends in a space, or starts lower-case) and the sentence was never asked for. `standalone`
    is a run with no `+` on either side, i.e. no per-request text spliced into it.
    """
    spans, runs = _js_string_spans(source), []
    for span in spans:
        if runs and re.fullmatch(r"\s*\+\s*", source[runs[-1][-1][3]:span[2]]):
            runs[-1].append(span)
        else:
            runs.append([span])
    out = []
    for run in runs:
        lead = source[max(0, run[0][2] - 40):run[0][2]].rstrip()
        tail = source[run[-1][3]:run[-1][3] + 40].lstrip()
        out.append((run, not lead.endswith("+") and not tail.startswith("+")))
    return out


def _js_claims(text, before):
    """Whether a literal (or a whole run of them) reads as user-visible text, given what precedes it."""
    return is_js_ui_text(text) or is_js_ui_word(text, before[-80:]) or is_js_t_arg(text, before)


def _js_whole_claim(joined, before):
    """A literal-only run's text as ONE node, whitespace-collapsed, when it is claimed as such."""
    key = re.sub(r"\s+", " ", joined).strip()
    if _JS_TEXT_SLOT.search(before) and re.search(r"[A-Za-z]{3}", key):
        return key
    # A paragraph break: a confirm body ('Close the public web port?\n\nFunnel is on…'), often
    # chosen by a ternary and passed on in a variable. is_js_ui_text refuses a "\n" (a fragment of
    # a longer splice), but with nothing spliced in it is the whole node, and i18n.js looks it up
    # whitespace-collapsed.
    if "\n" in joined and is_js_ui_text(key):
        return key
    return None


def _js_run_claims(run, standalone, source):
    """The user-visible texts one run of literals (from _js_literal_runs) makes, as a list."""
    before = source[max(0, run[0][2] - 160):run[0][2]]
    joined = "".join(s[0] for s in run)
    whole = _js_whole_claim(joined, before) if standalone else None
    if whole:
        return [whole]
    # Judged whole when nothing is spliced in; part by part otherwise, as before.
    parts = [(joined, before)] if standalone and len(run) > 1 else \
        [(s[0], source[max(0, s[2] - 160):s[2]]) for s in run]
    out = [text for text, bef in parts if _js_claims(text, bef)]
    for s in run:
        out.extend(js_markup_texts(s[0]))
    return out


def scan_js(js_dir=JS_DIR):
    """{string: {filename}} for every JS literal that reads as user-visible text."""
    found = {}
    for path in sorted(glob.glob(os.path.join(js_dir, "*.js"))):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        lines = source.splitlines()
        for run, standalone in _js_literal_runs(source):
            if any(1 <= s[1] <= len(lines) and JS_IGNORE in lines[s[1] - 1] for s in run):
                continue
            for text in _js_run_claims(run, standalone, source):
                found.setdefault(text, set()).add(name)
    return found


def missing_js(lang="es", js_dir=JS_DIR, translation_dir=TRANSLATION_DIR):
    """{string: {filename}} for JS user-visible text with no entry in `lang`'s catalog."""
    catalog = load_catalog(lang, translation_dir)
    return {t: w for t, w in scan_js(js_dir).items() if t not in catalog}


def load_catalog(lang, translation_dir=TRANSLATION_DIR):
    """The merged {english: translated} catalog for a language, as panel.core.i18n builds it."""
    catalog = {}
    for path in sorted(glob.glob(os.path.join(translation_dir, lang, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            catalog.update(json.load(fh))
    return catalog


def missing(lang="es", template_dir=TEMPLATE_DIR, translation_dir=TRANSLATION_DIR):
    """{string: {template: {contexts}}} for template strings with no entry in `lang`'s catalog."""
    found, _ = scan_templates(template_dir)
    catalog = load_catalog(lang, translation_dir)
    return {text: where for text, where in found.items() if text not in catalog}


def _main():
    import sys
    show_all = "--all" in sys.argv
    found, dynamic = scan_templates()
    catalog = load_catalog("es")
    gaps = {t: w for t, w in found.items() if t not in catalog}

    print("templates scanned : %d" % len(glob.glob(os.path.join(TEMPLATE_DIR, "*.html"))))
    print("translatable      : %d" % len(found))
    print("in catalog        : %d" % (len(found) - len(gaps)))
    print("MISSING           : %d" % len(gaps))
    print("unreachable ({{}}): %d" % len(dynamic))
    print()
    _print_missing(gaps)
    if dynamic:
        print()
        _print_dynamic(dynamic, catalog)
    if show_all:
        print()
        for text in sorted(t for t in found if t in catalog):
            print("  ok       %r" % text[:100])
    return 1 if gaps else 0


def _print_missing(gaps):
    """One MISSING line per template string with no catalog entry, grouped by first template."""
    for text, where in sorted(gaps.items(), key=lambda kv: sorted(kv[1])[0]):
        files = ",".join(sorted(where))
        print("  MISSING  [%s] %r" % (files[:40], text[:100]))


def _print_dynamic(dynamic, catalog):
    """One DYNAMIC line per string welded to a {{ }} that no catalog entry can reach."""
    for text, where in sorted(dynamic.items(), key=lambda kv: sorted(kv[1])[0]):
        if text in catalog:
            continue   # translated elsewhere as a standalone node; here it is just inert
        print("  DYNAMIC  [%s] %r" % (",".join(sorted(where))[:40], text[:100]))


if __name__ == "__main__":
    raise SystemExit(_main())
