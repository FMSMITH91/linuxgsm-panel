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
# A form's confirm dialog (panel.js): each value is written into the dialog with textContent, so it
# reaches the walker as ONE text node, wherever the form sits. Not read at all before, so neither a
# missing entry nor a name spliced into the sentence ("Delete user “{{ name }}”?") was reported.
CONFIRM_ATTRS = ("data-confirm", "data-confirm-title", "data-confirm-label")

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
        self._skip_tag = None     # the element that began it: a SKIP_TAGS name, or "data-no-i18n"

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
        # Read in a guarded region too: the dialog is built elsewhere, outside the guard.
        self._collect_attrs(attr_map, CONFIRM_ATTRS)
        if tag in self._VOID:
            return                # never closes, so it opens no region
        self._open.append(tag)
        if skips and self._skip_at is None:
            self._skip_at = len(self._open)   # the depth this skip region starts at
            self._skip_tag = tag if tag in SKIP_TAGS else "data-no-i18n"

    def _collect_attrs(self, attr_map, names=I18N_ATTRS):
        """Record the element's translatable attributes (title, placeholder...) as "@name"."""
        for name in names:
            value = attr_map.get(name)
            if value is None:
                continue
            # A {% if %} splits the value into branches, each a whole value, as it splits a text
            # run. A branch holding a {{ }} is per-request text: an attribute made of the
            # expression alone is the expression's business (a t() call, or a literal
            # _expression_labels asks for), but static words welded to one ("Move {{ label }}
            # left") reach the browser as one value no catalog key can equal. Those were skipped,
            # so the gate passed while every such label stayed English; reported as unreachable
            # now, as text runs are.
            for branch in html.unescape(value).split(_SPLIT):
                branch = re.sub(r"\s+", " ", branch).strip()
                if _DYNAMIC not in branch:
                    if is_translatable(branch):
                        self.strings.setdefault(branch, set()).add("@" + name)
                    continue
                for part in branch.split(_DYNAMIC):
                    part = part.strip()
                    if is_translatable(part):
                        self.dynamic.setdefault(part, set()).add("@" + name)

    def handle_endtag(self, tag):
        if tag in self._VOID or tag not in self._open:
            return                # a stray close, or one for an element that never opened
        # Unwind to the matching open tag: browsers close implicitly-open elements the same way,
        # and an unbalanced template must not leave the walker permanently skipping (or never).
        while self._open and self._open.pop() != tag:
            pass
        if self._skip_at is not None and len(self._open) < self._skip_at:
            self._skip_at = self._skip_tag = None     # left the element that opened the skip

    def handle_data(self, data):
        if self._skip_at is not None:
            self._skipped_prose(data)
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


    # The walker never reads a skipped region, so prose there is English in every language, and the
    # gate mirrored the skip and said nothing: a guard put on a whole sentence to keep the name
    # inside it verbatim ("This is a real shell on {{ host }}, running as …") hid the panel's own
    # words, and a placeholder written inside a <pre> ("Pick a log above, …") was never asked for.
    # Reported as unreachable. A guard belongs on the name alone; a <pre>'s placeholder in a
    # sibling element.
    def _skipped_prose(self, data):
        inner = self._open[self._skip_at - 1:]
        in_pre = "pre" in inner
        if not in_pre and (self._skip_tag != "data-no-i18n" or set(inner) & SKIP_TAGS):
            return                # code, a script, a style: never prose
        for part in re.split("[%s%s]" % (_SPLIT, _DYNAMIC), re.sub(r"\s+", " ", data)):
            part = part.strip()
            if _is_skipped_prose(part, in_pre):
                self.dynamic.setdefault(part, set()).add("pre" if in_pre else "guarded")


def _is_skipped_prose(part, in_pre):
    """A sentence in a <pre> (four words, ending like one), or three words under a guard."""
    if _JS_CODEY.search(part) or not re.search(r"[a-z]{3}", part):
        return False
    words = len(part.split())
    return words >= 4 and part[-1:] in ".!?" if in_pre else words >= 3


# A quoted literal inside a {{ }} expression: `{{ 'Regenerate token' if t else 'Generate token' }}`,
# a macro's label argument (`sort_th('target', 'Target')`). It renders as the whole text of its
# node as often as not, and _resolve_jinja turned it into _DYNAMIC, so it was never asked for:
# those labels showed in English on translated pages while the gate passed.
_EXPR_LITERAL = re.compile(r"'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"")
# A URL builder's arguments are endpoint and parameter names, never text a person reads.
_URL_CALL = re.compile(r"\b(?:url_for|asset_url)\([^()]*\)")


def _is_expr_label(text):
    """Does a literal from a {{ }} expression read as a label: capitalised, a word, not code?"""
    return bool(re.match(r"^[A-Z][A-Za-z]", text) and not _JS_CODEY.search(text)
                and "%" not in text and text == text.strip())


def _is_expr_prose(text):
    """Does a lower-case literal read as words a person reads ('this host', '•••• (leave blank…')?

    _is_expr_label asks for a capital, so a fallback like `display_host or 'this host'` and a
    placeholder like 'the bot token from the Developer Portal' were never asked for. Two words or
    more, after any leading symbols, none of them shaped like a CSS class or an identifier (a
    hyphen, an underscore, a digit): `'btn btn-sm'` is markup, not prose.
    """
    core = re.sub(r"^[^A-Za-z]+", "", text)
    words = core.split()
    return bool(len(words) >= 2 and re.search(r"[a-z]{3}", core) and not _JS_CODEY.search(text)
                and "%" not in text and text == text.strip()
                and not any(re.search(r"[-_0-9]", w) for w in words))


def _jinja_literal(raw):
    r"""A Jinja string literal's text, its escapes (\uXXXX, \', \") decoded as Jinja decodes them."""
    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)",
                  lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) == 5 else m.group(1), raw)


# A t() call's argument is a catalog key by definition, whatever its shape: "Move %s up" has a %,
# and _is_expr_label refused it, so a format key with no entry rendered English (and its |format
# is where a translation that lost the %s would raise). Matched as "an open t( call".
_EXPR_T_CALL = re.compile(r"""\bt\(\s*$""")


def _expression_labels(source):
    """Every label-like quoted literal inside the {{ }} expressions (and {% set %}s) of `source`."""
    source = re.sub(r"\{#.*?#\}", "", source, flags=re.S)
    # {% set NAME = {'key': 'Label'} %}: a lookup table rendered through {{ NAME[key] }}, so its
    # labels are what the page shows (the dashboard's tile names, the server page's panels).
    exprs = re.findall(r"\{\{(.*?)\}\}", source, flags=re.S) \
        + re.findall(r"\{%-?\s*set\b(.*?)%\}", source, flags=re.S)
    out = set()
    for expr in exprs:
        expr = _URL_CALL.sub("", expr)
        for m in _EXPR_LITERAL.finditer(expr):
            text = _jinja_literal(m.group(1) if m.group(1) is not None else m.group(2))
            if _EXPR_T_CALL.search(expr[:m.start()]) and _HAS_LETTER.search(text):
                out.add(text)
            elif _is_expr_label(text) or (_is_expr_prose(text)
                                          and not re.search(r"(?:[=!]=|\bin)\s*$", expr[:m.start()])):
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
_JS_T_CALL = re.compile(r"""\b(?:t|_discT|tf|tfHtml)\((?:[^;'"()]|'[^'\n]*'|"[^"\n]*"|\([^()]*\))*$""")


def is_js_t_arg(text, before):
    """Is this literal an argument of t() / _discT(), given the source just `before` it?"""
    # Not the right-hand side of a comparison: t(action === 'stop' ? … : …) chooses by 'stop'.
    m = _JS_T_CALL.search(before)
    # Nor a VALUE of tf()/tfHtml(): `{dir: base || 'home'}` goes in untranslated, after the sentence.
    if m and m.group(0).startswith("tf") and "{" in m.group(0):
        return False
    # A tf() template is a sentence by construction: its {placeholders}, a "/" or a "=" are words
    # there ("{used} / {total} used", "Blank = use the default"); only markup or code is refused.
    codey = re.compile(r"[<>{}$\\]") if m and m.group(0).startswith("tf") else _JS_CODEY
    return bool(re.search(r"[A-Za-z]{2}", text) and not codey.search(re.sub(r"#?\{\w+\}", "", text))
                and not re.search(r"[=!]==?\s*$", before) and m)


# An innerHTML-built literal: the text of a WHOLE element inside it (`<th>Mods</th>`, an icon then
# `Scan failed.</span>`) reaches the page as its own text node, translated on the same terms as any
# other — and _JS_CODEY drops the whole literal for its `<`, so none of it was ever asked for. That
# is how a dialog built as one innerHTML string stayed English for every viewer (review 2026-10-11,
# the players dialog; 117 such strings had no entry). Only an element's whole text counts: prose at
# a literal's edge is spliced to a value and no catalog key can match it.
_JS_MARKUP_TEXT = re.compile(r"(?:<(?!/)([a-zA-Z0-9]*)([^<>]*)>|</i>|^([^<>]*)>)([^<>]+)</([a-zA-Z0-9]+)>")
# Emphasis inside a sentence: "Attach this host to your <strong>free</strong> subscription". The
# word is a fragment of prose spliced around it, not a label, so a lower-case one is not claimed.
_JS_INLINE_TAGS = {"b", "strong", "i", "em", "u"}
# A whole element's text in lower case: a badge ("banned now"), a link ("view log"), a button
# ("unblock"), a note ("(empty folder)"). is_js_ui_text and _JS_UI_WORD both want a capital, so a
# lower-case label inside markup was never asked for. Words only: letters, spaces, an apostrophe or a closing full stop,
# and two letters at least ("fail2ban isn't installed on this host." has a digit in a word, which
# is a name, and is allowed inside one).
_JS_LOWER_LABEL = re.compile(r"^\(?[a-z][a-z0-9']*(?: [a-z0-9'][a-z0-9'.]*)*[.…]?\)?$")


def _js_markup_claims(seg, tag):
    """Whether one element's whole text reads as a label, ignoring a leading emoji or symbol."""
    core = re.sub(r"^[^A-Za-z(]+", "", seg)   # "❌ Request failed": the shape is the words'
    if not core or not re.search(r"[A-Za-z]{2}", core):
        return False
    return bool(is_js_ui_text(core) or _JS_UI_WORD.match(core)
                or (tag not in _JS_INLINE_TAGS and _JS_LOWER_LABEL.match(core)
                    and not _JS_CODEY.search(core)))


def _js_guarded_before(prefix):
    """Whether `prefix` (a literal up to an element's text) leaves a data-no-i18n element open."""
    at = prefix.rfind("data-no-i18n")
    if at < 0:
        return False
    opened = re.search(r"<([a-zA-Z0-9]+)[^<>]*$", prefix[:at])
    return bool(opened) and ("</%s>" % opened.group(1).lower()) not in prefix[at:].lower()


def js_markup_texts(text):
    """The user-visible whole-element texts inside an innerHTML-built literal.

    Also a literal that STARTS inside an opening tag, after a splice:
    `'<a href="#"' + _da('x') + '>Advanced: use a pre-auth key instead</a>'` — the label is the
    element's whole text, and the opening tag being in the previous literal hid it.
    """
    out = []
    for m in _JS_MARKUP_TEXT.finditer(text):
        if _js_markup_skipped(m, text):
            continue              # the walker skips these, so nothing in them is asked for
        seg = re.sub(r"\s+", " ", html.unescape(m.group(4))).strip()
        if seg and _js_markup_claims(seg, (m.group(1) or m.group(5)).lower()):
            out.append(seg)
    return out


def _js_markup_skipped(m, text):
    """Whether a _JS_MARKUP_TEXT match sits where the walker never looks (code, pre, a guard)."""
    attrs = (m.group(2) or "") + (m.group(3) or "")
    return bool((m.group(1) or "").lower() in SKIP_TAGS or m.group(5).lower() in SKIP_TAGS
                or "data-no-i18n" in attrs or _js_guarded_before(text[:m.start()]))


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
    if standalone:
        out.extend(_js_icon_tail(joined))
    return out


# An icon, then words to the END of a literal with nothing spliced on: `'<i class="bi …"></i> Updates
# installed.'`. The words are the element's whole text, but the closing tag is in no literal (the
# element was opened earlier, or its parent closes it), so _JS_MARKUP_TEXT never matched them:
# "Starting Tailscale…", "Backing up…" and eleven more were English with the gate green.
_JS_ICON_TAIL = re.compile(r"(?:</i>|<i\b[^<>]*></i>)([^<>]+)\Z")


def _js_icon_tail(joined):
    """The words after a trailing icon in a standalone run of literals, as one claimed text."""
    m = _JS_ICON_TAIL.search(joined)
    seg = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip() if m else ""
    return [seg] if seg and _js_markup_claims(seg, "") and not _js_guarded_before(joined[:m.start()]) else []


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


# ── Text a script writes where the translator never looks ─────────────────────────────────────
# A script that writes panel text into an element the translator skips — one carrying data-no-i18n
# (guarded for a name or a path it holds at other times), or a <pre> — has it shown in English in
# every language, catalog entry or not: "Enter SSH password" into the credential field, the stale
# notice into #live-stale, "Could not read the log." into the security log's <pre>. Nothing above
# can see it, because the literal is fine and only its DESTINATION is wrong. Such a write goes
# through t() (or the element loses its guard). Read from the templates (an element's id or name)
# and the scripts (a variable bound to it, or one that sets data-no-i18n itself).
class _GuardedIds(HTMLParser):
    """The id and name of every template element the translator skips."""

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.ids, self.names = set(), set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in SKIP_TAGS or "data-no-i18n" in a:
            for key, into in (("id", self.ids), ("name", self.names)):
                v = a.get(key) or ""
                if v and _DYNAMIC not in v and _SPLIT not in v:
                    into.add(v)


_JS_WRITE = r"\.(?:textContent|innerText|placeholder|title)\s*=(?!=)"


def _guarded_vars(source, ids, names):
    """{variable: [index of its binding]} for script variables bound to a skipped element.

    By name as well as id: the credential field is reached as `[name="credential"]`. A name some
    other template's element shares without a guard still counts (a write through t() is right for
    either), which is the conservative side of a guess.
    """
    out = {}
    for m in re.finditer(r"\b(?:var|let|const)\s+(\w+)\s*=\s*([^;]*)", source):
        rhs = m.group(2)
        hit = any(("'%s'" % i) in rhs or ('"%s"' % i) in rhs or ("#%s'" % i) in rhs for i in ids) \
            or any(('name="%s"' % n) in rhs or ("name='%s'" % n) in rhs for n in names)
        if hit:
            out.setdefault(m.group(1), []).append(m.start())
    for m in re.finditer(r"\b(\w+)\.setAttribute\(\s*['\"]data-no-i18n['\"]", source):
        out.setdefault(m.group(1), []).append(m.start())
    return out


def guarded_writes(js_dir=JS_DIR, template_dir=TEMPLATE_DIR):
    """[(file, line, text)]: UI text written, not through t(), into an element the translator skips."""
    guard = _GuardedIds()
    for path in sorted(glob.glob(os.path.join(template_dir, "*.html"))):
        with open(path, encoding="utf-8") as fh:
            guard.feed(_resolve_jinja(fh.read()))
    out = []
    for path in sorted(glob.glob(os.path.join(js_dir, "*.js"))):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        for var, starts in _guarded_vars(source, guard.ids, guard.names).items():
            for start in starts:
                # The binding's own neighbourhood: a short name (`el`) is rebound elsewhere.
                window = source[start:start + 2500]
                for w in re.finditer(r"\b%s%s([^;]*)" % (re.escape(var), _JS_WRITE), window):
                    out.extend(_untranslated_in(path, source, start + w.start(1), w.group(1)))
    return sorted(set(out))


def _untranslated_in(path, source, at, rhs):
    """The UI-text literals of one assignment's right-hand side that no t() wraps."""
    found = []
    spans = _js_string_spans(rhs)
    # `window.t ? window.t('x') : 'x'`: the bare one is the fallback for a page without i18n.js.
    wrapped = {text for text, _l, s0, _e in spans if re.search(r"\bt\(\s*$", rhs[:s0])}
    for text, _line, s0, _e in spans:
        before, text = rhs[:s0], text.strip()   # " (alerts muted)", spliced on after a name
        if text in wrapped:
            continue
        if _js_claims(text, before) or (_JS_LOWER_LABEL.match(text) and " " in text):
            found.append((os.path.basename(path), source.count("\n", 0, at + s0) + 1, text))
    return found


# ── A sentence spliced around a value ─────────────────────────────────────────────────────────
# `toast(n + ' uploaded to ' + dir)`, `bodyText: 'Remove ' + id + ' from this server?'`: the words
# reach the page welded to the value, as ONE text node no catalog key can match, so the sentence is
# English in every language, and translating the pieces would keep English's word order. Such a
# sentence is a catalog template with placeholders, filled after translation: tf('{n} uploaded to
# {dir}', {n: n, dir: dir}) (tfHtml for an innerHTML sink, which escapes every value). Reported here:
# a literal joined by `+` to something that is not a literal, whose text at that join is words.
# Only the text node at the join counts: a literal's whole elements (`<th>Name</th>`) are their own
# nodes, attributes and markup are not text, and punctuation, units and CSS class lists around a
# name ('“' + name + '”', n + ' MB', 'btn ' + cls) are not prose. `i18n-ignore` on a line exempts it.
_JS_GAP = re.compile(r"(?:\s|//[^\n]*\n|/\*.*?\*/)*\+(?:\s|//[^\n]*\n|/\*.*?\*/)*\Z", re.S)
_JS_UNITS = {"ms", "px", "kb", "mb", "gb", "tb", "s", "m", "h", "d"}
_JS_CSS_WORDS = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]*)*$")
# The statement assigns a class, a style or an id, so its words are names, not text.
_JS_NOT_TEXT_SINK = re.compile(r"(?:\bclassName|\.style(?:\.\w+)?|\.id|\bclassList\.\w+\(|"
                               r"setAttribute\(\s*['\"](?:class|id|style|data-[\w-]+)['\"]\s*,)\s*[+]?=?[^=;]*$")


def _js_splice_runs(source):
    """The literals of a JS file as `'…' + '…'` runs, comments allowed in a join: [(spans, lead, tail)].

    `lead`/`tail`: the run is joined by `+` to something that is not a literal before/after it.
    """
    runs = []
    for span in _js_string_spans(source):
        if runs and _JS_GAP.match(source[runs[-1][-1][3]:span[2]] + "\n") \
                and "+" in source[runs[-1][-1][3]:span[2]]:
            runs[-1].append(span)
        else:
            runs.append([span])
    out = []
    for run in runs:
        lead = re.search(r"\+(?:\s|//[^\n]*\n)*\Z", source[max(0, run[0][2] - 200):run[0][2]])
        tail = re.match(r"(?:\s|//[^\n]*\n)*\+", source[run[-1][3]:run[-1][3] + 200])
        out.append((run, bool(lead), bool(tail)))
    return out


_JS_INLINE_EDGE = r"(?:b|strong|em|u|span|code)"


def _js_edge_text(joined, side):
    """The text node at one end of a joined run: before its first tag, or after its last.

    Past an inline element's own tags: in 'Ban <strong>' + name + '</strong> from <strong>' the
    value sits inside <strong>, and " from " is still a piece of the sentence around it.
    """
    if side == "lead":
        joined = re.sub(r"\A(?:</%s>)+" % _JS_INLINE_EDGE, "", joined)
        seg = joined.split("<", 1)[0]
        return "" if ">" in seg else seg              # starts inside an opening tag: not text
    joined = re.sub(r"(?:<%s\b[^<>]*>)+\Z" % _JS_INLINE_EDGE, "", joined)
    seg = joined.rsplit(">", 1)[-1]
    return "" if "<" in seg else seg                  # ends inside a tag: not text


def _js_splice_prose(seg):
    """Whether the text at a join reads as words, not punctuation, a unit or a class list."""
    seg = re.sub(r"&\w+;", " ", seg)
    if re.search(r"[/=<>\"\[\]{};#\\(]$|[/=<>\"\[\]{};#\\]|^\s*[.&?-]", seg.strip()):
        return False                                  # a URL, a selector, an attribute, code
    words = seg.split()
    if words and all(_JS_CSS_WORDS.match(w) for w in words) and any("-" in w for w in words):
        return False                                  # 'btn text-wrap ' + cls
    return any(len(w) >= 2 and w.lower() not in _JS_UNITS
               for w in re.findall(r"[A-Za-z]*[a-z][A-Za-z]*", seg))


def spliced_js(js_dir=JS_DIR):
    """[(file, line, text)]: sentence words joined by `+` to a value in a script."""
    found = []
    for path in sorted(glob.glob(os.path.join(js_dir, "*.js"))):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        lines = source.splitlines()
        for run, lead, tail in _js_splice_runs(source):
            if not (lead or tail) or any(JS_IGNORE in lines[s[1] - 1] for s in run if s[1] <= len(lines)):
                continue
            stmt = source[max(0, run[0][2] - 300):run[0][2]].rsplit(";", 1)[-1]
            if _JS_NOT_TEXT_SINK.search(stmt):
                continue                              # a class list, a style, an id: not text
            joined = "".join(s[0] for s in run)
            for side, on in (("lead", lead), ("tail", tail)):
                seg = _js_edge_text(joined, side) if on else ""
                if _js_splice_prose(seg):
                    found.append((os.path.basename(path), run[0][1], seg.strip()))
    return sorted(set(found))


# A sentence split by emphasis: 'Click <strong>Repair database</strong> — it rebuilds…'. Each piece
# reaches the walker as its own node ("Click", "— it rebuilds…"), keys no translation can be written
# for, in English's order. Reported: prose OUTSIDE a bold/em element whose own text is prose, right
# beside it. ('<strong>1.</strong> Open this link' is a step number, not a split sentence.)
_JS_INLINE_OPEN = re.compile(r"<(b|strong|em|u)\b[^>]*>\Z")


def _js_emphasis_splits(joined):
    """The prose pieces of one literal run that sit beside an emphasised piece of prose."""
    parts, out = re.split(r"(<[^>]*>)", joined), []
    for i, part in enumerate(parts):
        if part.startswith("<") or not _js_splice_prose(part):
            continue
        # after a closing </b> whose element held prose, or before an opening <b> that does
        before = i >= 3 and re.fullmatch(r"</(b|strong|em|u)>", parts[i - 1]) \
            and _JS_INLINE_OPEN.match(parts[i - 3]) and _js_splice_prose(parts[i - 2])
        after = i + 3 < len(parts) and _JS_INLINE_OPEN.match(parts[i + 1]) \
            and _js_splice_prose(parts[i + 2]) and re.fullmatch(r"</(b|strong|em|u)>", parts[i + 3])
        if before or after:
            out.append(part.strip())
    return out


def emphasis_split_js(js_dir=JS_DIR):
    """[(file, line, text)]: sentence pieces split around bold or emphasised words in a script."""
    found = []
    for path in sorted(glob.glob(os.path.join(js_dir, "*.js"))):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        lines = source.splitlines()
        for run, _lead, _tail in _js_splice_runs(source):
            if any(JS_IGNORE in lines[s[1] - 1] for s in run if s[1] <= len(lines)):
                continue
            for text in _js_emphasis_splits("".join(s[0] for s in run)):
                found.append((os.path.basename(path), run[0][1], text))
    return sorted(set(found))


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
    """One DYNAMIC line per string welded to a {{ }}, where no catalog entry can reach it.

    Every one, in the catalog or not. One that is in it was skipped as "translated elsewhere as a
    standalone node; here it is just inert" — but inert is the defect: the node it sits in stays
    English ("root@host:22 · Auth: key" passed the gate because "· Auth:" was a key). `catalog` is
    kept for callers; it no longer decides anything.
    """
    del catalog
    for text, where in sorted(dynamic.items(), key=lambda kv: sorted(kv[1])[0]):
        print("  DYNAMIC  [%s] %r" % (",".join(sorted(where))[:40], text[:100]))


if __name__ == "__main__":
    raise SystemExit(_main())
