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
import ast
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
    # The title block renders into <head><title>, which the runtime walker never reads (it walks
    # document.body), so its text is translated on the server or not at all: through t() there,
    # which _expression_labels claims. Literal words left in it are reported (_r15c_title_words).
    src = re.sub(_R15C_TITLE_BLOCK, "", src, flags=re.S)
    # An if/elif/else/endif ends no text node in the rendered page: `{% if a %}Super Admin{% else
    # %}Standard{% endif %} · Account` is ONE node per branch, branch and neighbours together. Read
    # as a split, each half was found in the catalog and the welded whole, which the walker looks
    # up, was never asked for (review 1011e: three such nodes stayed English). Marked apart here;
    # handle_data rebuilds each branch's node where it can, and splits as before where it cannot.
    src = re.sub(r"\{%-?\s*if\b.*?%\}", _R15C_IF, src, flags=re.S)
    src = re.sub(r"\{%-?\s*elif\b.*?-?%\}", _R15C_ELIF, src, flags=re.S)
    src = re.sub(r"\{%-?\s*else\s*-?%\}", _R15C_ELSE, src, flags=re.S)
    src = re.sub(r"\{%-?\s*endif\s*-?%\}", _R15C_ENDIF, src, flags=re.S)
    src = re.sub(r"\{%.*?%\}", _SPLIT, src, flags=re.S)
    src = re.sub(r"\{\{.*?\}\}", _DYNAMIC, src, flags=re.S)
    return src


_R15C_IF, _R15C_ELIF, _R15C_ELSE, _R15C_ENDIF = "\x03", "\x06", "\x04", "\x05"
_R15C_BRANCH_MARKS = _R15C_IF + _R15C_ELIF + _R15C_ELSE + _R15C_ENDIF


def _r15c_as_splits(text):
    """`text` with every if/else/endif mark read as the plain split it was before."""
    return re.sub("[%s]" % _R15C_BRANCH_MARKS, _SPLIT, text)


def _r15c_branch_nodes(run):
    """The text nodes one run renders, one per way through the {% if %}s in it (nested ones too).

    None when the run holds no if, or marks this cannot pair (an element inside a branch puts its
    tags in different text runs): the marks are then read as splits, as before.
    """
    if not any(c in run for c in _R15C_BRANCH_MARKS):
        return None
    tokens = re.split("([%s])" % _R15C_BRANCH_MARKS, run)
    try:
        variants, _end = _r15c_expand(tokens, 0, False)
    except ValueError:
        return None
    return variants


_R15C_MAX_NODES = 64


def _r15c_if_branches(tokens, i):
    """(every text one {% if %}…{% endif %} starting after tokens[i-1] renders, the index past it)."""
    branches, has_else = [], False
    while True:
        got, i = _r15c_expand(tokens, i, True)
        branches.extend(got)
        if tokens[i] == _R15C_ENDIF:
            break
        has_else = has_else or tokens[i] == _R15C_ELSE
        i += 1                                        # past an elif/else: the next branch
    # With an else one branch always renders; without one, none may.
    return branches + ([] if has_else else [""]), i + 1


def _r15c_expand(tokens, i, inside):
    """(every text tokens[i:] renders up to a closing mark, where it stopped). ValueError: unpaired."""
    out = [""]
    while i < len(tokens):
        tok = tokens[i]
        if tok in (_R15C_ELIF, _R15C_ELSE, _R15C_ENDIF):
            if not inside:
                raise ValueError(tok)
            return out, i
        if tok == _R15C_IF:
            branches, i = _r15c_if_branches(tokens, i + 1)
            out = [o + b for o in out for b in branches]
            if len(out) > _R15C_MAX_NODES:
                raise ValueError("too many ways through")
            continue
        out = [o + tok for o in out]
        i += 1
    if inside:
        raise ValueError("unclosed if")
    return out, i


_R15C_TITLE_BLOCK = r"\{%\s*block title\s*%\}(.*?)\{%\s*endblock\s*%\}"


def _r15c_title_words(source):
    """The literal words of a template's title block: English in every tab, whatever the language.

    The block used to be dropped as "a gap no catalog entry could close", and every page's tab
    title stayed English; t() is in every template's context, so it can be closed there.
    """
    out = []
    for m in re.finditer(_R15C_TITLE_BLOCK, re.sub(r"\{#.*?#\}", "", source, flags=re.S), re.S):
        bare = re.sub(r"\{%.*?%\}|\{\{.*?\}\}", _SPLIT, m.group(1), flags=re.S)
        out.extend(part.strip() for part in bare.split(_SPLIT) if is_translatable(part))
    return out


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
            for branch in _r15c_as_splits(html.unescape(value)).split(_SPLIT):
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
            self._skipped_prose(_r15c_as_splits(data))
            return
        runs = []
        for run in data.split(_SPLIT):
            nodes = _r15c_branch_nodes(run)
            runs.extend(nodes if nodes is not None else _r15c_as_splits(run).split(_SPLIT))
        for run in runs:
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
    for text in _r15c_title_words(source):
        walker.dynamic.setdefault(text, set()).add("title")
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
_JS_T_CALL = re.compile(r"""\b(?:t|_discT|tf|tfHtml|tfn)\((?:[^;'"()]|'[^'\n]*'|"[^"\n]*"|\([^()]*\))*$""")


_R15C_QUOTED = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"")


def is_js_t_arg(text, before):
    """Is this literal an argument of t() / _discT(), given the source just `before` it?"""
    # Not the right-hand side of a comparison: t(action === 'stop' ? … : …) chooses by 'stop'.
    m = _JS_T_CALL.search(before)
    # Nor a VALUE of tf()/tfHtml(): `{dir: base || 'home'}` goes in untranslated, after the sentence.
    # Judged on the call with its quoted literals taken out: a template's own {placeholder} is no
    # values object, and read as one it left every template after it unclaimed (tfn's plural, the
    # second branch of a ternary), so a new sentence there passed the gate with no translation.
    call = _R15C_QUOTED.sub("", m.group(0)) if m else ""
    if call.startswith("tf") and "{" in call:
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
# Scanned by hand (_js_markup_matches), not by one regex: the regex form of it,
#   (?:<(?!/)([a-zA-Z0-9]*)([^<>]*)>|</i>|^([^<>]*)>)([^<>]+)</([a-zA-Z0-9]+)>
# backtracks super-linearly on a long run with no closing tag (SonarCloud S8786). Same matches.
_JS_CLOSE_TAG = re.compile(r"</[a-zA-Z0-9]+>")
_JS_ALNUM_RUN = re.compile(r"[a-zA-Z0-9]*")


class _MarkupMatch:
    """One opener + text + closing tag, shaped like the re.Match the regex above returned."""

    def __init__(self, at, groups):
        self._at, self._groups = at, groups

    def start(self):
        """Where the opener begins."""
        return self._at

    def group(self, i):
        """Groups 1-5: opener tag name, opener attributes, attributes before a leading `>`, text, closing name."""
        return self._groups[i - 1]


def _js_markup_opener(text, at):
    """(end, groups 1-3) of an opener at `at`: `<tag …>`, `</i>`, or (at 0) the tail of a tag `…>`; else None."""
    if at == 0 and text[:1] != "<":
        gt = text.find(">")
        return (gt + 1, (None, None, text[:gt])) if gt >= 0 and "<" not in text[:gt] else None
    if text.startswith("</i>", at):
        return at + 4, (None, None, None)
    if text[at + 1:at + 2] == "/":
        return None
    gt = text.find(">", at + 1)
    if gt < 0 or "<" in text[at + 1:gt]:
        return None
    inner = text[at + 1:gt]
    name = _JS_ALNUM_RUN.match(inner).group(0)
    return gt + 1, (name, inner[len(name):], None)


def _js_markup_at(text, at):
    """The match whose opener begins at `at` (an opener, text with no `<>`, a closing tag), or None."""
    opened = _js_markup_opener(text, at)
    if opened is None:
        return None
    end, (g1, g2, g3) = opened
    lt = text.find("<", end)
    if lt < 0 or lt == end or ">" in text[end:lt]:
        return None
    close = _JS_CLOSE_TAG.match(text, lt)
    return (_MarkupMatch(at, (g1, g2, g3, text[end:lt], close.group(0)[2:-1])), close.end()) if close else None


def _js_markup_matches(text):
    """Every element's whole text in `text`, left to right and not overlapping, as re.finditer would."""
    out, floor = [], 0
    for at in [0] + [i for i, c in enumerate(text) if c == "<" and i > 0]:
        found = _js_markup_at(text, at) if at >= floor else None
        if found:
            out.append(found[0])
            floor = found[1]
    return out


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
    # The last `<` before the guard, opening a tag still open there (no `>` after it). By hand, not
    # `<([a-zA-Z0-9]+)[^<>]*$`, which backtracks super-linearly on a long run of `<` (S8786).
    head = prefix[:at]
    lt = head.rfind("<")
    name = _JS_ALNUM_RUN.match(head, lt + 1).group(0) if lt >= 0 and ">" not in head[lt:] else ""
    return bool(name) and ("</%s>" % name.lower()) not in prefix[at:].lower()


def js_markup_texts(text):
    """The user-visible whole-element texts inside an innerHTML-built literal.

    Also a literal that STARTS inside an opening tag, after a splice:
    `'<a href="#"' + _da('x') + '>Advanced: use a pre-auth key instead</a>'` — the label is the
    element's whole text, and the opening tag being in the previous literal hid it.
    """
    out = []
    for m in _js_markup_matches(text):
        if _js_markup_skipped(m, text):
            continue              # the walker skips these, so nothing in them is asked for
        seg = re.sub(r"\s+", " ", html.unescape(m.group(4))).strip()
        if seg and _js_markup_claims(seg, (m.group(1) or m.group(5)).lower()):
            out.append(seg)
    return out


def _js_markup_skipped(m, text):
    """Whether a _js_markup_matches match sits where the walker never looks (code, pre, a guard)."""
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


# How far back a literal's t()/tf() call is looked for. 160 characters lost the call of a plural
# whose singular before it was longer than that (tfn(n, '<a long sentence>', '<its plural>', …)).
_R15C_LOOKBACK = 600


def _js_claim_parts(run, standalone, source):
    """(text, source before it) to judge: judged whole when nothing is spliced in; part by part otherwise."""
    if standalone and len(run) > 1:
        return [("".join(s[0] for s in run), source[max(0, run[0][2] - _R15C_LOOKBACK):run[0][2]])]
    return [(s[0], source[max(0, s[2] - _R15C_LOOKBACK):s[2]]) for s in run]


def _js_run_claims(run, standalone, source):
    """The user-visible texts one run of literals (from _js_literal_runs) makes, as a list."""
    before = source[max(0, run[0][2] - _R15C_LOOKBACK):run[0][2]]
    joined = "".join(s[0] for s in run)
    whole = _js_whole_claim(joined, before) if standalone else None
    if whole:
        return [whole]
    out = [text for text, bef in _js_claim_parts(run, standalone, source) if _js_claims(text, bef)]
    out.extend(text for s in run for text in js_markup_texts(s[0]))
    return out + _js_icon_tail(joined, standalone)


# An icon, then words to the END of a literal with nothing spliced on: `'<i class="bi …"></i> Updates
# installed.'`. The words are the element's whole text, but the closing tag is in no literal (the
# element was opened earlier, or its parent closes it), so _JS_MARKUP_TEXT never matched them:
# "Starting Tailscale…", "Backing up…" and eleven more were English with the gate green.
_JS_ICON_TAIL = re.compile(r"(?:</i>|<i\b[^<>]*></i>)([^<>]+)\Z")


def _js_icon_tail(joined, standalone=True):
    """The words after a trailing icon in a standalone run of literals, as one claimed text."""
    m = _JS_ICON_TAIL.search(joined) if standalone else None
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
def _js_gap_is_plus(gap):
    r"""Whether the source between two literals is one `+`, with blanks and comments around it.

    Scanned token by token, not by `(?:\s|//[^\n]*\n|/\*.*?\*/)*\+(…)*\Z`, which can backtrack
    exponentially (SonarCloud S5852). A `//` comment must end in a newline, as the regex asked.
    """
    i, pluses = 0, 0
    while i < len(gap):
        if gap[i].isspace():
            i += 1
        elif gap.startswith("//", i):
            nl = gap.find("\n", i)
            if nl < 0:
                return False
            i = nl + 1
        elif gap.startswith("/*", i):
            close = gap.find("*/", i + 2)
            if close < 0:
                return False
            i = close + 2
        elif gap[i] == "+":
            pluses, i = pluses + 1, i + 1
        else:
            return False
    return pluses == 1


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
        if runs and _js_gap_is_plus(source[runs[-1][-1][3]:span[2]] + "\n"):
            runs[-1].append(span)
        else:
            runs.append([span])
    out = []
    for run in runs:
        before = source[max(0, run[0][2] - 200):run[0][2]]
        after = source[run[-1][3]:run[-1][3] + 200]
        out.append((run, _r15c_plus_before(before), _r15c_plus_after(after)))
    return out


def _r15c_skip_blank(text, i):
    """Index of the first character at or after `i` that is not a blank or inside a comment.

    `/* */` as well as `//`, as the joins inside a run (_js_gap_is_plus) take them: the edges of a
    run took only `//`, so `n + /* count */ ' items left'` was never reported as a splice.
    len(text) when the rest is all blanks and comments; -1 inside an unclosed comment.
    """
    while i < len(text):
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            nl = text.find("\n", i)
            if nl < 0:
                return -1
            i = nl + 1
        elif text.startswith("/*", i):
            close = text.find("*/", i + 2)
            if close < 0:
                return -1
            i = close + 2
        else:
            return i
    return i


def _r15c_plus_after(text):
    """Whether `text` (what follows a run) starts with a `+`, past blanks and comments."""
    i = _r15c_skip_blank(text, 0)
    return 0 <= i < len(text) and text[i] == "+"


def _r15c_plus_before(text):
    """Whether `text` (what precedes a run) ends with a `+` and then only blanks and comments.

    Tried at each `+` from the right, so a `+` inside a trailing comment is not taken for the join.
    """
    i = text.rfind("+")
    while i >= 0:
        if _r15c_skip_blank(text + "\n", i + 1) == len(text) + 1:
            return True
        i = text.rfind("+", 0, i)
    return False


_JS_INLINE_EDGE = r"(?:b|strong|em|u|span|code)"


def _js_edge_text(joined, side):
    """The text node at one end of a joined run: before its first tag, or after its last.

    Past an inline element's own tags: in 'Ban <strong>' + name + '</strong> from <strong>' the
    value sits inside <strong>, and " from " is still a piece of the sentence around it.
    """
    if side == "lead":
        joined = re.sub(r"\A(?:</%s>)+" % _JS_INLINE_EDGE, "", joined)
        seg = joined.split("<", 1)[0]
        if ">" in seg:
            return ""                                 # starts inside an opening tag: not text
        return seg if seg.strip() else _r15c_span_at_edge(joined, side)
    joined = re.sub(r"(?:<%s\b[^<>]*>)+\Z" % _JS_INLINE_EDGE, "", joined)
    seg = joined.rsplit(">", 1)[-1]
    if "<" in seg:
        return ""                                     # ends inside a tag: not text
    return seg if seg.strip() else _r15c_span_at_edge(joined, side)


# A bare <span> of prose with only blanks between it and the join: '<span>Tailscale is not installed
# on</span> <strong>' + name + '</strong>.' The text node at the join is the blank, so the edge read
# above found nothing, yet the span holds the sentence's first half and no catalog key can be
# written for the whole of it (review 1011e). An attributed span (`<span class="badge">`) is a label
# of its own, not half a sentence; so is one word beside a count ('3 <span>banned</span>'), which is
# split from its number on purpose so the word is a node the walker can translate.
_R15C_SPAN_TAIL = re.compile(r"<span>([^<>]*)</span>\s*\Z")
_R15C_SPAN_LEAD = re.compile(r"\A\s*<span>([^<>]*)</span>")


def _r15c_span_at_edge(joined, side):
    """The text of a bare <span> that sits, past blanks only, at the join's end of `joined`."""
    m = (_R15C_SPAN_LEAD.match(joined) if side == "lead" else _R15C_SPAN_TAIL.search(joined))
    return m.group(1) if m and len(m.group(1).split()) > 1 else ""


def _js_splice_prose(seg):
    """Whether the text at a join reads as words, not punctuation, a unit or a class list."""
    seg = re.sub(r"&\w+;", " ", seg)
    if re.search(r"[/=<>\"\[\]{};#\\(]$|[/=<>\"\[\]{};#\\]|^\s*[.&?-]", seg.strip()):
        return False                                  # a URL, a selector, an attribute, code
    if "_" in seg and re.fullmatch(r"\w+", seg.strip()):
        return False                                  # an identifier: '__i18nA_' + attr
    return not _js_css_list(seg) and _js_has_word(seg)


def _js_css_list(seg):
    """Whether `seg` is a CSS class list: 'btn text-wrap ' + cls."""
    words = seg.split()
    return bool(words) and all(_JS_CSS_WORDS.match(w) for w in words) and any("-" in w for w in words)


def _js_has_word(seg):
    """Whether `seg` holds a word of two letters or more, with a lower-case one, that is not a unit.

    Plain letter runs, then a test: the one-regex form `[A-Za-z]*[a-z][A-Za-z]*` backtracks
    super-linearly on a long upper-case run (SonarCloud S8786).
    """
    return any(len(w) >= 2 and w.lower() not in _JS_UNITS and w != w.upper()
               for w in re.findall(r"[A-Za-z]+", seg))


def _js_ignored(run, lines):
    """Whether any literal of a run sits on an `i18n-ignore` line."""
    return any(JS_IGNORE in lines[s[1] - 1] for s in run if s[1] <= len(lines))


def _js_run_splices(run, lead, tail, source):
    """The sentence words at a run's `+` joins, unless the statement writes a class, style or id."""
    stmt = source[max(0, run[0][2] - 300):run[0][2]].rsplit(";", 1)[-1]
    if _JS_NOT_TEXT_SINK.search(stmt):
        return []                                     # a class list, a style, an id: not text
    joined = "".join(s[0] for s in run)
    segs = [_js_edge_text(joined, side) for side, on in (("lead", lead), ("tail", tail)) if on]
    return [seg.strip() for seg in segs if _js_splice_prose(seg)]


def spliced_js(js_dir=JS_DIR):
    """[(file, line, text)]: sentence words joined by `+` to a value in a script."""
    found = []
    for path in sorted(glob.glob(os.path.join(js_dir, "*.js"))):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        lines = source.splitlines()
        for run, lead, tail in _js_splice_runs(source):
            if (lead or tail) and not _js_ignored(run, lines):
                found.extend((os.path.basename(path), run[0][1], seg)
                             for seg in _js_run_splices(run, lead, tail, source))
            if not _js_ignored(run, lines):
                found.extend((os.path.basename(path), s[1], seg)
                             for s in run for seg in _r15c_template_splices(s, source))
    return sorted(set(found))


def _r15c_template_splices(span, source):
    """The prose around each `${…}` of a backtick literal: the same splice as `+`, spelled otherwise.

    `Saved ${n} files` reaches the page as one node no key can match, and none of the checks above
    could see it: the literal holds `$` and `{`, so it was never claimed, and nothing is joined by `+`.
    """
    text, _line, start, _end = span
    if source[start:start + 1] != "`" or "${" not in text:
        return []
    return [seg.strip() for seg in re.split(r"\$\{[^{}]*\}", text) if _js_splice_prose(seg)]


# A sentence split by emphasis: 'Click <strong>Repair database</strong> — it rebuilds…'. Each piece
# reaches the walker as its own node ("Click", "— it rebuilds…"), keys no translation can be written
# for, in English's order. Reported: prose OUTSIDE a bold/em element whose own text is prose, right
# beside it. ('<strong>1.</strong> Open this link' is a step number, not a split sentence.)
_JS_INLINE_OPEN = re.compile(r"<(b|strong|em|u)\b[^>]*>\Z")


def _js_emphasised(parts, at):
    """Whether parts[at:at+3] is a bold/em element (open tag, text, close tag) holding prose."""
    return bool(0 <= at and at + 2 < len(parts) and _JS_INLINE_OPEN.match(parts[at])
                and _js_splice_prose(parts[at + 1]) and re.fullmatch(r"</(b|strong|em|u)>", parts[at + 2]))


def _js_emphasis_splits(joined):
    """The prose pieces of one literal run that sit beside an emphasised piece of prose."""
    parts = re.split(r"(<[^>]*>)", joined)
    # after a closing </b> whose element held prose, or before an opening <b> that does
    return [part.strip() for i, part in enumerate(parts)
            if not part.startswith("<") and _js_splice_prose(part)
            and (_js_emphasised(parts, i - 3) or _js_emphasised(parts, i + 1))]


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


# ── Python: sentences a route or service sends the viewer ──────────────────────────────────────
# A flash, a form answer or a JSON "message"/"error"/"warning" reaches the page as one text node, and
# the walker above only swaps EXACT catalog text. Built with an f-string, `%`, `+` or .format(), it
# is a different string for every value it carries ("Group 'ops' created."), so no catalog key can
# ever match it: es/fr viewers read English. Such a sentence goes through panel.core.i18n.tr — the
# WHOLE sentence is the key, with named {slots}, and the values go in after. Reported here: every
# such sink fed a built string directly, through a local variable assigned one in the same function,
# or through a call to a function (anywhere scanned) that returns one. A line holding PY_IGNORE is
# skipped — for a string that is not shown to anyone (the reason goes beside the marker).
PY_IGNORE = "i18n-ignore"
PY_SINK_CALLS = ("flash", "_form_err", "_form_ok", "_form_credential")
PY_SINK_KEYS = ("message", "error", "warning")


def _py_files(root):
    """app.py and every .py under panel/."""
    paths = [os.path.join(root, "app.py")]
    for path in sorted(glob.glob(os.path.join(root, "panel", "**", "*.py"), recursive=True)):
        paths.append(path)
    return paths


def _py_call_name(node):
    """The called name of a Call (`f(…)` or `x.f(…)`), else None."""
    if not isinstance(node, ast.Call):
        return None
    return getattr(node.func, "id", None) or getattr(node.func, "attr", None)


def _py_text(node):
    """Whether a node is a str literal."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _py_built_binop(node, plain):
    """`%` (any: the template may be a constant held elsewhere, BUSY % host) or `+` with text."""
    if isinstance(node.op, ast.Mod):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.left.value, (int, float)))
    if isinstance(node.op, ast.Add):
        return any(_py_built(n, plain) or _py_text(n) for n in (node.left, node.right))
    return False


def _py_built(node, plain=False):
    """Whether an expression BUILDS a string from text and values (f-string, %, +, .format()).

    An i18n.Sentence counts, unless `plain`: it is English, remembering how it was built, and a sink
    still has to pass it through tr. `plain` asks the other question — is this English that tr()
    could never translate, because it was built before tr saw it?
    """
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _py_built_binop(node, plain)
    if isinstance(node, ast.IfExp):
        return _py_built(node.body, plain) or _py_built(node.orelse, plain)
    name = _py_call_name(node)
    return (name in ("Sentence", "Sentences") and not plain) or (name == "format" and _py_text(node.func.value))


class _PyBuilders(dict):
    """_py_builders' table, carrying which question it answers (see _py_built's `plain`)."""

    plain = False


def _py_call_sinks(node, wrappers):
    """The message arguments of a sink call, or of a wrapper's sink parameter."""
    name = _py_call_name(node)
    out = [node.args[0]] if name in PY_SINK_CALLS and node.args else []
    out.extend(k.value for k in node.keywords if k.arg in PY_SINK_KEYS)
    for pos, param in wrappers.get(name, ()):
        if pos is not None:
            out.extend(node.args[pos:pos + 1])
        out.extend(k.value for k in node.keywords if k.arg == param)
    return out


def _py_sink_values(node, wrappers=None):
    """The expressions a node hands the viewer as a message.

    `wrappers` ({function name: {(position, parameter name)}}) are the panel's own functions that
    pass a parameter straight to a sink (`_changed(message, …)` answers jsonify({"message": message})).
    """
    if isinstance(node, ast.Call):
        return _py_call_sinks(node, wrappers or {})
    if isinstance(node, ast.Dict):
        return [v for k, v in zip(node.keys, node.values) if _py_sink_key(k)]
    if isinstance(node, ast.Assign):     # reply["message"] = …
        return [node.value for t in node.targets if isinstance(t, ast.Subscript) and _py_sink_key(t.slice)]
    return []


def _py_sink_key(node):
    """Whether a dict key or subscript is "message", "error" or "warning"."""
    return _py_text(node) and node.value in PY_SINK_KEYS


def _py_ignored(lines, node):
    """Whether any line of `node` carries the PY_IGNORE marker."""
    return any(PY_IGNORE in lines[n - 1] for n in range(node.lineno, (node.end_lineno or node.lineno) + 1)
               if n <= len(lines))


def _py_trees(root):
    """[(relpath, source lines, ast)] for every scanned file."""
    out = []
    for path in _py_files(root):
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        out.append((os.path.relpath(path, root), source.splitlines(), ast.parse(source)))
    return out


def _py_unpacked(n, builders):
    """[(local name, line)] that `ok, msg = f(…)` binds from a tuple builder's built items.

    `ok, msg = f(…) if c else g(…)` (or `f(…) or g(…)`) asks each call.
    """
    names = [_py_call_name(v) for v in [n.value] + _py_operands(n.value)]
    return [(elt.id, builders[(name, i)][1]) for t in n.targets if isinstance(t, ast.Tuple)
            for i, elt in enumerate(t.elts) for name in names
            if isinstance(elt, ast.Name) and (name, i) in builders]


def _py_assigned(fn, lines, builders):
    """{local name: line} for each local of one function assigned a built string.

    Unpacking counts: `ok, msg = svc(…)` binds `msg` built when svc returns (…, a built string).
    """
    assigned = {}
    for n in _py_own_nodes(fn):
        if isinstance(n, (ast.Assign, ast.AugAssign)) and not _py_ignored(lines, n):
            for local, line in _py_assignment_binds(n, assigned, builders):
                assigned.setdefault(local, line)
    return assigned


def _py_assignment_binds(n, assigned, builders):
    """[(local name, line)] one assignment binds to a built string (see _py_assigned)."""
    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
    built = ((isinstance(n, ast.AugAssign) and isinstance(n.op, ast.Add))
             or _py_fed_built(n.value, assigned, builders) is not None)
    out = [(t.id, n.lineno) for t in targets if built and isinstance(t, ast.Name)]
    # `res = svc(…)` then `flash(res[1])`: (res, 1) is bound when svc's item 1 is built (_r16c_).
    callee = _py_call_name(n.value) if isinstance(n, ast.Assign) else None
    out += [((t.id, k[1]), builders[k][1]) for t in targets if isinstance(t, ast.Name)
            for k in builders if isinstance(k, tuple) and k[0] == callee]
    return out + (_py_unpacked(n, builders) if isinstance(n, ast.Assign) else [])


def _py_functions(tree):
    """Every function defined in a module, nested ones included."""
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _py_returns_built(fn, lines, builders):
    """{key: line} for `fn`'s returns of a built string (see _py_builders).

    The key is the function's name for a returned string, and (name, i) for item i of a returned
    tuple — the `(ok, message)` every service answers with.
    """
    assigned = _py_assigned(fn, lines, builders)
    found = {}
    for n in _py_own_nodes(fn):
        if isinstance(n, ast.Return) and n.value is not None and not _py_ignored(lines, n):
            for key in _py_return_keys(fn.name, n.value, assigned, builders):
                found.setdefault(key, n.lineno)
    return found


def _py_return_keys(name, value, assigned, builders):
    """The _py_builders keys one `return value` of function `name` earns."""
    items = list(enumerate(value.elts)) if isinstance(value, ast.Tuple) else [(None, value)]
    keys = [name if i is None else (name, i) for i, item in items
            if _py_fed_built(item, assigned, builders) is not None]
    # `return other(…)`: whatever items of other's tuple are built, this one's are too.
    callee = _py_call_name(value)
    return keys + [(name, k[1]) for k in builders if isinstance(k, tuple) and k[0] == callee]


def _py_builders(trees, plain=False):
    """{function name or (name, item): (file, line)} for every function that returns a built string.

    Directly, or a local it built, or another builder's answer — or as an item of a returned tuple.
    Repeated until nothing new is found.
    """
    found = _PyBuilders()
    found.plain = plain
    while True:
        before = len(found)
        for rel, lines, tree in trees:
            for fn in _py_functions(tree):
                for key, line in _py_returns_built(fn, lines, found).items():
                    found.setdefault(key, (rel, line))
        if len(found) == before:
            return found


def _py_operands(value):
    """The operands that decide whether `a or b`, `a if c else b` or `a + b` was built."""
    if isinstance(value, ast.BoolOp):
        return value.values
    if isinstance(value, ast.IfExp):
        return [value.body, value.orelse]
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        return [value.left, value.right]
    return []


def _py_fed_built(value, assigned, builders):
    """Where a sink's value was built, or None when it was not.

    Itself, a local assigned one, a builder's return, or (for `a or b`, `a if c else b` and `a + b`)
    any operand that is one of those.
    """
    if _py_built(value, getattr(builders, "plain", False)):
        return value.lineno
    if isinstance(value, ast.Name) and value.id in assigned:
        return assigned[value.id]
    if (isinstance(value, ast.Subscript) and isinstance(value.value, ast.Name)
            and isinstance(value.slice, ast.Constant) and (value.value.id, value.slice.value) in assigned):
        return assigned[(value.value.id, value.slice.value)]
    if _py_call_name(value) in builders:
        return builders[_py_call_name(value)]
    for operand in _py_operands(value):
        where = _py_fed_built(operand, assigned, builders)
        if where is not None:
            return where
    return None


def _py_own_nodes(fn):
    """Every node of one function (or module) body, not those of a function defined inside it.

    A route registrar defines its routes as nested functions: walking it whole mixed every route's
    locals into one table, so a `msg` built in one route was "found" feeding another's answer.
    """
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))


def _py_wrapped_params(fn, lines, wrappers):
    """{(position, parameter)} of `fn`'s parameters that it hands to a sink as they are."""
    params = [a.arg for a in fn.args.args]
    if params[:1] in (["self"], ["cls"]):
        params = params[1:]     # obj.method(a, …): `a` is the parameter after self
    # A keyword-only parameter (`def _reply(*, message)`) is passed by name only: position None.
    kwonly = [a.arg for a in fn.args.kwonlyargs]
    return {(params.index(v.id) if v.id in params else None, v.id)
            for n in _py_own_nodes(fn) for v in _py_sink_values(n, wrappers)
            if isinstance(v, ast.Name) and (v.id in params or v.id in kwonly) and not _py_ignored(lines, v)}


def _py_wrappers(trees):
    """{function name: {(position, parameter)}}: functions that hand a parameter to a sink as it is.

    Repeated until nothing new is found, so a wrapper of a wrapper counts too.
    """
    wrappers = {}
    while True:
        before = sum(len(v) for v in wrappers.values())
        for _rel, lines, tree in trees:
            for fn in _py_functions(tree):
                got = _py_wrapped_params(fn, lines, wrappers)
                if got:
                    wrappers.setdefault(fn.name, set()).update(got)
        if sum(len(v) for v in wrappers.values()) == before:
            return wrappers


# A service (panel/services, panel/ops) hands its payload BACK to a route, which translates it
# (host_reboot.shown): an i18n.Sentence in a payload there — one that is built, but not in plain
# English — is the hand-off, not the page. In a
# route or app.py the same Sentence reaching jsonify/flash untranslated is English on the page.
_PY_PAYLOAD_DIRS = ("panel/services/", "panel/ops/")


def _py_function_splices(rel, lines, fn, tables, wrappers):
    """[(file, line, where built)] for one function's (or module's) sinks fed a built string.

    `tables` is (builders, plain builders): see _py_built's `plain`.
    """
    builders, plain = tables
    assigned = _py_assigned(fn, lines, builders)
    payload = rel.replace(os.sep, "/").startswith(_PY_PAYLOAD_DIRS)
    plain_assigned = _py_assigned(fn, lines, plain) if payload else {}
    found = []
    for n in _py_own_nodes(fn):
        for value in _py_sink_values(n, wrappers):
            if _py_ignored(lines, value) or (payload and _py_fed_built(value, plain_assigned, plain) is None):
                continue
            where = _py_fed_built(value, assigned, builders)
            if where is not None:
                found.append((rel, value.lineno, where))
    return found


def _py_tr_fed(rel, lines, fn, plain_builders):
    """[(file, line, where built)]: an i18n.tr() handed English built before it (never a key)."""
    assigned = _py_assigned(fn, lines, plain_builders)
    return [(rel, n.lineno, where) for n in _py_own_nodes(fn)
            if _py_call_name(n) == "tr" and n.args and not _py_ignored(lines, n.args[0])
            for where in [_py_fed_built(n.args[0], assigned, plain_builders)] if where is not None]


def spliced_py(root=ROOT):
    """[(file, line, where built)]: a message for the viewer built from text and values, untranslatable.

    Two ways: a sink fed a built string (or an untranslated Sentence) — and an i18n.tr() fed a string
    built in plain English, by an f-string, `%` or `+` anywhere upstream (a service's `(ok, message)`
    unpacked by the route included): tr() can only look that up, never match it.
    """
    trees = _py_trees(root)
    builders, wrappers = _py_builders(trees), _py_wrappers(trees)
    plain = _py_builders(trees, plain=True)
    found = [hit for rel, lines, tree in trees for fn in [tree] + _py_functions(tree)
             for hit in _py_function_splices(rel, lines, fn, (builders, plain), wrappers)
             + _py_tr_fed(rel, lines, fn, plain)]
    return sorted(set(found), key=repr)


def _py_module_consts(tree):
    """{name: text} for a module's top-level `NAME = "literal"` assignments."""
    return {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign) and _py_text(n.value)
            for t in n.targets if isinstance(t, ast.Name)}


def tr_keys_py(root=ROOT):
    """{key: "file:line"} for every literal sentence handed to i18n.tr or i18n.Sentence.

    A module constant handed to one counts too.
    """
    keys = {}
    for rel, _lines, tree in _py_trees(root):
        consts = _py_module_consts(tree)
        for n in ast.walk(tree):
            for key in (k for a in _py_key_args(n) for k in _py_key_texts(a, consts) if k):
                keys.setdefault(key, "%s:%d" % (rel, n.lineno))
    return keys


def _py_key_args(n):
    """The arguments of a tr()/Sentence()/Sentences() call that are sentences to translate.

    Sentences(…) says each of its parts, and its separator, through tr(): a literal one is a key too.
    """
    name = _py_call_name(n)
    if name in ("tr", "Sentence"):
        return n.args[:1]
    if name == "Sentences":
        return n.args + [k.value for k in n.keywords if k.arg == "sep"]
    return []


def _py_key_texts(arg, consts):
    """The sentence(s) one tr()/Sentence() first argument can be.

    A literal, a module constant, or each branch of `a if c else b` / `a or b`.
    """
    if _py_text(arg):
        return [arg.value]
    if isinstance(arg, ast.Name) and arg.id in consts:
        return [consts[arg.id]]
    if isinstance(arg, ast.IfExp):
        return _py_key_texts(arg.body, consts) + _py_key_texts(arg.orelse, consts)
    if isinstance(arg, ast.BoolOp):
        return [k for v in arg.values for k in _py_key_texts(v, consts)]
    return []


def tr_gaps_py(lang, root=ROOT, translation_dir=TRANSLATION_DIR):
    """[(key, problem)]: a tr() sentence missing from `lang`, or translated with other {slots}."""
    catalog = load_catalog(lang, translation_dir)
    slot = re.compile(r"\{(\w+)\}")
    gaps = []
    for key in sorted(tr_keys_py(root)):
        if key not in catalog:
            gaps.append((key, "missing"))
        elif sorted(slot.findall(key)) != sorted(slot.findall(catalog[key])):
            gaps.append((key, "slots differ"))
    return gaps


# ── What a route ANSWERS, followed into the service that worded it (_r16c_) ─────────────────────
# tr_keys_py collects only the literal FIRST ARGUMENT of tr()/Sentence(). A route that answers
# jsonify({"message": msg}) with a module constant (close_port22's _NO_WAY_BACK), or with the
# message of a service's (ok, message) — "Port 22 rule removed from UFW", or the lockout guard's
# "Couldn't read the firewall…" two calls down in ssh_manager/hosts.py, whether or not the route
# then calls tr(msg) — handed the viewer a sentence no gate read: 259 of them had no es/fr entry.
# Here every literal a route's sink or tr() can be handed is a key: written there, a module
# constant, or an item of a service's returned tuple, followed through locals unpacked from
# another call and through `return other(…)`, to where it is written.
def _r16c_prose(text):
    """Whether a literal is a sentence for a person, not a code ("ALREADY_CONNECTED", "bad_mode")."""
    return " " in text.strip() and bool(_HAS_LETTER.search(text)) and not text.startswith("\\")


def _r16c_binds(fn):
    """{local: [(callee, item index or None)]} for `a, b = f(…)` and `x = f(…)` in one function.

    `f(…) if c else g(…)` and `f(…) or g(…)` bind from each call.
    """
    out = {}
    for n in _py_own_nodes(fn):
        if not (isinstance(n, ast.Assign) and len(n.targets) == 1):
            continue
        names = [c for c in (_py_call_name(v) for v in [n.value] + _py_operands(n.value)) if c]
        t = n.targets[0]
        pairs = ([(e, i) for i, e in enumerate(t.elts)] if isinstance(t, ast.Tuple) else [(t, None)])
        for e, i in pairs:
            if isinstance(e, ast.Name):
                out.setdefault(e.id, []).extend((c, i) for c in names)
    return out


def _r16c_item_sources(node, consts, binds):
    """(texts, refs) one returned item or sink value can be: literals, and (callee, index) to follow."""
    if node is None:
        return [], []
    texts = list(_py_key_texts(node, consts))
    refs = list(binds.get(node.id, ())) if isinstance(node, ast.Name) else []
    # `why[1]`, where `why = f(…)`: item 1 of what f answers.
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
            and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int)):
        refs += [(c, node.slice.value) for c, i in binds.get(node.value.id, ()) if i is None]
    for operand in _py_operands(node):
        t, r = _r16c_item_sources(operand, consts, binds)
        texts += t
        refs += r
    return texts, refs


def _r16c_returns(trees):
    """{(function, item index or None): set((text, file, line))}: the literals a function answers.

    A tuple's items by index, a plain return as None; through locals bound from other calls and
    `return other(…)`, repeated until nothing new is found.
    """
    direct, refs = {}, {}
    for rel, lines, tree in trees:
        consts = _py_module_consts(tree)
        for fn in _py_functions(tree):
            binds = _r16c_binds(fn)
            for n in _py_own_nodes(fn):
                if not isinstance(n, ast.Return) or n.value is None or _py_ignored(lines, n):
                    continue
                items = (list(enumerate(n.value.elts)) if isinstance(n.value, ast.Tuple)
                         else [(None, n.value)])
                for i, item in items:
                    texts, follow = _r16c_item_sources(item, consts, binds)
                    direct.setdefault((fn.name, i), set()).update((t, rel, n.lineno) for t in texts)
                    refs.setdefault((fn.name, i), set()).update(follow)
                callee = _py_call_name(n.value)
                if callee:     # `return other(…)`: whatever other answers, item for item
                    refs.setdefault(("*", fn.name), set()).add(callee)
    return _r16c_resolve(direct, refs)


def _r16c_resolve(direct, refs):
    """direct + everything reachable through refs (see _r16c_returns), to a fixed point."""
    table = {k: set(v) for k, v in direct.items()}
    while True:
        before = sum(len(v) for v in table.values())
        for (name, i), follow in list(refs.items()):
            if name == "*":
                for (other, j), got in list(table.items()):
                    if other in follow:
                        table.setdefault((i, j), set()).update(got)
                continue
            for callee, j in follow:
                table.setdefault((name, i), set()).update(table.get((callee, j), ()))
        if sum(len(v) for v in table.values()) == before:
            return table


def _r16c_is_route(rel):
    rel = rel.replace(os.sep, "/")
    return rel == "app.py" or rel.startswith("panel/routes/")


def route_answer_keys(root=ROOT):
    """{key: "file:line"} for every sentence a route can hand the viewer as a message, or to tr().

    Its sinks (flash, _form_*, a "message"/"error"/"warning" in a reply) and its tr() arguments:
    a literal, a module constant, or a service's answer (see _r16c_returns). Codes are left out.
    """
    trees = _py_trees(root)
    table = _r16c_returns(trees)
    keys = {}
    for rel, lines, tree in trees:
        if not _r16c_is_route(rel):
            continue
        consts = _py_module_consts(tree)
        for fn in [tree] + _py_functions(tree):
            binds = _r16c_binds(fn)
            for n in _py_own_nodes(fn):
                values = list(_py_sink_values(n))
                if _py_call_name(n) == "tr" and n.args:
                    values.append(n.args[0])
                for v in values:
                    if _py_ignored(lines, v):
                        continue
                    texts, follow = _r16c_item_sources(v, consts, binds)
                    found = [(t, rel, v.lineno) for t in texts]
                    found += [x for ref in follow for x in table.get(ref, ())]
                    for t, f, line in found:
                        if _r16c_prose(t):
                            keys.setdefault(t, "%s:%d" % (f, line))
    return keys


def route_answer_gaps(lang, root=ROOT, translation_dir=TRANSLATION_DIR):
    """[(key, where)]: a sentence a route can answer (route_answer_keys) with no `lang` entry."""
    catalog = load_catalog(lang, translation_dir)
    return sorted((k, w) for k, w in route_answer_keys(root).items() if k not in catalog)


# ── A job's progress text: written in English by a worker, translated when it is read (_r16c_) ──
# An install or bootstrap worker runs with no viewer, so it stores its step names as they are and
# install-status / bootstrap-status hand them to tr() for whoever asks. None of those names was a
# key, and no gate read this path: tr() got a subscript (j["step_name"]), never a literal, so
# every step of every install and bootstrap stayed English in Spanish and French. Every literal
# handed to a job writer, or stored as a job's step_name or message, is a key here; one BUILT in
# plain English (an f-string, %, +) is reported, because no key can ever match it.
_R16C_STEP_WRITERS = ("progress", "p", "_p", "_set", "fail", "_fail", "emit", "note", "_end", "finish")
_R16C_JOB_KEYS = ("step_name", "message")
_R16C_LABEL = re.compile(r"^[A-Z][a-z]+(?:…|\.\.\.|\.)?$")


def _r16c_step_values(n):
    """The values one node hands a job as its progress text (see _R16C_STEP_WRITERS)."""
    if isinstance(n, ast.Call) and _py_call_name(n) in _R16C_STEP_WRITERS:
        return list(n.args)
    if isinstance(n, ast.Dict):
        return [v for k, v in zip(n.keys, n.values) if _py_text(k) and k.value == "step_name"]
    if isinstance(n, ast.Assign):
        out = []
        for t in n.targets:
            pairs = (list(zip(t.elts, n.value.elts)) if isinstance(t, ast.Tuple) and isinstance(n.value, ast.Tuple)
                     else [(t, n.value)])
            out += [v for tt, v in pairs if isinstance(tt, ast.Subscript) and _py_text(tt.slice)
                    and tt.slice.value in _R16C_JOB_KEYS]
        return out
    return []


def _r16c_step_walk(root):
    """[(file, line, value node, consts, binds, lines)] for every job progress value in the tree."""
    out = []
    for rel, lines, tree in _py_trees(root):
        consts = _py_module_consts(tree)
        for fn in [tree] + _py_functions(tree):
            binds = _r16c_binds(fn)
            out += [(rel, v.lineno, v, consts, binds, lines) for n in _py_own_nodes(fn)
                    for v in _r16c_step_values(n) if not _py_ignored(lines, v)]
    return out


def step_name_keys(root=ROOT):
    """{key: "file:line"} for every literal a job's progress text can be (see _R16C_STEP_WRITERS)."""
    table = _r16c_returns(_py_trees(root))
    keys = {}
    for rel, line, v, consts, binds, _lines in _r16c_step_walk(root):
        texts, follow = _r16c_item_sources(v, consts, binds)
        found = [(t, rel, line) for t in texts] + [x for ref in follow for x in table.get(ref, ())]
        for t, f, ln in found:
            if _r16c_prose(t) or _R16C_LABEL.match(t):
                keys.setdefault(t, "%s:%d" % (f, ln))
    return keys


def step_names_built(root=ROOT):
    """[(file, line)]: a job's progress text built in plain English, which no key can match."""
    plain = _PyBuilders()
    plain.plain = True
    return sorted({(rel, line) for rel, line, v, _c, _b, _l in _r16c_step_walk(root)
                   if any(_py_built(x, plain=True) for x in [v] + _py_operands(v))})


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
