"""The Config tab's LinuxGSM settings form: LinuxGSM's own help for each setting, and its secrets.

LinuxGSM documents every setting in the game's _default.cfg, in the comment lines above it:

    #### LinuxGSM Settings ####                   a section (files._cfg_section_title groups by it)

    ## Backup | https://docs.linuxgsm.com/commands/backup      a heading, with its docs page
    maxbackups="4"

    # Discord Alerts | https://docs.linuxgsm.com/alerts/discord a sub-heading, until the next blank
    discordalert="off"
    discordwebhook="webhook"

    ## Game Server Login Token (GSLT): Required
    # GSLT is required for running a public server.            help for the setting below it
    # More info: https://docs.linuxgsm.com/steamcmd/gslt
    gslt=""

(read from GameServerManagers/LinuxGSM, lgsm/config-default/config-lgsm/*/_default.cfg). annotate
adds that help to each setting files.lgsm_read_config lists, the heading it sits under, a link to
docs.linuxgsm.com when the comments name a page there, and the file its value comes from.

form_view takes the secrets out of a read for a viewer who may not see them: the rule `details`
output follows (server_detail._dtl_sees_secrets — whoever can open the server's configs).
"""
import re

# The files LinuxGSM sources, LAST WINS (_core.LGSM_CFG_ORDER), highest first, as
# files.lgsm_read_config tags their frames; and the name each is shown under.
_CMPC_LAYERS = (("SECRETS_INSTANCE", "secrets-instance"), ("INSTANCE", "instance"),
                ("SECRETS_COMMON", "secrets-common"), ("COMMON", "common"), ("DEFAULT", "default"))
_CMPC_FILES = {"secrets-instance": "secrets-{name}.cfg", "instance": "{name}.cfg",
               "secrets-common": "secrets-common.cfg", "common": "common.cfg", "default": "_default.cfg"}
# An assignment, as files._CFG_LINE_RE reads one.
_CMPC_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
# `Title | https://…`: a heading naming its docs page (both `## ` and `# ` lines use it). Split on
# the first "|" in code rather than by one pattern, which could backtrack over the title's spaces.
_CMPC_URL_RE = re.compile(r"https?://\S+")
# The only link the form makes: a page of LinuxGSM's own docs. Anything else the comments name stays
# text. Checked whole, so nothing after the path (a quote, a space) can reach the page's href.
_CMPC_DOCS_RE = re.compile(r"https://docs\.linuxgsm\.com(?:/[A-Za-z0-9._~%/-]*)?(?:#[A-Za-z0-9._~%-]*)?")
# The file is the game account's to write, so what it holds is bounded before it reaches a page.
_CMPC_HELP_MAX, _CMPC_HEADING_MAX = 2000, 120

# Settings whose value is a credential, by name: passwords (serverpassword, rconpassword,
# betapassword, ntfypassword), tokens (telegramtoken, gotifytoken), keys (wsapikey,
# pushoveruserkey), the Steam server token (gslt), webhooks, which carry their own secret, and salts.
_CMPC_SECRET_RE = re.compile(r"pass|token|secret|key|gslt|webhook|salt|auth", re.I)
# Not named as secrets, but a server's start line is where a password or a GSLT is often written
# inline (`+rcon_password x`); `details` hides it for the same reason (_DTL_CMDLINE_HIDDEN).
_CMPC_MASK_ALSO = frozenset({"startparameters", "extraparams"})
MASK = "********"


def is_secret(key):
    """Whether setting `key` holds a credential, so a viewer who may not see secrets never gets it."""
    return bool(_CMPC_SECRET_RE.search(key or "")) or key in _CMPC_MASK_ALSO


def _cmpc_heading(body):
    """(title, url) when a comment's text is a `Title | https://…` heading, else None."""
    title, bar, url = body.partition("|")
    title, url = title.rstrip(), url.lstrip()
    if not (bar and title and _CMPC_URL_RE.fullmatch(url)):
        return None
    return title[:_CMPC_HEADING_MAX], url


def _cmpc_comment(st, s):
    """Read one comment line `s` (stripped) into the reader's state `st`."""
    body = s.lstrip("#")
    level, body = len(s) - len(body), body.strip()
    head = _cmpc_heading(body)
    if level == 2:
        st.update(h2=head or (body[:_CMPC_HEADING_MAX], ""), h1=None, pending=[])
    elif head:
        st.update(h1=head, pending=[])
    elif body:
        st["pending"].append(body)


def _cmpc_step(st, line):
    """Read one line of _default.cfg into `st`; the setting's name when the line assigns one."""
    s = line.strip()
    if not s:
        # A blank ends a `# Title | url` sub-heading and any help not followed by a setting.
        st.update(h1=None, pending=[])
        return None
    if s.startswith("###"):
        # A `#### Section ####` header (or the banner's rule of #s): nothing above it carries over.
        st.update(h2=None, h1=None, pending=[])
        return None
    if s.startswith("#"):
        _cmpc_comment(st, s)
        return None
    m = _CMPC_ASSIGN_RE.match(line)
    return m.group(1) if m else None


def _cmpc_docs(lines, head):
    """The docs.linuxgsm.com page for a setting: one its own comments name, else its heading's, or "".

    Only the heading it is shown under: a sub-heading whose page is no docs page links nothing,
    rather than the outer heading's page under the sub-heading's name.
    """
    urls = _CMPC_URL_RE.findall("\n".join(lines)) + ([head[1]] if head else [])
    return next((u for u in urls if _CMPC_DOCS_RE.fullmatch(u)), "")


def _cmpc_entry(st):
    """The help, heading and docs link for the setting the reader is on."""
    lines, head = st["pending"], st["h1"] or st["h2"]
    # A comment that is only a link is the docs link, not help to read.
    text = "\n".join(ln for ln in lines if not _CMPC_URL_RE.fullmatch(ln))
    return {"help": text[:_CMPC_HELP_MAX], "heading": head[0] if head else "", "docs": _cmpc_docs(lines, head)}


def parse_help(default_text):
    """{setting: {"help", "heading", "docs"}} from the comments of a _default.cfg.

    `help`: the comment lines directly above the setting (a setting right under another shares its
    heading but not that one's help). `heading`: the `## Heading` or `# Sub-heading | url` it sits
    under. `docs`: a docs.linuxgsm.com page those name, or "". A setting assigned twice keeps the
    help of its first line.
    """
    st, out = {"h2": None, "h1": None, "pending": []}, {}
    for line in (default_text or "").splitlines():
        key = _cmpc_step(st, line)
        if key is None:
            continue
        out.setdefault(key, _cmpc_entry(st))
        st["pending"] = []
    return out


def layer_of(key, layers):
    """Which file `key`'s value comes from: the last one LinuxGSM sources that sets it."""
    return next((name for tag, name in _CMPC_LAYERS if key in (layers.get(tag) or {})), "default")


def annotate(groups, default_text, layers, selfname):
    """Give each setting in `groups` its help, heading, docs link and the file its value comes from.

    `layers`: each frame's parsed settings, keyed by its tag (DEFAULT, COMMON, ...). In place; the
    return is the read's own flag: `default_missing`, when _default.cfg was there to read but empty
    or absent — the form then has nothing to list, and says why instead of showing nothing.
    """
    helps = parse_help(default_text)
    for grp in groups or ():
        for s in grp.get("settings") or ():
            s.update(helps.get(s["key"]) or {"help": "", "heading": "", "docs": ""})
            s["layer"] = layer_of(s["key"], layers)
            s["layer_file"] = _CMPC_FILES[s["layer"]].format(name=selfname)
    return {"default_missing": not (default_text or "").strip()}


def _cmpc_settings(d):
    """Every setting dict a config read carries: the grouped form's and the curated list's."""
    for grp in d.get("groups") or ():
        yield from grp.get("settings") or ()
    if isinstance(d.get("settings"), list):
        yield from d["settings"]


def form_view(d, actor=None):
    """The config read `d` as `actor` (default: the request's user) may have it.

    A viewer who may not see secrets (server_detail._dtl_sees_secrets) gets every secret setting's
    value and default as MASK, marked `masked` (the page makes those fields read-only, so a Save
    can never post the mask back), and no raw instance cfg at all — it holds the same values.
    """
    from panel.routes import server_detail as _sd
    who = actor
    if who is None:
        from flask_login import current_user
        who = current_user
    if _sd._dtl_sees_secrets(who):
        return d
    for s in _cmpc_settings(d):
        if is_secret(s.get("key")):
            s.update(value=MASK, default=MASK if s.get("default") else "", masked=True)
    d.update(raw="", raw_hidden=True)
    return d
