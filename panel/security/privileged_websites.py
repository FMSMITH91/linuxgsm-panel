"""The website verbs of the panel's privileged table (privileged._ARGV), kept beside it.

The same shapes tools/panel-helper holds for its website-* verbs: a site account is ws<digits> or
the tunnel connector's own account; the web proxy's release is x.y.z with its sha256; the page cache build's images are pinned by
digest and its module by an exact version; a quota is MB, a CPU share thousandths.
Every one is performed by the helper itself (an empty argv) and is local-only: they write root-owned
units, nftables and the proxy's binary, which no shell form reproduces, and ssh_manager.websites
refuses a host without the helper in words, so none ever reaches the remote branch.
privileged.py merges them into its table (install) after VerbError and _choice exist.
"""
import re

ACCOUNT_RE = r"ws[1-9][0-9]{0,8}"
TUNNEL_ACCOUNT = "lgsmtunnel"
IMAGE_RE = r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}"
# The verb whose document travels on the helper's stdin: the proxy configuration with any certificate an
# operator supplied. ssh_manager.websites runs it through the helper with that stdin itself.
STDIN_VERBS = frozenset({"website-proxy-apply"})


def _matcher(test, why, error):
    def check(s):
        s = str(s)
        if not test(s):
            raise error(why)
        return s
    return check


def argv(error, choice):
    """{verb: (validators, build, stdin)} for the website verbs; `error` is VerbError, `choice` _choice."""
    account = _matcher(lambda s: bool(re.fullmatch(ACCOUNT_RE, s)) or s == TUNNEL_ACCOUNT, "not a website account",
                       error)
    version = _matcher(lambda s: bool(re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", s)), "not a release version",
                       error)
    sha256 = _matcher(lambda s: bool(re.fullmatch(r"[0-9a-f]{64}", s)), "not a sha256", error)
    quota = _matcher(lambda s: s.isdecimal() and int(s) <= 10 * 1024 * 1024, "not a size in MB", error)
    image = _matcher(lambda s: bool(re.fullmatch(IMAGE_RE, s)), "not an image pinned by digest", error)
    module = _matcher(lambda s: bool(re.fullmatch(r"v[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", s)),
                      "not an exact module version", error)
    cpu = _matcher(lambda s: s.isdecimal() and 100 <= int(s) <= 64000, "not a CPU share in thousandths", error)
    validators = {
        "website-account-create": [account], "website-account-remove": [account],
        "website-proxy-install": [version, choice("amd64", "arm64"), sha256],
        "website-proxy-apply": [choice("start", "reload", "restart")], "website-proxy-stop": [],
        "website-proxy-rebind": [choice("start", "check")],
        "website-proxy-status": [], "website-egress-guard": [choice("on", "off")],
        "website-quota-set": [account, quota],
        "website-proxy-install-cache": [version, image, image, module], "website-cpu-limit": [account, cpu],
    }
    return {verb: (checks, lambda a: [], None) for verb, checks in validators.items()}


def install(table, error, choice):
    """Merge argv() into the privileged `table`; the website verbs, which are all local-only."""
    verbs = argv(error, choice)
    table.update(verbs)
    return frozenset(verbs)
