"""Fast unit tests for the pure-logic helpers — no network, no SSH, no live DB.

These lock in the behaviour of the parsing/classification code where subtle bugs
tend to hide: firewall rule grouping + lock-out protection, game-port selection,
password policy, safe int parsing, and secret encryption. Several of these would
have caught real regressions (wrong protocol split, opening non-essential ports,
deleting the last SSH rule, a non-numeric port 500).

    python tests/unit_test.py      # exits 0 if all pass, 1 otherwise
"""
import json
import glob
import os
import re
import sys
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import privileged as _privmod
import ssh_manager as sm
import notifications as N
import system_ops as SO
from app import (password_problem, _int_or, _valid_ip_or_cidr, _whitelisted, _parse_tg_command,
                 _tg_command_arg, _valid_hex_color, _clean_console_text, _apply_user_order,
                 _apply_user_server_order)
from auth import can_access_remote, client_ip

results = []


def check(name, cond, detail=""):
    results.append((bool(cond), name, detail))


def eq(name, got, want):
    check(name, got == want, "got %r want %r" % (got, want))


# ── perf guard: importing `auth` must NOT compute the ~400ms bcrypt "dummy" hash.
#    It's lazy (computed on the first bad-login attempt, warmed off-thread by init_auth)
#    so panel startup stays fast — a regression here re-adds ~0.4s to every boot. This
#    runs BEFORE the dummy_password_check() call later in this file, which is what
#    actually populates it. ──
check("perf: auth import does no bcrypt work (dummy hash stays lazy)",
      sys.modules["auth"]._DUMMY_BCRYPT_HASH is None)

# ── password policy ───────────────────────────────────────────
check("weak: too short", password_problem("Ab1!") is not None)
check("weak: no upper", password_problem("test1234!@") is not None)
check("weak: no lower", password_problem("TEST1234!@") is not None)
check("weak: no digit", password_problem("TestTest!@") is not None)
check("weak: no symbol", password_problem("TestTest12") is not None)
check("strong password accepted", password_problem("Test1234!@") is None)

# ── accent colour (Settings → Branding) is emitted into a CSS custom property, so it MUST be a
#    strict #rrggbb literal — never arbitrary text that could carry `}`/`<` and break out. ──
eq("hex colour: valid passes through (lowercased)", _valid_hex_color("#10B981"), "#10b981")
eq("hex colour: bare 6-hex gets a '#'", _valid_hex_color("1a2b3c"), "#1a2b3c")
eq("hex colour: surrounding whitespace trimmed", _valid_hex_color("  #ABCDEF "), "#abcdef")
eq("hex colour: blank -> '' (use built-in)", _valid_hex_color(""), "")
eq("hex colour: None -> ''", _valid_hex_color(None), "")
eq("hex colour: 3-digit shorthand rejected", _valid_hex_color("#fff"), "")
eq("hex colour: named colour rejected", _valid_hex_color("red"), "")
eq("hex colour: CSS/HTML breakout rejected", _valid_hex_color("#fff;}</style><script>"), "")
eq("hex colour: too long rejected", _valid_hex_color("#1234567"), "")

# ── remote fail2ban helpers: the remote unban docstring says it mirrors the panel-host version and
# it did not — no jail allowlist, .match (which accepts a trailing newline against a ^…$ pattern),
# and no IP canonicalisation, so unbanning 2001:0DB8::0001 silently missed the stored 2001:db8::1.
_F2B_STATUS = "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, panel-auth\n"
_F2B_JAIL = ("Status for the jail: sshd\n   |- Currently banned: 1\n   |- Total banned: 3\n"
             "   |- Total failed: 0\n   `- Banned IP list: 10.0.0.9\n")


def _f2b_fake_run(server, cmd, **kw):
    # These are the commands privileged.py renders for the SSH transport, so match on the argv
    # shape rather than on a `2>` suffix that the verb rendering no longer always adds.
    parts = cmd.split()
    if parts[:2] == ["fail2ban-client", "status"]:
        return ((_F2B_JAIL if len(parts) > 2 and not parts[2].startswith("2>") else _F2B_STATUS),
                "", 0)
    if "command -v fail2ban-client" in cmd:
        return ("yes", "", 0)
    return ("1", "", 0)


_orig_f2b = sm.run_command
try:
    sm.run_command = _f2b_fake_run
    eq("f2b remote: a non-canonical IPv6 is normalised before unbanning",
       sm.remote_fail2ban_unban(None, "sshd", "2001:0DB8::0001"),
       (True, "Unbanned 2001:db8::1 from sshd."))
    check("f2b remote: an unknown jail is refused against the host's own list",
          sm.remote_fail2ban_unban(None, "nosuch", "10.0.0.9")[0] is False)
    check("f2b remote: a non-IP is refused",
          sm.remote_fail2ban_unban(None, "sshd", "not-an-ip")[0] is False)
    check("f2b remote: a trailing newline in the jail name is stripped, not accepted raw",
          sm.remote_fail2ban_unban(None, "sshd\n", "10.0.0.9") == (True, "Unbanned 10.0.0.9 from sshd."))
finally:
    sm.run_command = _orig_f2b
eq("f2b: _canonical_ip normalises", sm._canonical_ip(" 2001:0DB8::0001 "), "2001:db8::1")
eq("f2b: _canonical_ip rejects junk", sm._canonical_ip("nope"), None)
check("f2b: _valid_ip still answers a bool", sm._valid_ip("10.0.0.1") is True)

# ── config keys must agree with the code that reads them ────────────────────────────────────────
# Each of these was a real divergence: a documented ssh_timeout nothing read (the two SSH paths
# hardcoded 15 and 12), and an autoblock threshold that defaulted to 20 when read and 100 when
# saved — so saving Settings once made the panel five times more permissive than documented.
import config as _cfgmod
import ssh_manager as _smod
check("config: every DEFAULT_CONFIG key has a reader",
      all(k in open("app.py").read() + open("ssh_manager.py").read() + open("system_ops.py").read()
          + open("notifications.py").read() + open("backup.py").read()
          for k in _cfgmod.DEFAULT_CONFIG),
      str([k for k in _cfgmod.DEFAULT_CONFIG
           if k not in open("app.py").read() + open("ssh_manager.py").read()
           + open("system_ops.py").read() + open("notifications.py").read() + open("backup.py").read()]))
check("config: ssh_timeout is actually used by the SSH layer",
      _smod._ssh_connect_timeout() == _cfgmod.DEFAULT_CONFIG["ssh_timeout"],
      "helper returned %r" % _smod._ssh_connect_timeout())
check("config: the autoblock default is one constant, not two",
      "_AUTOBLOCK_DEFAULT_THRESHOLD), 100000)" in open("app.py").read())

# ── terminal.py: ONE renderer, because this had drifted into four incompatible ANSI regexes and two
# carriage-return rules that contradicted each other (each docstring calling the other wrong).
import terminal as _term
eq("terminal: SGR colour stripped", _term.strip_escapes("\x1b[31mred\x1b[0m"), "red")
eq("terminal: erase-line stripped (an SGR-only regex left a literal '[K')",
   _term.strip_escapes("a\x1b[Kb"), "ab")
eq("terminal: private modes stripped (a CSI-only-with-letters regex left these)",
   _term.strip_escapes("\x1b[?2004ha\x1b[?1l"), "a")
eq("terminal: two-byte escapes stripped (these rendered as '>' and '=')",
   _term.strip_escapes("\x1b>a\x1b=b\x1b(Bc"), "abc")
eq("terminal: OSC window title stripped", _term.strip_escapes("\x1b]0;title\x07x"), "x")
eq("terminal: control CHARACTERS are left for the renderers", _term.strip_escapes("a\rb\bc"), "a\rb\bc")
eq("terminal: \\r overwrites from column 0", _term.apply_carriage_returns("abcdef\rXY"), "XYcdef")
eq("terminal: a line ENDING in \\r keeps its content (split('\\r')[-1] would lose it)",
   _term.apply_carriage_returns("done\r"), "done")
eq("terminal: backspaces erase", _term.apply_backspaces("ab\b\bxy"), "xy")
eq("terminal: render_line does all three", _term.render_line("\x1b[31ms\b\x1b[0msay hi\r"), "say hi")
eq("terminal: render treats \\r\\n as a line break", _term.render("a\r\nb"), "a\nb")
eq("terminal: empty input is returned unchanged", _term.render(""), "")

# ── console cleaning: Minecraft/Paper's JLine console writes ANSI escapes (incl. \x1b[K -> a visible
#    "[K"), carriage returns, and bare "> " prompt lines into its log. Strip them for display; leave
#    plain-text (Source/CoD/GMod) consoles untouched. ──
_mc_raw = ("\x1b[K[02:46:21 INFO]: UUID of player Kitty is abc\n> \n"
           "\x1b[K[02:46:21 INFO]: Connection closed\n> \n")
_mc_clean = _clean_console_text(_mc_raw)
check("console: JLine \\x1b[K erase-line removed (no visible '[K')", "[K" not in _mc_clean)
check("console: bare '> ' prompt lines dropped",
      not any(ln.strip() == ">" for ln in _mc_clean.split("\n")))
check("console: real log lines preserved",
      "[02:46:21 INFO]: UUID of player Kitty is abc" in _mc_clean
      and "[02:46:21 INFO]: Connection closed" in _mc_clean)
eq("console: ANSI colour codes stripped",
   _clean_console_text("\x1b[0;32mgreen\x1b[0m text"), "green text")
# A carriage return OVERWRITES from column 0 — it does not start a new line. Rendering it as a
# newline (the old behaviour) split JLine's prompt-erase into stray blank lines.
eq("console: \\r overwrites from column 0 instead of starting a line",
   _clean_console_text("abc\rX"), "Xbc")
eq("console: a line merely ENDING in \\r is still shown in full",
   _clean_console_text("> say hi\r"), "> say hi")
eq("console: \\r\\n is a real line break", _clean_console_text("first\r\nsecond"), "first\nsecond")
# JLine re-renders a typed command with syntax colour by erasing and rewriting it. Without applying
# backspaces every discarded attempt stays on screen: "say hi" reads as "ssasay  hi".
eq("console: backspaces erase, as a terminal would",
   _clean_console_text("> s\bsa\b\bsay hi"), "> say hi")
eq("console: two-byte escapes (ESC> / ESC=) are stripped, not shown as '>' and '=>'",
   _clean_console_text("\x1b[?1l\x1b>\x1b[?1000l\x1b=\x1b[?2004hdone"), "done")
eq("console: an OSC window-title sequence is stripped",
   _clean_console_text("\x1b]0;a title\x07ready"), "ready")
# The real thing: bytes taken verbatim from the panel's own Minecraft console log, where a typed
# "say hi" rendered as "> ssasay  hi" followed by ">=>" noise.
_jline_real = ("> s\b\x1b[31msa\x1b[0m\x1b[K\b\bsay\x1b[K\x1b[31m \x1b[0m\b \x1b[36mh\x1b[0m"
               "\x1b[K\x1b[36mi\x1b[0m\r\r\n"
               "\x1b[?1l\x1b>\x1b[?1000l\x1b[?2004l\x1b[?1h\x1b=\x1b[?2004h> \r\x1b[K"
               "[23:52:54 INFO]: [Not Secure] [Server] hi\r\n")
_jline_clean = _clean_console_text(_jline_real)
eq("console: a real JLine command echo renders as typed",
   [ln for ln in _jline_clean.split("\n") if ln.strip()],
   ["> say hi", "[23:52:54 INFO]: [Not Secure] [Server] hi"])
check("console: no control characters survive to the browser",
      not any(ord(c) < 32 and c != "\n" for c in _jline_clean), repr(_jline_clean[:80]))
eq("console: an echoed command line ('> list') is kept",
   _clean_console_text("> list"), "> list")
eq("console: plain Source/CoD line untouched",
   _clean_console_text("L 01/01/2026 - 12:00: player connected"),
   "L 01/01/2026 - 12:00: player connected")
eq("console: empty input -> empty", _clean_console_text(""), "")

# ── safe int parsing (a non-numeric port must not raise) ──────
eq("_int_or valid", _int_or("2222", 22), 2222)
eq("_int_or blank -> default", _int_or("", 22), 22)
eq("_int_or junk -> default", _int_or("abc", 22), 22)
eq("_int_or None -> default", _int_or(None, 5000), 5000)
eq("_int_or whitespace", _int_or("  80 ", 1), 80)

# ── per-user layout order: _apply_user_order is the single chokepoint every page's ordering goes
# through, so its edge cases are the whole feature's correctness. "No saved order" MUST mean "the
# list you passed in, untouched" — that is what keeps the default layout the default.
_ord_items = [NS(id=1), NS(id=2), NS(id=3), NS(id=4)]
_ids = lambda seq: [o.id for o in seq]
eq("order: no saved order leaves the default alone", _ids(_apply_user_order(_ord_items, None)), [1, 2, 3, 4])
eq("order: empty saved order leaves the default alone", _ids(_apply_user_order(_ord_items, [])), [1, 2, 3, 4])
eq("order: a full saved order is applied", _ids(_apply_user_order(_ord_items, [3, 1, 4, 2])), [3, 1, 4, 2])
eq("order: items missing from the order keep their default order, after the ordered ones",
   _ids(_apply_user_order(_ord_items, [4, 2])), [4, 2, 1, 3])
eq("order: ids that no longer exist are ignored (a host was deleted)",
   _ids(_apply_user_order(_ord_items, [99, 3, 42, 1])), [3, 1, 2, 4])
eq("order: junk entries are skipped, the rest still applies",
   _ids(_apply_user_order(_ord_items, ["2", None, {}, 1])), [2, 1, 3, 4])
eq("order: a duplicated id does not displace its first position",
   _ids(_apply_user_order(_ord_items, [3, 1, 3])), [3, 1, 2, 4])
eq("order: an all-junk order is the same as no order", _ids(_apply_user_order(_ord_items, ["x", None])),
   [1, 2, 3, 4])
check("order: the input list is never mutated in place",
      (_apply_user_order(_ord_items, [4, 3, 2, 1]) is not _ord_items) and _ids(_ord_items) == [1, 2, 3, 4])
eq("order: a custom key function is honoured (ordering by something other than .id)",
   [o.rid for o in _apply_user_order([NS(rid=7), NS(rid=8)], [8, 7], key=lambda o: o.rid)], [8, 7])
# Per-host server order. The dashboard slices ONE flat list per host, so this pass must reorder each
# host's members WITHOUT disturbing anything else about the list — a host with no saved order, and the
# positions the other hosts occupy, both have to come out untouched.
_srv = lambda i, r: NS(id=i, remote_id=r)
_mixed = [_srv(10, 1), _srv(11, 2), _srv(12, 1), _srv(13, 2), _srv(14, 1)]
_sids = lambda seq: [o.id for o in seq]
eq("server order: no saved order leaves the list alone", _sids(_apply_user_server_order(_mixed, {})),
   [10, 11, 12, 13, 14])
eq("server order: a junk pref value leaves the list alone",
   _sids(_apply_user_server_order(_mixed, {"server_order": "not a dict"})), [10, 11, 12, 13, 14])
eq("server order: one host is reordered within its own slots, other hosts untouched",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"1": [14, 12, 10]}})),
   [14, 11, 12, 13, 10])
eq("server order: two hosts reordered independently",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"1": [12, 10, 14], "2": [13, 11]}})),
   [12, 13, 10, 11, 14])
eq("server order: a host with no entry keeps its default order",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"2": [13, 11]}})),
   [10, 13, 12, 11, 14])
eq("server order: ids from another host cannot pull a server across hosts",
   _sids(_apply_user_server_order(_mixed, {"server_order": {"1": [11, 13, 14]}})),
   [14, 11, 10, 13, 12])
eq("server order: an int key (not the JSON string key) is ignored, not crashed on",
   _sids(_apply_user_server_order(_mixed, {"server_order": {1: [14, 12, 10]}})),
   [10, 11, 12, 13, 14])
check("server order: the input list is not mutated",
      (_apply_user_server_order(_mixed, {"server_order": {"1": [14, 10, 12]}}) is not _mixed)
      and _sids(_mixed) == [10, 11, 12, 13, 14])
# ui_prefs accessors: a corrupt or NULL blob must degrade to the default layout, never raise into a
# page render, and only whitelisted keys may take effect (a retired key stops working on upgrade).
_UsrP = __import__("models").User
_up = _UsrP()
check("ui_prefs: unset column reads as no preferences", _up.get_ui_prefs() == {})
_up.ui_prefs = "not json at all"
check("ui_prefs: a corrupt blob reads as no preferences", _up.get_ui_prefs() == {})
_up.ui_prefs = '["a","list","not","a","dict"]'
check("ui_prefs: a non-object blob reads as no preferences", _up.get_ui_prefs() == {})
_up.ui_prefs = '{"host_order": [2, 1], "evil_key": "x"}'
check("ui_prefs: only whitelisted keys are returned",
      _up.get_ui_prefs() == {"host_order": [2, 1]})
_up.set_ui_pref("host_order", [3, 2])
check("ui_prefs: set writes a whitelisted key", _up.get_ui_prefs()["host_order"] == [3, 2])
_up.set_ui_pref("not_a_key", [1])
check("ui_prefs: set ignores a non-whitelisted key", "not_a_key" not in _up.get_ui_prefs())
_up.set_ui_pref("host_order", None)
check("ui_prefs: clearing a key restores the default (absent, not empty)",
      _up.get_ui_prefs() == {} and "host_order" not in (_up.ui_prefs or ""))

# ── new-user language: Settings holds a concrete language code. It used to allow a blank
# "creator's language" value which read as English anyway — confusing on the page, so it is gone.
from app import _new_user_language as _nul
_LANGS = {"en": "English", "es": "Espanol", "fr": "Francais"}
eq("new-user lang: the configured language is used", _nul({"default_language": "fr"}, _LANGS), "fr")
eq("new-user lang: English when configured so", _nul({"default_language": "en"}, _LANGS), "en")
eq("new-user lang: a blank left over from an older install reads as English",
   _nul({"default_language": ""}, _LANGS), "en")
eq("new-user lang: a missing key reads as English", _nul({}, _LANGS), "en")
eq("new-user lang: a language no longer supported cannot be assigned",
   _nul({"default_language": "de"}, _LANGS), "en")
eq("new-user lang: junk in the config cannot be assigned", _nul({"default_language": 42}, _LANGS), "en")

# ── the install default layout: a superadmin's published arrangement sits UNDER each user's own, and
# the merge is per-KEY so someone who only reordered their tiles still gets the house host order.
from app import _effective_prefs as _ep
_U = lambda prefs: NS(is_authenticated=True, get_ui_prefs=lambda: prefs)
eq("default: no default and no user prefs -> nothing", _ep(_U({}), {}), {})
eq("default: the install default applies when the user has none",
   _ep(_U({}), {"default_ui_prefs": {"host_order": [2, 1]}}), {"host_order": [2, 1]})
eq("default: the user's own key wins over the default",
   _ep(_U({"host_order": [1, 2]}), {"default_ui_prefs": {"host_order": [2, 1]}}),
   {"host_order": [1, 2]})
eq("default: merge is per-key, not all-or-nothing",
   _ep(_U({"panels": {"dash_tiles": ["host"]}}),
       {"default_ui_prefs": {"host_order": [2, 1], "panels": {"dash_tiles": ["total"]}}}),
   {"host_order": [2, 1], "panels": {"dash_tiles": ["host"]}})
eq("default: a non-whitelisted key in the published default is ignored",
   _ep(_U({}), {"default_ui_prefs": {"host_order": [1], "evil": "x"}}), {"host_order": [1]})
eq("default: a junk default is ignored", _ep(_U({}), {"default_ui_prefs": "nope"}), {})
eq("default: an anonymous visitor still gets the house layout",
   _ep(NS(is_authenticated=False), {"default_ui_prefs": {"host_order": [3]}}), {"host_order": [3]})


class _BoomPrefs:
    is_authenticated = True

    def get_ui_prefs(self):
        raise RuntimeError("db gone")


eq("default: a failure reading user prefs falls back to the house layout, no raise",
   _ep(_BoomPrefs(), {"default_ui_prefs": {"host_order": [9]}}), {"host_order": [9]})

# ── movable panels: _panel_layout decides what a page renders and in what order. The safety property
# is that it can only ever return keys the PAGE declared — several panels are permission-gated, so a
# stored key must never be able to conjure one.
from app import _panel_layout as _pl, _clean_panel_map as _cpm
_KEYS = ["total", "online", "offline", "players", "host"]
eq("panels: no prefs -> the page's own default order", _pl({}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: a saved order is applied",
   _pl({"panels": {"dash_tiles": ["host", "total"]}}, "dash_tiles", _KEYS),
   (["host", "total", "online", "offline", "players"], []))
eq("panels: a key the page did not declare cannot appear",
   _pl({"panels": {"dash_tiles": ["evil_panel", "host"]}}, "dash_tiles", _KEYS),
   (["host", "total", "online", "offline", "players"], []))
eq("panels: a hidden key is removed from visible and reported as hidden",
   _pl({"hidden": {"dash_tiles": ["offline"]}}, "dash_tiles", _KEYS),
   (["total", "online", "players", "host"], ["offline"]))
eq("panels: hiding an undeclared key is a no-op",
   _pl({"hidden": {"dash_tiles": ["nope"]}}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: another region's layout does not leak in",
   _pl({"panels": {"other": ["host"]}}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: junk pref shapes fall back to the default",
   _pl({"panels": "nope", "hidden": 7}, "dash_tiles", _KEYS), (_KEYS, []))
eq("panels: a duplicated key is not rendered twice",
   _pl({"panels": {"dash_tiles": ["host", "host", "total"]}}, "dash_tiles", _KEYS),
   (["host", "total", "online", "offline", "players"], []))
eq("panels: a panel added by a NEW version appears for an existing user",
   _pl({"panels": {"dash_tiles": ["host", "total"]}}, "dash_tiles", _KEYS + ["brand_new"]),
   (["host", "total", "online", "offline", "players", "brand_new"], []))
eq("panels: an empty declared list renders nothing", _pl({"panels": {"dash_tiles": ["host"]}},
   "dash_tiles", []), ([], []))
# _clean_panel_map guards what gets STORED: cosmetic data, so junk is dropped, not rejected.
eq("panels: a clean map survives", _cpm({"dash_tiles": ["total", "host"]}), {"dash_tiles": ["total", "host"]})
eq("panels: non-dict input -> empty", _cpm("nope"), {})
eq("panels: a bad region name is dropped", _cpm({"Bad Region!": ["total"]}), {})
eq("panels: bad keys are dropped, good ones kept",
   _cpm({"dash_tiles": ["total", "<script>", "", 42, "host"]}), {"dash_tiles": ["total", "host"]})
eq("panels: duplicate keys are collapsed", _cpm({"r": ["a", "a", "b"]}), {"r": ["a", "b"]})
check("panels: key count is capped", len(_cpm({"r": ["k%d" % i for i in range(200)]})["r"]) == 60)
check("panels: region count is capped", len(_cpm({"r%d" % i: ["a"] for i in range(50)})) == 20)

# ── tags: the name charset is pinned at the DATA layer, so no route can store one that would need
# escaping to be safe in HTML, in a filter key, or in alert text.
_TagM = __import__("models").ServerTag
for _good in ("production", "PvE", "source games", "cs-1.6", "v2.0_beta", "A"):
    try:
        _TagM(name=_good)
        _ok = True
    except ValueError:
        _ok = False
    check("tag name accepted: %r" % _good, _ok)
for _bad in ("<script>", "drop; table", "tag'name", 'tag"name', " leading", "", "x" * 33,
             "emoji🎮", "back\\slash", "semi;colon"):
    try:
        _TagM(name=_bad)
        _rej = False
    except ValueError:
        _rej = True
    check("tag name rejected: %r" % _bad, _rej)
# _alerts_muted: any tag saying "don't alert" wins, and it must never raise inside a poller thread.
from notifications import alerts_muted as _am   # moved out of app.py in #93
_tg = lambda n: NS(notify=n)
check("mute: no tags -> not muted", _am(NS(tags=[], short_name="s")) is False)
check("mute: all tags notify -> not muted", _am(NS(tags=[_tg(True), _tg(True)], short_name="s")) is False)
check("mute: one muting tag wins", _am(NS(tags=[_tg(True), _tg(False)], short_name="s")) is True)
check("mute: None tags -> not muted", _am(NS(tags=None, short_name="s")) is False)


class _BoomTags:
    short_name = "boom"

    @property
    def tags(self):
        raise RuntimeError("db gone")


check("mute: a failure fails OPEN (alert still sent, no raise)", _am(_BoomTags()) is False)

# ── transports must decode leniently: command output is GAME SERVER output (player names, mod
# chatter, latin-1 logs), so it is not guaranteed valid UTF-8. A strict decode raises inside
# subprocess, gets swallowed by the generic handler, and returns ("", ..., -1) — a caller then
# cannot tell "printed nothing" from "could not be decoded". The paramiko path already used
# errors="replace"; these two did not.
_bad_out, _bad_err, _bad_rc = sm._run_local(r"printf 'caf\351: cannot start\n'", timeout=10, sudo=False)
check("transport (local): invalid UTF-8 in stdout still returns the text",
      _bad_rc == 0 and _bad_out.startswith("caf") and "cannot start" in _bad_out)
check("transport (local): the undecodable byte becomes U+FFFD, not a lost result",
      "�" in _bad_out and _bad_out != "")
_bad2_out, _bad2_err, _bad2_rc = sm._run_local(r"printf 'x\200y\n' >&2; printf 'ok\n'",
                                               timeout=10, sudo=False)
check("transport (local): invalid UTF-8 on stderr does not blank stdout",
      _bad2_rc == 0 and _bad2_out == "ok" and _bad2_err.startswith("x"))
_sshkw = {}


class _FakeCompleted:
    stdout = "out"
    stderr = ""
    returncode = 0


_orig_sprun = sm.subprocess.run
try:
    sm.subprocess.run = lambda cmd, **kw: (_sshkw.update(kw), _FakeCompleted())[1]
    sm._run_via_ssh_cli(type("S", (), {"sudo_enabled": False, "linuxgsm_user": None, "port": 22,
                                       "username": "u", "host": "h", "auth_method": "tailscale"})(),
                        "echo hi", timeout=5, sudo=False)
finally:
    sm.subprocess.run = _orig_sprun
check("transport (ssh cli): decodes with errors='replace' like the other two",
      _sshkw.get("errors") == "replace" and _sshkw.get("encoding") == "utf-8"
      and _sshkw.get("text") is True)

# ── cron manager (pure logic; no crontab touched) ─────────────
# schedule validation
check("cron: 5-field ok", sm._validate_cron("*/5 * * * *", "/bin/true")[0])
check("cron: @daily ok", sm._validate_cron("@daily", "/home/gm/backup.sh")[0])
check("cron: @reboot ok", sm._validate_cron("@reboot", "echo hi")[0])
check("cron: ranges/steps ok", sm._validate_cron("0-30/2 1,3 * * mon-fri", "x")[0])
check("cron: normalises inner ws", sm._validate_cron("0   5  *  *  *", "x")[2] == "0 5 * * * x")
check("cron: 4 fields rejected", not sm._validate_cron("* * * *", "x")[0])
check("cron: bad @shortcut rejected", not sm._validate_cron("@sometimes", "x")[0])
check("cron: empty command rejected", not sm._validate_cron("@daily", "")[0])
check("cron: newline in command rejected", not sm._validate_cron("@daily", "a\nb")[0])
check("cron: embedded CR rejected", not sm._validate_cron("@daily", "a\rb")[0])
check("cron: embedded CR in schedule rejected", not sm._validate_cron("0 5 *\r* *", "x")[0])
check("cron: shell metachars allowed in command", sm._validate_cron("@daily", "a && b | c")[0])
# NOTHING is locked any more — every line is editable/deletable, including the panel-installed ones.
check("cron: monitor is NOT managed (editable/deletable)",
      not sm._cron_line_managed("*/5 * * * * /home/gm/gmodserver monitor > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: daily-restart flag is NOT managed (editable/deletable)",
      not sm._cron_line_managed("0 5 * * * touch /home/gm/.restart-pending", "gm", "gmodserver"))
check("cron: legacy @reboot start is NOT managed (deletable)",
      not sm._cron_line_managed("@reboot /home/gm/gmodserver start > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: user backup line is NOT managed",
      not sm._cron_line_managed("0 3 * * * /home/gm/backup.sh", "gm", "gmodserver"))
# _cron_role gives panel lines a non-blocking LABEL so the admin knows what they are.
check("cron role: monitor is labelled 'autostart'",
      sm._cron_role("/home/gm/gmodserver monitor", "gm", "gmodserver") == "autostart")
check("cron role: a .restart-pending line is labelled 'daily-restart'",
      sm._cron_role("[ -f /home/gm/.restart-pending ] && /home/gm/gmodserver restart", "gm", "gmodserver") == "daily-restart")
check("cron role: update / user jobs carry no label",
      sm._cron_role("/home/gm/gmodserver update", "gm", "gmodserver") == ""
      and sm._cron_role("/home/gm/backup.sh", "gm", "gmodserver") == "")
# _wrap_cron_command keeps the monitor marker VISIBLE (inline recorder) so a reschedule doesn't hide it
# from the Autostart detection; the .restart-pending line stays verbatim; a `%` command uses base64.
_wmon = sm._wrap_cron_command(None, "gm", "/home/gm/gmodserver monitor")
check("cron wrap: a plain command (monitor) stays visible, not base64-hidden",
      "/home/gm/gmodserver monitor" in _wmon and ".lgsm-cron/run " not in _wmon)
check("cron wrap: the .restart-pending flag line is kept verbatim",
      sm._wrap_cron_command(None, "gm", "[ -f /home/gm/.restart-pending ] && x")
      == "[ -f /home/gm/.restart-pending ] && x")
_orig_wrap_rc = sm.run_command
try:
    sm.run_command = lambda *a, **k: ("", "", 0)   # _install_cron_runner touches SSH on the base64 path
    _wpct = sm._wrap_cron_command(None, "gm", "echo %H")
    check("cron wrap: a '%' command uses the base64 runner (cron-safe)",
          ".lgsm-cron/run " in _wpct and "%H" not in _wpct)
finally:
    sm.run_command = _orig_wrap_rc

# node-tools auto-update: a weekly ROOT cron keeps npm + gamedig (player-query tools) current.
check("node-tools: the cron updates npm + gamedig weekly and logs it",
      "npm install -g npm gamedig" in sm._NODE_TOOLS_CRON
      and sm._NODE_TOOLS_CRON.lstrip().startswith("#")
      and "/var/log/lgsm-node-tools.log" in sm._NODE_TOOLS_CRON
      and _privmod.WRITE_TARGETS["node-tools-cron"][0] == "/etc/cron.d/lgsm-node-tools")
_ntc = {}
_orig_ntc_rc = sm.run_command
try:
    # This used to assert the command started with "sudo bash -c". It now goes through the
    # write-file verb, so what matters is the DESTINATION NAME and the content — the path is the
    # table's, not the call site's, and on a remote host the base64 form is still what is sent.
    sm.run_command = lambda s, c, **k: (_ntc.__setitem__("cmd", c), ("", "", 0))[1]
    _ntc_ok = sm.ensure_node_tools_cron(object())
    check("node-tools: ensure writes the cron.d file as root, at the table's path",
          _ntc_ok is True and "/etc/cron.d/lgsm-node-tools" in _ntc["cmd"], _ntc.get("cmd", "")[:80])
    check("node-tools: the cron body is base64-piped + chmod 644 (no quoting/`%` hazards)",
          "base64 -d" in _ntc["cmd"] and "chmod 644" in _ntc["cmd"])
    check("node-tools: the cron path has ONE definition — the write target",
          not hasattr(sm, "_NODE_TOOLS_CRON_PATH"),
          "ssh_manager still keeps a second copy of the path")
finally:
    sm.run_command = _orig_ntc_rc

# ── UFW port/protocol validation (both interpolate into a ROOT shell command) ──
eq("ufw: tcp normalises", sm._ufw_proto("tcp"), "tcp")
eq("ufw: UDP case-folds", sm._ufw_proto("UDP"), "udp")
eq("ufw: blank -> both", sm._ufw_proto(""), "both")
eq("ufw: None -> both", sm._ufw_proto(None), "both")
eq("ufw: 'any' -> both", sm._ufw_proto("any"), "both")
check("ufw: injection protocol rejected", sm._ufw_proto("tcp; rm -rf /") is None)
check("ufw: unknown protocol rejected", sm._ufw_proto("sctp") is None)
eq("ufw: valid port coerced to int", sm._ufw_port_int("27015"), 27015)


def _priv_err_for(verb, args):
    """The VerbError text privileged.py produces for these arguments, or "" if it accepts them."""
    import privileged as _p
    try:
        _p.check_args(verb, args)
        return ""
    except _p.VerbError as e:
        return str(e)


def _ufw_raises_verb(fn):
    import privileged as _p
    try:
        fn()
        return False
    except _p.VerbError:
        return True


def _ufw_raises_fnf(fn, *a):
    try:
        fn(*a)
        return False
    except FileNotFoundError:
        return True


def _ufw_raises(fn):
    try:
        fn()
        return False
    except (TypeError, ValueError):
        return True


check("ufw: non-numeric port rejected", _ufw_raises(lambda: sm._ufw_port_int("22; reboot")))
check("ufw: port 0 rejected", _ufw_raises(lambda: sm._ufw_port_int(0)))
check("ufw: port 70000 rejected", _ufw_raises(lambda: sm._ufw_port_int(70000)))
# End-to-end: a malicious protocol/port must NOT reach run_command (no shell runs).
_orig_ufw_rc, _orig_ufw_rp = sm.run_command, sm.run_privileged
try:
    _ufw_calls = []
    sm.run_command = lambda *a, **k: (_ufw_calls.append(a), ("", "", 0))[1]
    sm.run_privileged = lambda *a, **k: (_ufw_calls.append(a), ("", "", 0))[1]
    _ok, _m = sm.remote_ufw_open_port(None, 27015, "tcp; touch /tmp/x #")
    check("ufw: open rejects injection proto, runs nothing", _ok is False and not _ufw_calls)
    _ok, _m = sm.remote_ufw_close_port(None, "22; reboot", "tcp")
    check("ufw: close rejects injection port, runs nothing", _ok is False and not _ufw_calls)
finally:
    sm.run_command, sm.run_privileged = _orig_ufw_rc, _orig_ufw_rp

# ── shell-identifier validation (usernames/short_names reach ssh + shell) ──
from models import _validate_shell_ident as _vsi
check("ident: normal value accepted", _vsi("k", "gmodserver") == "gmodserver")
check("ident: internal dash/dot/underscore ok", _vsi("k", "game-1.beta_2") == "game-1.beta_2")
check("ident: empty allowed (optional field)", _vsi("k", "") == "")
check("ident: leading dash rejected (ssh option-injection guard)",
      _ufw_raises(lambda: _vsi("k", "-oProxyCommand=x")))
check("ident: leading dot rejected", _ufw_raises(lambda: _vsi("k", ".hidden")))
check("ident: shell metachar rejected", _ufw_raises(lambda: _vsi("k", "a;b")))

# ── Tailscale bootstrap: user-supplied auth_key/routes/tags are REFUSED, not quoted ────────────
# These three used to assert that each value was shell-quoted into a root command — the best you
# can do when the value has to reach a shell. It does not any more: they are validated arguments,
# so the assertion is now the stronger one. A route that is not a network and a tag that is not
# `tag:name` never become part of anything.
_orig_ts_rc, _orig_ts_rp = sm.run_command, sm.run_privileged
try:
    _ts_calls = []
    sm.run_command = lambda s, c, **k: ("ok", "", 0)
    sm.run_privileged = lambda s, v, a=(), **k: (_ts_calls.append((v, list(a))),
                                                 ("Status: inactive", "", 0))[1]
    sm.remote_bootstrap_tailscale(None, auth_key="tskey; touch /tmp/x",
                                  advertise_routes="1.2.3.0/24; reboot", tags="tag:x; rm -rf /")
    _ts_up = [a for v, a in _ts_calls if v == "tailscale-up-key"]
    check("tailscale: the join goes through the verb, not a composed command", _ts_up, str(_ts_calls))
    for _i, _label in ((0, "auth_key"), (2, "routes"), (3, "tags")):
        check("tailscale: an injected %s is refused by privileged.py, not quoted into a command"
              % _label,
              _ts_up and _ufw_raises_verb(
                  lambda a=_ts_up[0]: _privmod.check_args("tailscale-up-key", a)),
              str(_ts_up[:1]))
    # And the clean case is accepted, so the validators are not simply refusing everything.
    check("tailscale: a well-formed key, route and tag ARE accepted",
          _privmod.check_args("tailscale-up-key",
                           ["tskey-auth-abc123def", "yes", "10.0.0.0/24", "tag:server"])
          == ["tskey-auth-abc123def", "yes", "10.0.0.0/24", "tag:server"])
    # The probe must CONTAIN the secret-shaped text, or "the secret is absent from the error" is
    # true for the boring reason. A previous version used "bad key!", which contains no key at all
    # — so a mutation that echoed the value back passed.
    _SECRET = "tskey-auth-SUPERSECRET!"          # the "!" is what makes it invalid
    _err = _priv_err_for("tailscale-up-key", [_SECRET, "no", "-", "-"])
    check("tailscale: the rejection actually fires for this probe", _err != "", _err)
    check("tailscale: a rejected auth key is never echoed back — it is a secret",
          "SUPERSECRET" not in _err and "tskey" not in _err, _err)
finally:
    sm.run_command, sm.run_privileged = _orig_ts_rc, _orig_ts_rp

# ── apt dependency names parsed from LinuxGSM output get interpolated into
#    `apt-get install <pkgs>`, so parse_missing_deps is a security filter, not just a parser. ──
eq("parse_missing_deps: extracts valid package names",
   sm.parse_missing_deps("log line\nMissing dependencies: libssl-dev lib32gcc-s1 gcc:i386  Run: x\n"),
   ["libssl-dev", "lib32gcc-s1", "gcc:i386"])
eq("parse_missing_deps: drops shell-metachar tokens (injection guard)",
   sm.parse_missing_deps("Missing dependencies: good $(reboot) a;b `id` also-good\n"),
   ["good", "also-good"])
eq("parse_missing_deps: no marker -> []", sm.parse_missing_deps("nothing to see here"), [])

# ── upload collisions: the browser must be able to ask "replace this?" with real facts ──────────
# stat_upload_targets lists the directory ONCE and filters locally, so the parsing is where this
# can go wrong: tab-separated fields, an epoch mtime that find prints as a float, and a filename
# that may itself contain a tab (which is why the name is last and re-joined).
class _FakeSrv:
    is_local, auth_method, sudo_enabled = True, "local", False
    host, port, username, linuxgsm_user = "127.0.0.1", 22, "u", ""


_orig_up_rc = sm.run_command
try:
    _FIND_OUT = "\n".join([
        "f\t1234\t1700000000.1234567890\tserver.cfg",
        "d\t4096\t1700000100.0000000000\taddons",
        "f\t0\t1700000200.5000000000\tempty.txt",
        "f\t77\t1700000300.0000000000\ttab\tname.cfg",   # a filename containing a tab
    ])
    sm.run_command = lambda *a, **k: (_FIND_OUT, "", 0)
    _hits = sm.stat_upload_targets(_FakeSrv(), "csgoserver", "", ["server.cfg", "nope.txt", "addons"])
    eq("stat_upload_targets: only names that exist come back",
       [h["name"] for h in _hits], ["server.cfg", "addons"])
    _byname = {h["name"]: h for h in _hits}
    eq("stat_upload_targets: size is parsed", _byname["server.cfg"]["size"], 1234)
    eq("stat_upload_targets: a float epoch mtime becomes an int",
       _byname["server.cfg"]["mtime"], 1700000000)
    check("stat_upload_targets: a directory is flagged, so the UI can refuse to replace it",
          _byname["addons"]["is_dir"] is True and _byname["server.cfg"]["is_dir"] is False)
    eq("stat_upload_targets: a zero-byte file still counts as existing",
       [h["name"] for h in sm.stat_upload_targets(_FakeSrv(), "u", "", ["empty.txt"])], ["empty.txt"])
    eq("stat_upload_targets: a filename containing a tab survives the split",
       [h["name"] for h in sm.stat_upload_targets(_FakeSrv(), "u", "", ["tab\tname.cfg"])],
       ["tab\tname.cfg"])
    eq("stat_upload_targets: a duplicate name is reported once",
       len(sm.stat_upload_targets(_FakeSrv(), "u", "", ["server.cfg", "server.cfg"])), 1)
    eq("stat_upload_targets: the name is basename'd, matching what upload_file writes",
       [h["name"] for h in sm.stat_upload_targets(_FakeSrv(), "u", "", ["sub/server.cfg"])],
       ["server.cfg"])
    check("stat_upload_targets: a traversal attempt returns None, not a listing",
          sm.stat_upload_targets(_FakeSrv(), "u", "../../etc", ["passwd"]) is None)

    # The host-side symlink guard. _safe_abspath is lexical and cannot see a symlink planted under
    # the game user's home, so every file operation now carries a realpath check that runs WHERE
    # THE PATH IS. Assert the guard is actually attached and that its sentinel is honoured.
    _cmds = []
    sm.run_command = lambda s, c, **k: (_cmds.append(c), ("", "", 0))[1]
    sm.browse_dir(_FakeSrv(), "csgoserver", "cfg")
    check("symlink guard: browse_dir resolves the path on the host before listing it",
          _cmds and "realpath -m" in _cmds[0] and "__OUTSIDE_HOME__" in _cmds[0], str(_cmds)[:150])
    sm.run_command = lambda s, c, **k: ("__OUTSIDE_HOME__", "", 9)
    check("symlink guard: a path that escapes home is refused by browse_dir",
          sm.browse_dir(_FakeSrv(), "csgoserver", "escape") is None)
    check("symlink guard: ...and by read_file",
          sm.read_file(_FakeSrv(), "csgoserver", "escape/x")[1] == "Invalid path")
    check("symlink guard: ...and by delete_path",
          sm.delete_path(_FakeSrv(), "csgoserver", "escape/x")[0] is False)
    check("symlink guard: ...and by stat_upload_targets",
          sm.stat_upload_targets(_FakeSrv(), "csgoserver", "escape", ["x"]) is None)
    check("symlink guard: ...and no bytes are written through one",
          sm.upload_file(_FakeSrv(), "csgoserver", "escape", "x", b"d", overwrite=True)[0] is False)

    # models' @validates fires on ASSIGNMENT only, so a row written before it existed reaches the
    # shell unchecked. _safe_abspath is the choke point every file op goes through, so it re-checks.
    for _bad in ("a b", "a;rm -rf /", "$(id)", "-oProxyCommand=x", "", "x" * 65):
        check("unix user %r is refused at the point of use" % _bad[:14],
              sm._safe_abspath(_bad, "cfg") is None)
    check("a legitimate unix user still resolves",
          sm._safe_abspath("csgoserver", "cfg") == "/home/csgoserver/cfg")
    sm.run_command = lambda *a, **k: ("", "", 0)
    eq("stat_upload_targets: no output means nothing exists",
       sm.stat_upload_targets(_FakeSrv(), "u", "", ["server.cfg"]), [])
    sm.run_command = lambda *a, **k: (_FIND_OUT, "", 0)

    # The server-side half: overwrite is opt-in. The UI asks first, but check and write are two
    # round trips, so a file that appears in between must be refused rather than clobbered.
    _calls = []
    sm.run_command = lambda s, c, **k: (_calls.append(c), ("__YES__", "", 0))[1]
    _ok, _msg = sm.upload_file(_FakeSrv(), "csgoserver", "", "server.cfg", b"data", overwrite=False)
    check("upload_file: refuses an existing target when overwrite was not granted",
          _ok is False and _msg == sm.UPLOAD_EXISTS, "%r %r" % (_ok, _msg))
    # ".paneltmp", not "printf": the symlink guard's realpath fallback legitimately uses printf,
    # so that word no longer means "a write happened". The staging file name only ever appears on
    # the write path.
    check("upload_file: and writes nothing on that path",
          not any("base64 -d" in c or ".paneltmp" in c for c in _calls), str(_calls)[:160])
    _calls.clear()
    sm.run_command = lambda s, c, **k: (_calls.append(c), ("", "", 0))[1]
    _ok2, _ = sm.upload_file(_FakeSrv(), "csgoserver", "", "server.cfg", b"data", overwrite=False)
    check("upload_file: a free name still uploads with overwrite=False",
          _ok2 is True and any("base64 -d" in c for c in _calls), "%r" % _ok2)
finally:
    sm.run_command = _orig_up_rc


# ── local-host injection defenses: system_ops runs commands on THIS machine (shell=True), so its
#    request-fed values (block/unban IPs, jail names) must be neutralised before reaching _run. ──
_orig_so_run = SO._run
try:
    _so = []
    SO._run = lambda cmd, *a, **k: (_so.append(cmd), ("", "", 0))[1]

    _ok, _ = SO.ufw_deny_ip("1.2.3.4; rm -rf /")
    check("ufw_deny_ip: non-IP rejected, runs nothing", _ok is False and not _so)
    _so.clear()
    _ok, _ = SO.ufw_deny_ip("10.0.0.5", tag="panel-test")
    check("ufw_deny_ip: valid IP reaches ufw insert",
          _ok is True and any("ufw insert 1 deny from 10.0.0.5" in c for c in _so))
    _so.clear()
    SO.ufw_deny_ip("10.0.0.6", tag="ev;il`x`")   # tag must be charset-stripped
    check("ufw_deny_ip: tag stripped of shell metacharacters",
          all(";" not in c and "`" not in c for c in _so))
    _so.clear()
    _ok, _ = SO.ufw_undeny_ip("not-an-ip")
    check("ufw_undeny_ip: non-IP rejected, runs nothing", _ok is False and not _so)
finally:
    SO._run = _orig_so_run

# ── fail2ban_unban: jail must be metacharacter-free AND on the host's real jail allowlist;
#    IP is canonicalised through ipaddress. Both are shlex-quoted at the sink. ──
_orig_so_run2, _orig_jails = SO._run, SO._fail2ban_jails
try:
    _fb = []
    SO._run = lambda cmd, *a, **k: (_fb.append(cmd), ("", "", 0))[1]
    SO._fail2ban_jails = lambda: ["sshd", "panel-login"]

    _ok, _ = SO.fail2ban_unban("sshd; rm -rf /", "1.2.3.4")
    check("fail2ban_unban: metachar jail rejected, runs nothing", _ok is False and not _fb)
    _fb.clear()
    _ok, _ = SO.fail2ban_unban("nftables", "1.2.3.4")   # charset-ok but not on the host
    check("fail2ban_unban: jail not on host allowlist rejected", _ok is False and not _fb)
    _fb.clear()
    _ok, _ = SO.fail2ban_unban("sshd", "9.9.9.9; reboot")
    check("fail2ban_unban: bad IP rejected, runs nothing", _ok is False and not _fb)
    _fb.clear()
    _ok, _ = SO.fail2ban_unban("sshd", "9.9.9.9")
    check("fail2ban_unban: valid jail+IP reaches fail2ban-client",
          _ok is True and any("fail2ban-client set sshd unbanip 9.9.9.9" in c for c in _fb))
finally:
    SO._run, SO._fail2ban_jails = _orig_so_run2, _orig_jails

# ── GMod mountable content: the game picker is allow-listed, and the mount config is generated from a
#    validated content username + constant game keys (so it's safe to write verbatim). ──
eq("gmod content: unknown games filtered, order + dedupe preserved",
   sm._valid_content_games(["cstrike", "tf", "doom", "cstrike"]), ["cstrike", "tf"])
eq("gmod content: empty -> []", sm._valid_content_games([]), [])
_gmc, _gmd = sm._gmod_mount_files("srcds", ["cstrike", "tf"])
check("gmod content: mount.cfg points each game at the content user's serverfiles",
      _gmc.startswith('"mountcfg"') and '"cstrike"\t"/home/srcds/serverfiles/cstrike"' in _gmc
      and '"tf"\t"/home/srcds/serverfiles/tf"' in _gmc)
check("gmod content: mountdepots enables hl2 + each game",
      _gmd.startswith('"gamedepotsystem"') and '"hl2"' in _gmd and '"cstrike"' in _gmd and '"tf"' in _gmd)
check("gmod content: installable games map to a LinuxGSM name, mount-only map to None",
      all(isinstance(v[1], str) for v in sm.GMOD_CONTENT_GAMES.values() if v[1] is not None)
      and sm.GMOD_CONTENT_GAMES["cstrike"][1] == "cssserver"
      and sm.GMOD_CONTENT_GAMES["hl1mp"][1] == "hldmsserver"     # free via LinuxGSM, not owned-only
      and sm.GMOD_CONTENT_GAMES["zps"][1] == "zpsserver"         # extra free Source game
      and sm.GMOD_CONTENT_GAMES["hl2"][1] is None                # owned single-player -> mount-only
      and "csgo" not in sm.GMOD_CONTENT_GAMES                    # dropped (CS2 now, unmountable)
      and sum(1 for v in sm.GMOD_CONTENT_GAMES.values() if v[1] is not None) == 16)
# Weekly content-update cron: update-lgsm (scripts) then update (content), Sunday, staggered, as the
# content user — so mounted content stays current (Source games get content updates).
_cron_body = sm._content_update_cron_body("srcds", ["cssserver", "tf2server"])
check("gmod content cron: per-game update + update-lgsm as the content user, Sunday, staggered",
      "0 1 * * 0 srcds /home/srcds/cssserver update-lgsm" in _cron_body
      and "2 1 * * 0 srcds /home/srcds/tf2server update-lgsm" in _cron_body
      and "0 2 * * 0 srcds /home/srcds/cssserver update >" in _cron_body
      and "10 2 * * 0 srcds /home/srcds/tf2server update >" in _cron_body)
# uninstall removes the content dir + the LinuxGSM install (host-wide), and rejects a bad user.
_orig_un_rc, _orig_un_rp = sm.run_command, sm.run_privileged
try:
    # These used to assert on the three `rm -rf` strings the call site built. It builds NAMES now
    # and the helper builds the paths, so the assertion moves to the verb — and the paths those
    # names produce are checked once, here, against privileged.content_path().
    _un = []
    sm.run_command = lambda s, c, **k: (_un.append(("cmd", c)), ("N", "", 0))[1]
    sm.run_privileged = lambda s, v, a=(), **k: (_un.append((v, list(a))), ("N", "", 1))[1]
    _uok, _urem, _ = sm.uninstall_gmod_content(object(), "gmodcontent", ["cstrike"])
    check("gmod content uninstall: asks to remove the game, its script and its config",
          ("content-game-remove", ["gmodcontent", "cstrike", "cssserver"]) in _un
          and _urem == ["cstrike"], str(_un))
    _un[:] = []
    _uok3, _urem3, _ = sm.uninstall_gmod_content(object(), "srcds", ["hl2"])   # mount-only game
    check("gmod content uninstall: a mount-only (owned) game passes '-' for 'no script'",
          ("content-game-remove", ["srcds", "hl2", "-"]) in _un and _urem3 == ["hl2"], str(_un))
    _un[:] = []
    _uok2, _, _ = sm.uninstall_gmod_content(object(), "bad;user", ["cstrike"])
    check("gmod content uninstall: rejects an invalid content user, runs nothing",
          _uok2 is False and not _un)
finally:
    sm.run_command, sm.run_privileged = _orig_un_rc, _orig_un_rp

# And the names really do resolve to the three paths the shell form removed — asserted against the
# path builder rather than against a command string, so it holds for both transports.
eq("gmod content uninstall: the game's content dir",
   _privmod.content_path("gmodcontent", "serverfiles", "cstrike"),
   "/home/gmodcontent/serverfiles/cstrike")
eq("gmod content uninstall: the LinuxGSM script",
   _privmod.content_path("gmodcontent", "cssserver"), "/home/gmodcontent/cssserver")
eq("gmod content uninstall: the LinuxGSM config",
   _privmod.content_path("gmodcontent", "lgsm", "config-lgsm", "cssserver"),
   "/home/gmodcontent/lgsm/config-lgsm/cssserver")
# free disk on the content filesystem (shown on the card so nobody starts a 13GB install without room)
_orig_df_rp = sm.run_privileged
try:
    # The fixture is now REAL `df -PB1` output, header and all, because the awk that used to
    # reduce it to two fields (under root) is gone and the parsing happens in Python. That makes
    # this a stronger test than it was: it exercises the column indices, not awk's answer.
    _DF_OUT = ("Filesystem       1B-blocks         Used    Available Use% Mounted on\n"
               "/dev/sda1     500107862016 376651072004 123456789012  76% /home\n")
    sm.run_privileged = lambda s, v, a=(), **k: (_DF_OUT, "", 0)
    eq("path_disk_free: parses (free, total) from real df output",
       sm.path_disk_free(object(), "/home/gmodcontent/serverfiles"), (123456789012, 500107862016))
    sm.run_privileged = lambda s, v, a=(), **k: ("garbage", "", 0)
    eq("path_disk_free: junk output -> (None, None)", sm.path_disk_free(object(), "/home"), (None, None))
    sm.run_privileged = lambda s, v, a=(), **k: ("", "", 0)
    eq("path_disk_free: empty output -> (None, None)", sm.path_disk_free(object(), "/home"), (None, None))
finally:
    sm.run_privileged = _orig_df_rp
# gmod_current_mounts: parse a real mount.cfg, keep only known games, ignore the header + unknowns.
_orig_gm_rc2 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        '"mountcfg"\n{\n\t"cstrike"\t"/home/srcds/serverfiles/cstrike"\n'
        '\t"tf"\t"/home/srcds/serverfiles/tf"\n'
        '//\t"csgo"\t"/home/srcds/serverfiles/csgo"\n'      # commented-out mount must NOT count
        '\t"notagame"\t"/x"\n}\n', "", 0)
    eq("gmod content: current mounts skip commented (//) lines + header + unknowns",
       sm.gmod_current_mounts(object(), "gmodserver"), ["cstrike", "tf"])
finally:
    sm.run_command = _orig_gm_rc2
# detect_content_user: parse a host scan, reject non-username tokens, resolve the primary group.
_orig_gm_rc = sm.run_command
try:
    def _gm_fake(server, cmd, **k):
        if "for u in" in cmd:
            return "HIT|srcds|cstrike\nHIT|b@d|cstrike\nHIT|srcds|cstrike", "", 0
        if "id -gn" in cmd:
            return "srcds", "", 0
        return "", "", 0
    sm.run_command = _gm_fake
    _det = sm.detect_content_user(object(), ("cstrike",))
    check("gmod content: detect reuses a valid content user, rejects bad usernames",
          bool(_det) and _det["user"] == "srcds" and _det["group"] == "srcds"
          and _det["present"].get("cstrike") == "/home/srcds/serverfiles/cstrike")
finally:
    sm.run_command = _orig_gm_rc

# a bad schedule is rejected by update before any SSH
_bad = sm.update_cron_job(None, "gm", "0 3 * * * /home/gm/backup.sh", "not-a-schedule", "x", "gmodserver")
check("cron: update rejects a bad schedule (no SSH)", _bad[0] is False)
# cron run-history: the recorder wrap/unwrap round-trips, and status files parse.
import base64 as _b64
_ccmd = "/home/gm/backup.sh --full && echo done"
_cjid = sm._cron_job_id(_ccmd)
check("cron: job id is a stable 12-hex hash",
      _cjid == sm._cron_job_id(_ccmd) and len(_cjid) == 12
      and all(c in "0123456789abcdef" for c in _cjid))
_wrapped = "/home/gm/.lgsm-cron/run %s %s" % (_cjid, _b64.b64encode(_ccmd.encode()).decode())
check("cron: unwrap recovers the original command",
      sm._unwrap_cron_command(_wrapped) == (_ccmd, _cjid))
check("cron: unwrap leaves a plain command untouched",
      sm._unwrap_cron_command("/home/gm/x.sh") == ("/home/gm/x.sh", None))
# Maintenance + autostart jobs use the INLINE recorder: the command stays visible (so the grep-based
# dedup/removal + last-run detection still work) and unwraps to the core command + a job id.
_mrec = sm._record_managed_cmd("gm", "/home/gm/gmodserver update")
check("managed cron: inline-recorded maintenance line still matches the dedup remove-regex",
      bool(__import__("re").search(r"/home/gm/gmodserver (monitor|mods-update|update|update-lgsm) ", _mrec)))
check("managed cron: unwrap recovers the core command + id",
      sm._unwrap_cron_command(_mrec)
      == ("/home/gm/gmodserver update", sm._cron_job_id("/home/gm/gmodserver update")))
# Nothing is managed now: an inline-recorded line (even monitor) is editable/deletable — the role
# label is all that distinguishes a panel line.
check("cron: an inline-recorded maintenance line is not managed (editable/deletable)",
      not sm._cron_line_managed(_mrec, "gm", "gmodserver"))
check("cron: an inline-recorded monitor line is not managed either — just role-labelled 'autostart'",
      not sm._cron_line_managed(sm._record_managed_cmd("gm", "/home/gm/gmodserver monitor"), "gm", "gmodserver")
      and sm._cron_role("/home/gm/gmodserver monitor", "gm", "gmodserver") == "autostart")
# upgrade_managed_cron_tracking rewraps EXISTING managed lines in place, leaving user jobs and
# the compound restart-check untouched (so old installs get success/error without a reinstall).
_upcap = {}
_orig_rw_u = sm._rewrite_crontab
_orig_run_u = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "*/5 * * * * /home/gm/gmodserver monitor > /dev/null 2>&1\n"
        "@reboot /home/gm/gmodserver start > /dev/null 2>&1\n"
        "0 3 * * * /home/gm/backup.sh\n"
        "10 * * * * [ -f /home/gm/.restart-pending ] && { /home/gm/gmodserver restart; }\n", "", 0)
    sm._rewrite_crontab = lambda s, u, grep, add, extra_pre="": (_upcap.update(add=list(add)) or (True, "ok"))
    _ures = sm.upgrade_managed_cron_tracking(None, "gm", "gmodserver")
    _uadd = _upcap.get("add", [])
    check("cron upgrade: reports a change", _ures is True)
    check("cron upgrade: monitor line wrapped in place", any(
        ln.startswith("*/5 * * * * ") and "/home/gm/gmodserver monitor" in ln and ".status" in ln for ln in _uadd))
    check("cron upgrade: autostart line wrapped in place", any(
        ln.startswith("@reboot ") and "/home/gm/gmodserver start" in ln and ".status" in ln for ln in _uadd))
    check("cron upgrade: user job left untouched", "0 3 * * * /home/gm/backup.sh" in _uadd)
    check("cron upgrade: compound restart-check left untouched", any(
        ln.startswith("10 * * * * [ -f") and ".status" not in ln for ln in _uadd))
finally:
    sm._rewrite_crontab = _orig_rw_u
    sm.run_command = _orig_run_u
import base64 as _b64cr


def _cron_wire(jobs):
    """Build the reader's wire reply: one tab-delimited line per job, log tail base64'd."""
    return "".join("%s\t%s\t%s\t%s\t%s\n"
                   % (jid, rc, st, en, _b64cr.b64encode(log.encode()).decode())
                   for jid, rc, st, en, log in jobs)


_orig_run3 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_cron_wire([("aaaaaaaaaaaa", 0, 100, 142, ""),
                                                    ("bbbbbbbbbbbb", 1, 200, 205, "boom: exit 1")]),
                                        "", 0)
    _cst = sm._read_cron_status(None, "gm")
    check("cron status: a successful run parses (ok + last_run)",
          _cst["aaaaaaaaaaaa"]["ok"] is True and _cst["aaaaaaaaaaaa"]["last_run"] == 142)
    check("cron status: a failed run parses with its error tail",
          _cst["bbbbbbbbbbbb"]["ok"] is False and _cst["bbbbbbbbbbbb"]["error"] == "boom: exit 1")
finally:
    sm.run_command = _orig_run3
# A FAITHFUL aborted `update-lgsm` log, byte-for-byte in the shape LinuxGSM writes one: fn_print_dots
# repaints the first line with \r, the reason arrives mid-log, and fn_print_*_eol_nl appends its
# verdict as a separate " ... FAIL" line. The \r is the whole point — it used to end the wire record
# early (text=True transports fold \r into \n; str.splitlines() splits on it), so the panel showed a
# red Failed badge with NO reason: worse than the ANSI soup this was meant to replace.
_lgsm_log = ("\x1b[1m\r\x1b[K[\x1b[0m .... \x1b[0m]\x1b[0m Updating LinuxGSM pmcserver: "
             "\x1b[0m\x1b[1m\r\x1b[K[\x1b[32m  OK  \x1b[0m]\x1b[0m Updating LinuxGSM: repo: GitHub\x1b[0m\n"
             "checking GitHub config [ \x1b[3mubuntu-24.04.csv\x1b[0m ] ... \x1b[33mUPDATE\x1b[0m\n"
             "fetching GitHub [ \x1b[3mubuntu-24.04.csv\x1b[0m ]"
             "curl: (22) The requested URL returned error: 404\n"
             " ... \x1b[31mERROR\x1b[0m\n"
             "fetching Bitbucket [ \x1b[3mubuntu-24.04.csv\x1b[0m ]"
             "curl: (22) The requested URL returned error: 404\n"
             " ... \x1b[31mFAIL\x1b[0m\n")
_orig_run3r = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_cron_wire([("cc33dd44ee55", 1, 100, 106, _lgsm_log)]), "", 0)
    _rerr = sm._read_cron_status(None, "gm")["cc33dd44ee55"]["error"]
finally:
    sm.run_command = _orig_run3r
# These go THROUGH the reader, not straight to the helper: that is the link the fix is about, and a
# revert of either half (the base64 wire or the _clean_cron_error call) fails them.
check("cron error (via reader): the reason survives a \\r-repainted log",
      "curl: (22) The requested URL returned error: 404" in _rerr and "ubuntu-24.04.csv" in _rerr)
check("cron error (via reader): no escape bytes reach the UI",
      "\x1b" not in _rerr and "[31m" not in _rerr and "[K" not in _rerr)
check("cron error (via reader): bare verdict lines dropped", "FAIL" not in _rerr)
check("cron error (via reader): fits the UI cell", 0 < len(_rerr) <= 240)
check("cron error (via reader): both mirror attempts are shown (they are different lines)",
      "fetching GitHub" in _rerr and "fetching Bitbucket" in _rerr)
check("cron error: an IDENTICAL repeated line is not shown twice",
      sm._clean_cron_error("fetching GitHub [ x.csv ]curl: (22) 404\n ... ERROR\n"
                           "fetching GitHub [ x.csv ]curl: (22) 404\n ... FAIL\n")
      == "fetching GitHub [ x.csv ]curl: (22) 404")
check("cron error (via reader): undecodable payload costs only that job's reason",
      sm._cron_log_text("not valid base64 !!") == ""
      and sm._cron_log_text(_b64cr.b64encode(b"caf\xe9: cannot start").decode()).startswith("caf"))
_lgsm_err = sm._clean_cron_error(_lgsm_log)
check("cron error: ANSI colour codes stripped", "\x1b" not in _lgsm_err and "[31m" not in _lgsm_err)
check("cron error: keeps the line that says why",
      "curl: (22) The requested URL returned error: 404" in _lgsm_err
      and "ubuntu-24.04.csv" in _lgsm_err)
check("cron error: bare ' ... FAIL' verdict lines dropped",
      "FAIL" not in _lgsm_err and "ERROR" not in _lgsm_err)
check("cron error: only a line's final \\r repaint is kept",
      sm._clean_cron_error("checking....\rchecking [ done ] failed to start") ==
      "checking [ done ] failed to start")
check("cron error: informative lines win over surrounding chatter",
      sm._clean_cron_error("step 1 ok\nstep 2 ok\nstep 3 ok\nstep 4 ok\n"
                           "cannot write /home/gm/x: permission denied\n ... FAIL")
      == "cannot write /home/gm/x: permission denied")
check("cron error: falls back to the tail when nothing looks like a reason",
      sm._clean_cron_error("aaa\nbbb\nccc\nddd") == "bbb ccc ddd")
check("cron error: capped for the UI cell", len(sm._clean_cron_error("error " + "x" * 900)) <= 240)
check("cron error: a line too long for the budget is not dropped entirely",
      sm._clean_cron_error("error " + "x" * 900).startswith("error x"))
_pack = sm._clean_cron_error("\n".join("failed step %d %s" % (i, "y" * 70) for i in range(4)))
check("cron error: the budget packs whole lines and never cuts mid-line",
      len(_pack) <= 240 and _pack.endswith("y" * 70)
      and "failed step 2" in _pack and "failed step 3" in _pack
      and "failed step 0" not in _pack)
# A CRLF log tail is the case the old `.split("\r")[-1]` silently emptied: every line ends in \r,
# so the "last repaint" was "" and the failure reason vanished — the blank red "Failed" badge again,
# in the module the console fix did not touch.
eq("cron error: a CRLF log still yields its reason",
   sm._clean_cron_error("checking config\r\ncurl: (22) The requested URL returned error: 404\r\n"),
   "curl: (22) The requested URL returned error: 404")
check("cron error: a mid-line repaint keeps what is on screen",
      sm._clean_cron_error("working...\rdone: permission denied") == "done: permission denied")
check("cron error: empty output stays empty", sm._clean_cron_error("") == ""
      and sm._clean_cron_error(None) == "")
# The reader must base64 the tail (so no log byte can break the record) and cap it BEFORE encoding.
_cronrd = {}
_orig_run3b = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_cronrd.update(cmd=c), ("", "", 0))[1]
    sm._read_cron_status(None, "gm")
    check("cron status: reads a wide tail, base64-framed, byte-capped before encoding",
          "tail -n 40" in _cronrd["cmd"] and "base64" in _cronrd["cmd"]
          and _cronrd["cmd"].index("tail -c 3000") < _cronrd["cmd"].index("base64"))
finally:
    sm.run_command = _orig_run3b
# cron run-times from the journald cron log (last-run TIME for managed/legacy jobs)
_orig_run4 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "1720000000 host CRON[11]: (gm) CMD (/home/gm/gmodserver monitor > /dev/null 2>&1)\n"
        "1720003600 host CRON[12]: (gm) CMD (/home/gm/gmodserver monitor > /dev/null 2>&1)\n"
        "1720007200 host CRON[13]: (gm) CMD (touch /home/gm/.restart-pending)\n", "", 0)
    _rt = sm._read_cron_run_times(None, "gm")
    check("cron run-times: newest run wins for a repeated command",
          _rt["/home/gm/gmodserver monitor > /dev/null 2>&1"] == 1720003600)
    check("cron run-times: parses a second distinct command",
          _rt["touch /home/gm/.restart-pending"] == 1720007200)
finally:
    sm.run_command = _orig_run4
# _match_run_time: a wrapped job's CORE command matches its logged line (old or wrapped form),
# so a freshly-upgraded job shows its run time instead of "—" until the recorder status lands.
_rtm = {"/home/gm/gmodserver monitor > /dev/null 2>&1": 100,
        "mkdir -p /home/gm/.lgsm-cron && /home/gm/gmodserver monitor > /home/gm/.lgsm-cron/ab.log 2>&1": 200}
check("run-time match: core command matches wrapped/old log line (newest wins)",
      sm._match_run_time(_rtm, "/home/gm/gmodserver monitor") == 200)
check("run-time match: exact command matches",
      sm._match_run_time({"touch /home/gm/.restart-pending": 50}, "touch /home/gm/.restart-pending") == 50)
check("run-time match: no match returns None",
      sm._match_run_time({"a b c": 1}, "/home/gm/nothing") is None)
# run_cron_job_now: runs the job's UNWRAPPED core command, detached, as the game user, and
# records to the job's own status file (so Last-run updates).
import base64 as _b64rn, re as _rern
_wl = ("*/5 * * * * /home/gm/.lgsm-cron/run " + sm._cron_job_id("/home/gm/backup.sh --full")
       + " " + _b64rn.b64encode(b"/home/gm/backup.sh --full").decode())
_rncap = {}
_orig_run6 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_rncap.update(cmd=c), ("", "", 0))[1]
    _rok, _ = sm.run_cron_job_now(None, "gm", _wl, "gmodserver")
    _c = _rncap["cmd"]
    check("run now: dispatched ok", _rok is True)
    check("run now: detached run as the game user",
          "sudo -u gm bash -c" in _c and "setsid bash" in _c)
    _m = _rern.search(r"echo ([A-Za-z0-9+/=]+) \| base64 -d", _c)
    _rec = _b64rn.b64decode(_m.group(1)).decode() if _m else ""
    check("run now: runs the unwrapped core command", "/home/gm/backup.sh --full >" in _rec)
    check("run now: records to the job's own status file",
          ("/home/gm/.lgsm-cron/" + sm._cron_job_id("/home/gm/backup.sh --full") + ".status") in _rec)
finally:
    sm.run_command = _orig_run6

# ── backup module: create / list / prune + path-traversal guard ──
import backup as _bk
import tempfile as _tf, sqlite3 as _sq, pathlib as _pl, os as _osb, tarfile as _tar, shutil as _sh2
_bktmp = _pl.Path(_tf.mkdtemp())
_bk.BACKUP_DIR = _bktmp / "backups"; _bk.DATA_DIR = _bktmp; _bk.DB_PATH = _bktmp / "panel.db"
_bk.CONFIG_FILE = _bktmp / "config.json"; _bk.SECRET_FILE = _bktmp / "secret_key"; _bk.CRED_KEY_FILE = _bktmp / "cred_key"
_dbc = _sq.connect(str(_bk.DB_PATH)); _dbc.execute("create table t(x)"); _dbc.commit(); _dbc.close()
_bk.CONFIG_FILE.write_text("{}"); _bk.SECRET_FILE.write_text("s"); _bk.CRED_KEY_FILE.write_text("k")
_bok, _bname = _bk.create_backup("manual")
check("backup: create returns a valid name", _bok and bool(_bk._NAME_RE.match(_bname)))
_blist = _bk.list_backups()
check("backup: appears in the list as 'manual'",
      len(_blist) == 1 and _blist[0]["kind"] == "manual" and _blist[0]["size"] > 0)
with _tar.open(_bk.BACKUP_DIR / _bname) as _t:
    check("backup: archive holds db+config+keys",
          set(_t.getnames()) == {"panel.db", "config.json", "secret_key", "cred_key"})
check("backup: _safe_path allows a real backup, rejects traversal/junk",
      _bk._safe_path(_bname) is not None and _bk._safe_path("../../etc/passwd") is None
      and _bk._safe_path("panel-backup-x.tar.gz") is None)
_old = _bk.BACKUP_DIR / "panel-backup-20000101-000000-daily.tar.gz"
_sh2.copy(_bk.BACKUP_DIR / _bname, _old); _osb.utime(_old, (0, 0))
check("backup: prune drops an old DAILY backup but keeps the manual one",
      _bk.prune_backups(7) == 1 and all(b["kind"] != "daily" for b in _bk.list_backups()))
_sh2.rmtree(_bktmp, ignore_errors=True)

# ── per-server backup schedules (config-backed; swap in an in-memory config) ──
def _fake_update(fakecfg, m):   # mirror config.update_config (backup now writes via update_config)
    c = dict(fakecfg)
    m(c)
    fakecfg.clear()
    fakecfg.update(c)
    return c


_sched_load, _sched_update = _bk.load_config, _bk.update_config
_fakecfg = {}
_bk.load_config = lambda: dict(_fakecfg)
_bk.update_config = lambda m: _fake_update(_fakecfg, m)
try:
    _d = _bk.get_game_schedule(4242)
    check("schedule: unset server inherits the global default",
          _d["overridden"] is False and _d["interval_set"] is False and _d["keep"] == _bk.DEFAULT_FULL_KEEP)
    _bk.set_game_schedule(4242, 1, 5)
    _o = _bk.get_game_schedule(4242)
    check("schedule: override sets interval + keep",
          _o["interval_days"] == 1 and _o["keep"] == 5 and _o["interval_set"] and _o["keep_set"])
    check("schedule: due immediately when never run", _bk.game_backup_due(4242) is True)
    _bk.record_game_backup(4242)
    check("schedule: not due right after a run", _bk.game_backup_due(4242) is False)
    _bk.set_game_schedule(4242, 0, None)   # interval 0 = off for this server, keep back to default
    check("schedule: interval 0 disables and keep falls back to default",
          _bk.game_backup_due(4242) is False and _bk.get_game_schedule(4242)["keep"] == _bk.DEFAULT_FULL_KEEP)
    _bk.set_game_schedule(4242, None, None)
    check("schedule: clearing the override returns to inherit",
          _bk.get_game_schedule(4242)["overridden"] is False)
    # corrupted config (game_schedules not a dict, or an entry not a dict) must not crash —
    # it should degrade to the global default, and set/record must repair it.
    for _i, _bad in enumerate(({"game_schedules": "notadict"}, {"game_schedules": {"4242": "notadict"}},
                               {"game_schedules": {"4242": {"interval_days": "x", "keep": None, "last": "y"}}})):
        _fakecfg.clear(); _fakecfg.update(_bad)
        _s = _bk.get_game_schedule(4242)   # must not raise; garbage values clamp to sane defaults
        check("schedule: corrupted config degrades safely (case %d)" % _i,
              _s["keep"] == _bk.DEFAULT_FULL_KEEP and isinstance(_s["interval_days"], int)
              and _bk.game_backup_due(4242) in (True, False))
        _bk.record_game_backup(4242)   # must not raise on a corrupted entry
    # remove_game_schedule (uninstall cleanup) drops the entry entirely, and is a safe no-op on
    # a missing/corrupted map.
    _fakecfg.clear(); _fakecfg.update({"game_schedules": {"77": {"interval_days": 7, "last": 1}}})
    _bk.remove_game_schedule(77)
    check("schedule: remove_game_schedule drops the entry",
          "77" not in _fakecfg.get("game_schedules", {}))
    _fakecfg.clear(); _fakecfg.update({"game_schedules": "corrupt"})
    _bk.remove_game_schedule(77)   # must not raise on a corrupted map
    check("schedule: remove_game_schedule is a safe no-op on junk", True)
finally:
    _bk.load_config, _bk.update_config = _sched_load, _sched_update

# ── full (game-file) backups: per-server LinuxGSM backup + settings/due ──
_orig_run7 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        "F\tgmodserver-2026.tar.gz\t1048576\t1720000000\nF\told.tar.gz\t500\t1719000000\n", "", 0)
    _gbl = sm.list_game_backups(None, "gm")
    check("game backups: parsed newest-first with sizes",
          len(_gbl) == 2 and _gbl[0]["name"] == "gmodserver-2026.tar.gz" and _gbl[0]["size"] == 1048576)
    check("game backups: no lock -> nothing marked in-progress",
          not any(b.get("in_progress") for b in _gbl))
    # Lock present + a NEW archive written after the backup started (lock mtime 1720000050) -> that
    # new one is in-progress; the pre-existing older backup is not.
    sm.run_command = lambda s, c, **k: (
        "F\tgmodserver-new.tar.zst\t2000\t1720000100\nF\tgmodserver-old.tar.zst\t1048576\t1720000000\n"
        "LOCK\t1720000050.5\n", "", 0)
    _gbl2 = sm.list_game_backups(None, "gm")
    check("game backups: active lock flags the new archive in-progress only",
          _gbl2[0]["name"] == "gmodserver-new.tar.zst" and _gbl2[0].get("in_progress") is True
          and not _gbl2[1].get("in_progress"))
    # Early in a backup (lock present, new archive not created yet): the existing backup predates the
    # lock, so it must NOT be flagged/hidden — this is the "existing backup disappears" regression.
    sm.run_command = lambda s, c, **k: (
        "F\tgmodserver-old.tar.zst\t1048576\t1720000000\nLOCK\t1720000050.5\n", "", 0)
    _gbl3 = sm.list_game_backups(None, "gm")
    check("game backups: a pre-existing backup isn't hidden while a new one is starting",
          len(_gbl3) == 1 and not _gbl3[0].get("in_progress"))
finally:
    sm.run_command = _orig_run7
_cap7 = {"cmds": []}
_orig_run8 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_cap7["cmds"].append(c), ("", "", 0))[1]
    _gok, _, _gskip = sm.run_game_backup(None, "gm", "gmodserver", 2)
    _joined = " ".join(_cap7["cmds"])
    check("run_game_backup: runs LinuxGSM backup as the game user",
          _gok is True and _gskip is False and "sudo -u gm bash -c" in _joined and "./gmodserver backup" in _joined)
    check("run_game_backup: prunes to keep N (keep=2 -> tail +3)", "tail -n +3" in _joined)
finally:
    sm.run_command = _orig_run8

# ── players-online guard: don't kick players for a backup unless forced ──
_orig_run8b = sm.run_command
try:
    # gamedig query reports 2 players; the LinuxGSM backup command must NOT run.
    def _run_busy(s, c, **k):
        if "gamedig" in c:
            return ("2", "", 0)
        return ("", "", 0)
    _cap_busy = {"cmds": []}
    sm.run_command = lambda s, c, **k: (_cap_busy["cmds"].append(c), _run_busy(s, c, **k))[1]
    _pc = sm.player_count(None, "gm", "gmod", 27015)
    check("player_count: parses gamedig player count", _pc == 2)
    _bok, _bmsg, _bskip = sm.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: skips (no backup) when players are online",
          _bok is False and _bskip is True and "backup" not in " ".join(c for c in _cap_busy["cmds"] if "gamedig" not in c))
    # force=True backs up anyway even with players on
    _cap_busy["cmds"] = []
    _fok, _fmsg, _fskip = sm.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015, force=True)
    check("run_game_backup: force=True backs up even with players online",
          _fok is True and _fskip is False and "./gmodserver backup" in " ".join(_cap_busy["cmds"]))
finally:
    sm.run_command = _orig_run8b

# ── empty/unqueryable server: player_count None, backup proceeds ──
_orig_run8c = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("0", "", 0) if "gamedig" in c else ("", "", 0)
    check("player_count: 0 players -> 0", sm.player_count(None, "gm", "gmod", 27015) == 0)
    check("player_count: unmapped game -> None (unknown)", sm.player_count(None, "gm", "nosuchgame", 27015) is None)
    check("player_count: no port -> None", sm.player_count(None, "gm", "gmod", None) is None)
    _eok, _emsg, _eskip = sm.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: empty server backs up normally", _eok is True and _eskip is False)
finally:
    sm.run_command = _orig_run8c

# ── 'Lockfile found' (LinuxGSM exits 0 but made no backup) must NOT read as success ──
_orig_lock = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("[ INFO ] Backup gmodserver: Lockfile found: Backup is currently running", "", 0)
    _lok, _lmsg, _lskip = sm.run_game_backup(None, "gm", "gmodserver", 2)
    check("run_game_backup: 'Lockfile found' at exit 0 is treated as failure",
          _lok is False and _lskip is False and "lock" in _lmsg.lower())
finally:
    sm.run_command = _orig_lock

# ── pre-flight disk guard: don't start a doomed backup when the disk is full ──
check("_fmt_size: bytes/MB/GB readable",
      sm._fmt_size(0) == "0 B" and sm._fmt_size(512) == "512 B"
      and sm._fmt_size(5 * 1024 * 1024) == "5.0 MB" and sm._fmt_size(2 * 1024 ** 3) == "2.0 GB")
_hs_saved = (sm._ensure_backup_headroom, sm.list_game_backups, sm.backup_disk_info, sm.run_command)
try:
    _GB2 = 1024 ** 3
    sm._ensure_backup_headroom = lambda s, u, k: ""       # nothing left to free
    sm.list_game_backups = lambda s, u: [{"name": "b-1", "size": int(1.2 * _GB2), "created": 1}]
    sm.backup_disk_info = lambda s, u: {"free": 22 * 1024 * 1024, "total": 23 * _GB2}   # ~22 MB free
    _pf_cmds = []
    sm.run_command = lambda s, c, **k: (_pf_cmds.append(c), ("", "", 0))[1]
    _pok, _pmsg, _pskip = sm.run_game_backup(None, "cs", "codserver", 2)
    check("run_game_backup: full disk -> clear 'Not enough disk space' failure, no backup run",
          _pok is False and _pskip is False and "Not enough disk space" in _pmsg
          and not any("./codserver backup" in c for c in _pf_cmds))
finally:
    (sm._ensure_backup_headroom, sm.list_game_backups, sm.backup_disk_info, sm.run_command) = _hs_saved

# ── mod-restart decision (pure): restart when empty, defer when busy/unknown, force wins ──
check("mod_restart_decision: stopped server -> idle (loads on next start)",
      sm.mod_restart_decision("offline", None) == "idle")
check("mod_restart_decision: online + empty -> restart now",
      sm.mod_restart_decision("online", 0) == "restart")
check("mod_restart_decision: online + players -> pending (don't kick)",
      sm.mod_restart_decision("online", 3) == "pending")
check("mod_restart_decision: online + unknown count -> pending (can't confirm empty)",
      sm.mod_restart_decision("online", None) == "pending")
check("mod_restart_decision: unknown status -> pending",
      sm.mod_restart_decision("unknown", None) == "pending")
check("mod_restart_decision: force restarts even with players online",
      sm.mod_restart_decision("online", 5, force=True) == "restart")
check("mod_restart_decision: force on a stopped server stays idle (nothing to restart)",
      sm.mod_restart_decision("offline", 5, force=True) == "idle")

# ── smart headroom: free space before a backup only when the disk is tight ──
_hr_saved = (sm.list_game_backups, sm.backup_disk_info, sm.delete_game_backup)
try:
    _GB = 1024 ** 3
    _hr_deleted = []
    sm.delete_game_backup = lambda s, u, name: (_hr_deleted.append(name), True)[1]
    _three = [{"name": "g-3", "size": 4 * _GB, "created": 300},
              {"name": "g-2", "size": 4 * _GB, "created": 200},
              {"name": "g-1", "size": 4 * _GB, "created": 100}]
    sm.list_game_backups = lambda s, u: list(_three)
    # plenty of room -> no deletion
    sm.backup_disk_info = lambda s, u: {"free": 57 * _GB, "total": 60 * _GB}
    _hr_deleted[:] = []
    _n1 = sm._ensure_backup_headroom(None, "gm", 2)
    check("headroom: with free disk, nothing is deleted", _hr_deleted == [] and _n1 == "")
    # tight -> delete oldest first, protect the newest (keep-1)
    sm.backup_disk_info = lambda s, u: {"free": 1 * _GB, "total": 60 * _GB}
    _hr_deleted[:] = []
    _n2 = sm._ensure_backup_headroom(None, "gm", 2)
    check("headroom: tight disk frees the OLDEST backup first, protects newest",
          _hr_deleted[:1] == ["g-1"] and "g-3" not in _hr_deleted and _n2)
    # no backups yet -> nothing to free
    sm.list_game_backups = lambda s, u: []
    _hr_deleted[:] = []
    check("headroom: no backups yet -> no deletion", sm._ensure_backup_headroom(None, "gm", 2) == "" and _hr_deleted == [])
    # 0-byte newest is a failed backup (junk): delete it first, protect the good older one, and
    # estimate from the LARGEST (so a 0-byte newest doesn't make it skip on a full disk).
    sm.list_game_backups = lambda s, u: [{"name": "junk", "size": 0, "created": 300},
                                         {"name": "good", "size": 226 * _GB, "created": 200}]
    sm.backup_disk_info = lambda s, u: {"free": 50 * 1024 * 1024, "total": 25 * _GB}
    _hr_deleted[:] = []
    sm._ensure_backup_headroom(None, "pmc", 2)
    check("headroom: deletes 0-byte junk first, protects the valid backup",
          _hr_deleted == ["junk"])
finally:
    sm.list_game_backups, sm.backup_disk_info, sm.delete_game_backup = _hr_saved

_fake_cfg = {}
_orig_bkload, _orig_bkupdate = _bk.load_config, _bk.update_config
_bk.load_config = lambda: dict(_fake_cfg)
_bk.update_config = lambda m: _fake_update(_fake_cfg, m)
try:
    _fs = _bk.set_full_settings(interval_days=7, keep=2)
    check("full backup: settings save round-trip", _fs["interval_days"] == 7 and _fs["keep"] == 2)
    check("full backup: due when never run", _bk.full_backup_due() is True)
    _bk.record_full_backup("2 server(s) backed up")
    check("full backup: not due right after a run", _bk.full_backup_due() is False)
    _bk.set_full_settings(interval_days=0)
    check("full backup: interval 0 = off (never due)", _bk.full_backup_due() is False)
finally:
    _bk.load_config, _bk.update_config = _orig_bkload, _orig_bkupdate

# ── alerts: lgsm_get_values reads merged config, instance overrides win ──
_orig_run9 = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (
        'discordalert="off"\ndiscordwebhook="default"\nemailalert="on"\n'
        'discordalert="on"\ndiscordwebhook="https://x/hook"\n', "", 0)
    _av = sm.lgsm_get_values(None, "gm", "gmodserver",
                             ["discordalert", "discordwebhook", "emailalert", "missingkey"])
    check("lgsm_get_values: later (instance) value wins",
          _av["discordwebhook"] == "https://x/hook" and _av["discordalert"] == "on")
    check("lgsm_get_values: reads other toggles; missing key -> empty",
          _av["emailalert"] == "on" and _av["missingkey"] == "")
finally:
    sm.run_command = _orig_run9

# line splitting
eq("cron: split 5-field", sm._split_cron_line("0 3 * * * /home/gm/b.sh a"), ("0 3 * * *", "/home/gm/b.sh a"))
eq("cron: split @shortcut", sm._split_cron_line("@reboot /home/gm/x start"), ("@reboot", "/home/gm/x start"))
eq("cron: split rejects short line", sm._split_cron_line("0 3 * *"), (None, None))

# ── anti-lockout: disabling public SSH must be refused with no Tailscale path back in ──
_orig_rc = sm.run_command
def _rc_no_tailnet(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Stopped"}', "", 0)   # Tailscale not running
    return ("", "", 0)
sm.run_command = _rc_no_tailnet
_ok, _msg = sm.remote_set_public_ssh(object(), "off")
check("ssh off REFUSED when no Tailscale path (anti-lockout)", _ok is False and "lock you out" in _msg.lower())

def _rc_ts_ssh(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Running"}', "", 0)
    if "debug prefs" in cmd:
        return ('{"RunSSH": true}', "", 0)                # Tailscale SSH enabled
    return ("", "", 0)
sm.run_command = _rc_ts_ssh
check("ssh off ALLOWED when Tailscale SSH enabled", sm.remote_set_public_ssh(object(), "off")[0] is True)

def _rc_iface(server, cmd, **kw):
    if "status --json" in cmd:
        return ('{"BackendState":"Running"}', "", 0)
    if "debug prefs" in cmd:
        return ('{"RunSSH": false}', "", 0)
    if "ufw status" in cmd:
        return ("Anywhere on tailscale0     ALLOW IN    Anywhere", "", 0)  # tailscale0 allowed
    return ("", "", 0)
sm.run_command = _rc_iface
check("ssh off ALLOWED when tailscale0 allowed in UFW", sm.remote_set_public_ssh(object(), "off")[0] is True)

sm.run_command = lambda *a, **k: ("", "", 0)
check("ssh allow is never lockout-guarded", sm.remote_set_public_ssh(object(), "allow")[0] is True)
check("ssh limit is never lockout-guarded", sm.remote_set_public_ssh(object(), "limit")[0] is True)
sm.run_command = _orig_rc

# ── secret encryption round-trip ──────────────────────────────
_pre = {p for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE)
        if os.path.exists(p)}
enc = config.encrypt_secret("hunter2")
check("encrypt adds enc: prefix", enc.startswith("enc:v1:"))
check("is_encrypted true for ciphertext", config.is_encrypted(enc))
eq("decrypt round-trips", config.decrypt_secret(enc), "hunter2")
eq("encrypt empty -> empty", config.encrypt_secret(""), "")
eq("decrypt legacy plaintext passthrough", config.decrypt_secret("plainpw"), "plainpw")

# ── UFW rule grouping: port / protocol split ──────────────────
def _rules(rs):
    return [{"num": str(i + 1), "detail": d} for i, d in enumerate(rs)]


groups = sm._group_ufw_rules(_rules([
    "22/tcp  ALLOW IN  Anywhere",
    "22/tcp (v6)  ALLOW IN  Anywhere (v6)",
    "5000/tcp  ALLOW IN  Anywhere",
    "28960  ALLOW IN  Anywhere  # codserver",
    "27015/udp  ALLOW IN  Anywhere",
]))
by_port = {g["port_num"]: g for g in groups}
eq("22 -> TCP", by_port["22"]["proto_label"], "TCP")
eq("22 merges v4+v6", by_port["22"]["family_label"], "IPv4 + IPv6")
eq("bare port -> BOTH", by_port["28960"]["proto_label"], "BOTH")
eq("bare port keeps comment", by_port["28960"]["comment"], "codserver")
eq("udp suffix -> UDP", by_port["27015"]["proto_label"], "UDP")

# ── firewall lock-out protection ──────────────────────────────
def protect(server, rules, enabled=True, cfg=None, is_local=False, tailscale=(False, False)):
    # Restores what it replaces. It used to leave sm.is_local_server stubbed for the REST of the
    # suite — every later test saw whatever the last protect() call happened to pass, which is how
    # a stub stops being scaffolding and starts being a silent global. Nothing depended on the leak
    # (this fix changed no other result), but the transport tests further down do read the real
    # is_local_server, and would have been testing the wrong branch.
    _saved = (sm.is_local_server, sm._tailscale_conn_state, config.load_config)
    try:
        sm.is_local_server = lambda s: is_local
        sm._tailscale_conn_state = lambda s: tailscale   # (running, ssh_enabled) — deterministic
        if cfg is not None:
            config.load_config = lambda: cfg
        return sm._annotate_firewall_protection(server, enabled, sm._group_ufw_rules(_rules(rules)))
    finally:
        sm.is_local_server, sm._tailscale_conn_state, config.load_config = _saved


# SSH-only: port 22 is the last way in -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("SSH-only: 22 protected", gp["22"]["protected"])
check("SSH-only: game port not protected", not gp["28960"]["protected"])

# A rate-limited SSH rule (`ufw limit`, action LIMIT — now the default) is still SSH access,
# and the only way in here -> protected. Regression: LIMIT != ALLOW was letting it be deleted.
g = protect(NS(port=22), ["22/tcp LIMIT IN Anywhere", "28960 ALLOW IN Anywhere"])
gp = {x["port_num"]: x for x in g}
check("LIMIT SSH rule recognised as SSH", gp["22"]["is_ssh"])
check("LIMIT SSH rule protected as the only way in", gp["22"]["protected"])

# Custom SSH port + a tailscale0 rule, WITH Tailscale actually running -> two real ways in
# -> the SSH rule can be removed (warn); custom port recognised as SSH.
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"], tailscale=(True, False))
gp = {x["port_num"]: x for x in g}
check("custom 2222 recognised as SSH", gp["2222"]["is_ssh"])
check("2222 warn when Tailscale is up (another way in)", gp["2222"]["warn"] and not gp["2222"]["protected"])

# Same rules but Tailscale is DOWN -> the tailscale0 rule is no real route -> 2222 is the only
# way in and must be PROTECTED (the reported bug: don't let me delete SSH with no tailnet path).
g = protect(NS(port=2222), ["2222/tcp ALLOW IN Anywhere",
                            "Anywhere ALLOW IN Anywhere on tailscale0"], tailscale=(False, False))
gp = {x["port_num"]: x for x in g}
check("2222 protected when Tailscale is down (no real fallback)", gp["2222"]["protected"])

# Tailscale SSH enabled -> a guaranteed way in -> the sole SSH rule can be removed (warn).
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere"], tailscale=(True, True))
gp = {x["port_num"]: x for x in g}
check("SSH rule removable when Tailscale SSH is enabled", gp["22"]["warn"] and not gp["22"]["protected"])

# Tailscale-only: the tailscale rule is the last way in -> protected.
g = protect(NS(port=22), ["Anywhere ALLOW IN Anywhere on tailscale0",
                          "28960 ALLOW IN Anywhere"])
ts = next(x for x in g if x["is_tailscale"])
check("tailscale-only: protected", ts["protected"])

# `allow in on tailscale0` + `allow out on tailscale0` (the pair ufw adds), no SSH: only the
# IN rule is a "way in", so it's the last route and must be protected. The OUT rule must NOT
# count as access, or the protection would think there are two routes and let you delete the
# real (in) one.
g = protect(NS(port=22), ["Anywhere ALLOW IN Anywhere on tailscale0",
                          "Anywhere ALLOW OUT Anywhere on tailscale0"])
ins = [x for x in g if x["is_tailscale"]]
check("tailscale in+out: only the IN rule counts as access", len(ins) == 1)
check("tailscale in+out: the last-way-in IN rule is protected", bool(ins) and ins[0]["protected"])

# UFW disabled -> nothing protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere"], enabled=False)
check("ufw disabled: nothing protected", not any(x["protected"] for x in g))

# Panel web port on the LOCAL host, no Tailscale -> protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"],
            cfg={"port": 5000}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local, no tailscale: panel 5000 protected", gp["5000"]["protected"] and gp["5000"]["is_panel"])

# Panel web port with a tailscale0 rule but Serve NOT set up -> STILL protected. The
# tailscale interface only provides SSH recovery, not panel-UI access, so the public web
# port is still the only way into the panel.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local + tailscale0 but no Serve: panel 5000 STILL protected", gp["5000"]["protected"])

# Once Tailscale Serve is configured, the panel IS reachable over the tailnet -> the public
# port is no longer the only way in -> NOT protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True)
gp = {x["port_num"]: x for x in g}
check("local + Serve set up: panel 5000 NOT protected", not gp["5000"]["protected"])
# ...and with Serve serving the panel, the inbound tailscale0 rule is now what keeps the
# panel reachable over the tailnet, so it must be PROTECTED (the reported bug: the UI let
# you delete tailscale0 while the panel was served over it — a lock-out).
_tsrule = next(x for x in g if x["is_tailscale"])
check("local + Serve set up: inbound tailscale0 rule protected", _tsrule["protected"])

# On a REMOTE host the panel port is never protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere"],
            cfg={"port": 5000}, is_local=False)
gp = {x["port_num"]: x for x in g}
check("remote host: panel 5000 not protected", not gp["5000"]["protected"])

# ── ssh-status: panel_port_open (gates the "Close public panel port" button) ──
_orig_run = sm.run_command
try:
    sm.run_command = lambda s, c, **k: ("Status: active\n5000/tcp  ALLOW  Anywhere\n"
                                        "22/tcp  ALLOW  Anywhere\n", "", 0)
    check("ssh-status: panel port open detected",
          sm.remote_public_ssh_status(NS(), panel_port=5000).get("panel_port_open") is True)
    # Closed: only a tailscale0 rule and a *different* port — must read as closed, and 27015
    # must not word-boundary-match 5000.
    sm.run_command = lambda s, c, **k: ("Status: active\nAnywhere  ALLOW  Anywhere on tailscale0\n"
                                        "27015  ALLOW  Anywhere\n", "", 0)
    check("ssh-status: panel port closed detected (no false match on 27015)",
          sm.remote_public_ssh_status(NS(), panel_port=5000).get("panel_port_open") is False)
    # Without panel_port the key is omitted entirely (remote hosts don't report it).
    check("ssh-status: panel_port_open omitted when not asked",
          "panel_port_open" not in sm.remote_public_ssh_status(NS()))
finally:
    sm.run_command = _orig_run

# ── game-port selection: open only what's needed ──────────────
_GMOD_DETAILS = """\
Some header text
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Client 27005 udp
SourceTV 27020 udp
"""
sm.run_as_game_user = lambda *a, **k: (_GMOD_DETAILS, "", 0)
res = sm.detect_game_ports(NS(), "gmodserver")
eq("gmod game_port", res["game_port"], 27015)
eq("gmod opens ONLY 27015 (no SourceTV/Client)", res["open_ports"], [27015])

_SRC_DETAILS = """\
DESCRIPTION PORT PROTOCOL
Game 27015 udp
Query 27016 udp
RCON 27015 tcp
SourceTV 27020 udp
Client 27005 udp
"""
sm.run_as_game_user = lambda *a, **k: (_SRC_DETAILS, "", 0)
res = sm.detect_game_ports(NS(), "srv")
eq("source: opens game + query only", res["open_ports"], [27015, 27016])

# ── per-remote access control (fix: MANAGE_REMOTES alone must NOT grant every host) ──
def _user(is_admin, *group_remote_ids):
    return NS(is_superadmin=is_admin,
              groups=[NS(servers=[NS(id=i) for i in group_remote_ids])])


check("remote access: granted host allowed", can_access_remote(_user(False, 1, 2), 1))
check("remote access: non-granted host DENIED", not can_access_remote(_user(False, 1, 2), 3))
check("remote access: superadmin allowed anywhere", can_access_remote(_user(True), 999))
check("remote access: string id handled", can_access_remote(_user(False, 5), "5"))
check("remote access: junk id denied", not can_access_remote(_user(False, 5), "abc"))

# ── client_ip: trust X-Forwarded-For ONLY from the loopback proxy ─────
from flask import Flask as _Flask
_app = _Flask(__name__)
with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                               environ_base={"REMOTE_ADDR": "127.0.0.1"}):
    eq("loopback proxy: trust XFF", client_ip(), "1.2.3.4")
with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                               environ_base={"REMOTE_ADDR": "203.0.113.9"}):
    eq("direct connection: ignore spoofed XFF, use socket", client_ip(), "203.0.113.9")

# ── TOTP (2FA) ────────────────────────────────────────────────
import time as _time
from auth import generate_totp_secret, verify_totp
import pyotp as _pyotp
_sec = generate_totp_secret()
check("verify_totp accepts the current code", verify_totp(_sec, _pyotp.TOTP(_sec).now()))
check("verify_totp accepts a spaced code", verify_totp(_sec, " " + _pyotp.TOTP(_sec).now() + " "))
check("verify_totp rejects a wrong code", not verify_totp(_sec, "000000"))
check("verify_totp rejects empty", not verify_totp(_sec, ""))

# A TOTP code stays valid for ~90s (its own step plus one either side for clock skew), so
# "is it valid" alone lets an observed code be replayed for the rest of that window. The login
# path records WHICH step was spent, so it needs the step back, not a boolean.
from auth import verify_totp_step
_step = verify_totp_step(_sec, _pyotp.TOTP(_sec).now())
check("verify_totp_step returns the step for a valid code", isinstance(_step, int) and _step > 0)
eq("verify_totp_step is stable for the same code", verify_totp_step(_sec, _pyotp.TOTP(_sec).now()), _step)
eq("verify_totp_step: the step matches the clock", _step, int(_time.time()) // 30)
check("verify_totp_step rejects a wrong code", verify_totp_step(_sec, "000000") is None)
check("verify_totp_step rejects empty", verify_totp_step(_sec, "") is None)
check("verify_totp_step tolerates a junk secret", verify_totp_step("not-base32!", "123456") is None)
# The previous step must still verify (clock skew) and report ITS step, not the current one —
# otherwise a code accepted near a boundary would look like a replay of the newer step.
_prev = _pyotp.TOTP(_sec).at(int(_time.time()) - 30)
_prev_step = verify_totp_step(_sec, _prev)
check("verify_totp_step accepts the previous step and reports it as older",
      _prev_step is not None and _prev_step == _step - 1, "%r vs %r" % (_prev_step, _step))

# ── password check robustness (a bad stored hash must never raise) ───
from auth import check_password, hash_password, dummy_password_check
_h = hash_password("Test1234!@")
check("check_password: correct password -> True", check_password("Test1234!@", _h))
check("check_password: wrong password -> False", not check_password("nope", _h))
check("check_password: empty stored hash -> False (no raise)", not check_password("x", ""))
check("check_password: None stored hash -> False (no raise)", not check_password("x", None))
check("check_password: garbage stored hash -> False (no raise)", not check_password("x", "not-a-bcrypt-hash"))
check("dummy_password_check always returns False", dummy_password_check("anything") is False)

# ── login-throttle map must not grow unbounded (prune stale/empty IP buckets) ──
# _LOGIN_FAILS is the same dict object app.py mutates, so in-place edits here are seen
# by _prune_login_fails. (Single import style — CodeQL flags mixing import/from-import.)
from app import _prune_login_fails, _LOGIN_FAILS
_now = 1_000_000.0
_LOGIN_FAILS.clear()
_LOGIN_FAILS["fresh"] = [_now - 10]     # last failure within the window
_LOGIN_FAILS["stale"] = [_now - 9999]   # last failure aged out
_LOGIN_FAILS["empty"] = []              # bucket emptied by trimming
_prune_login_fails(_now)
check("login-throttle prune keeps a recently-active IP", "fresh" in _LOGIN_FAILS)
check("login-throttle prune drops an aged-out IP", "stale" not in _LOGIN_FAILS)
check("login-throttle prune drops an empty bucket", "empty" not in _LOGIN_FAILS)
_LOGIN_FAILS.clear()

# ── 2FA backup codes ──────────────────────────────────────────
from auth import generate_backup_codes
from models import User as _User
_codes = generate_backup_codes()
check("backup: generates 8 codes", len(_codes) == 8)
check("backup: codes are unique", len(set(_codes)) == 8)
check("backup: xxxxx-xxxxx format", all(len(c) == 11 and c[5] == "-" for c in _codes))
check("backup: unambiguous alphabet (no 0/o/1/l/i)",
      all(ch in "23456789abcdefghjkmnpqrstuvwxyz-" for c in _codes for ch in c))
_u = _User()
_u.set_backup_codes(_codes)
check("backup: 8 remaining after set", _u.backup_codes_remaining == 8)
check("backup: wrong code rejected", not _u.use_backup_code("00000-00000"))
check("backup: valid code accepted (ignores case + dashes)",
      _u.use_backup_code(_codes[0].upper().replace("-", "")))
check("backup: remaining drops to 7 after use", _u.backup_codes_remaining == 7)
check("backup: a used code can't be reused (one-time)", not _u.use_backup_code(_codes[0]))
check("backup: a different code still works", _u.use_backup_code(_codes[1]))
check("backup: no codes set is handled", not _User().use_backup_code("whatever"))

# ── one-click connect URI (steam://connect for Source/GoldSrc) ─
from models import GameServer as _GS
_steam = _GS(game_type="gmod", port=27015)
eq("connect: steam game -> steam://connect", _steam.connect_uri("1.2.3.4"),
   "steam://connect/1.2.3.4:27015")
_cs16 = _GS(game_type="cs", port=27015)
eq("connect: goldsrc game -> steam://connect", _cs16.connect_uri("host.example"),
   "steam://connect/host.example:27015")
_cod = _GS(game_type="cod", port=28960)
eq("connect: non-steam game (cod) -> no URI", _cod.connect_uri("1.2.3.4"), "")
_mc = _GS(game_type="mc", port=25565)
eq("connect: minecraft -> no URI", _mc.connect_uri("1.2.3.4"), "")
eq("connect: no host -> no URI", _steam.connect_uri(""), "")

# ── install port auto-assignment: span-aware, sequential packing ──
#    Regression guard for the "increments by 2" bug — a single-port game (Call of Duty, Source,
#    Minecraft) must pack sequentially, while a multi-port game reserves its whole adjacent block.
from app import _port_span, _first_free_block
eq("port-span: cod is single-port", _port_span("cod"), 1)
eq("port-span: source game is single-port", _port_span("gmod"), 1)
eq("port-span: unknown game defaults to 1", _port_span("totally-made-up"), 1)
eq("port-span: rust reserves 2", _port_span("rust"), 2)
eq("port-span: valheim reserves 3", _port_span("valheim"), 3)
eq("port-span: case-insensitive", _port_span("RUST"), 2)


def _pack(seq_spans, desired_of):
    """Simulate installing servers in order; each reserves its span. Returns assigned ports."""
    occupied, assigned = set(), []
    for gt in seq_spans:
        span = _port_span(gt)
        p = _first_free_block(desired_of[gt], span, occupied)
        for k in range(span):
            occupied.add(p + k)
        assigned.append(p)
    return assigned

eq("port-pack: 3 cod servers are sequential (no +2 gap)",
   _pack(["cod", "cod", "cod"], {"cod": 28960}), [28960, 28961, 28962])
eq("port-pack: cod then coduo pack tightly",
   _pack(["cod", "coduo"], {"cod": 28960, "coduo": 28960}), [28960, 28961])
eq("port-pack: 2 rust servers keep a 2-port block each",
   _pack(["rust", "rust"], {"rust": 28015}), [28015, 28017])
eq("port-pack: 2 valheim servers keep a 3-port block each",
   _pack(["valheim", "valheim"], {"valheim": 2456}), [2456, 2459])
eq("port-block: a live listening port is skipped",
   _first_free_block(28960, 1, {28960, 28961}), 28962)

# _dedupe_aux_ports: a 2nd Source server must move its SourceTV/client ports off any already taken,
# so -strictportbind doesn't quit it. Free ports keep their value (and are omitted from the result).
from app import _dedupe_aux_ports
eq("aux-ports: both free -> no changes",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27015}), {})
eq("aux-ports: both taken -> each bumped to the next free port",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27005, 27015, 27020}),
   {"clientport": 27006, "sourcetvport": 27021})
eq("aux-ports: only the colliding key moves",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27020}),
   {"sourcetvport": 27021})
eq("aux-ports: scans past a run of taken ports",
   _dedupe_aux_ports({"sourcetvport": 27020}, {27020, 27021, 27022}), {"sourcetvport": 27023})
eq("aux-ports: two keys never land on the same freed port",
   _dedupe_aux_ports({"clientport": 27020, "sourcetvport": 27020}, {27020}),
   {"clientport": 27021, "sourcetvport": 27022})

# _extract_start_error: turn a game's start log into a one-line reason (or "" if none is clear), so a
# failed auto-start shows WHY instead of a bare "offline".
from app import _extract_start_error
eq("start-error: pulls the -strictportbind port line, ANSI stripped",
   _extract_start_error('boot\n\x1b[38;2;255;90;90mERROR: Port 27020 was unavailable - quitting due to "-strictportbind" flag!\x1b[39m\nmore'),
   'Port 27020 was unavailable - quitting due to "-strictportbind" flag!')
eq("start-error: a clean boot log yields no reason", _extract_start_error("Loading map\nServer started"), "")
eq("start-error: catches a couldn't-load line", _extract_start_error("Couldn't open mapcycle.txt"),
   "Couldn't open mapcycle.txt")
eq("port-block: multi-port block steps past a partial overlap",
   _first_free_block(28015, 2, {28016}), 28017)

# ── panel file integrity + repair (git-based) ─────────────────
import system_ops as _so
_so._is_git_checkout = lambda: True
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"]
    else ("M\tapp.py\nD\ttemplates/base.html\n", "", 0) if list(args) == ["diff", "--name-status", "HEAD"]
    else ("", "", 0))
_intg = _so.panel_integrity(force=True)   # force: each scenario mocks a different git state
check("integrity: reports git checkout", _intg["git"] is True)
eq("integrity: counts tampered files", _intg["count"], 2)
check("integrity: not clean when files differ", _intg["clean"] is False)

# ── update-noise filter: only real runtime changes should raise the "update available" badge ──
check("runtime-path: app.py counts", _so._is_runtime_path("app.py") is True)
check("runtime-path: a template counts", _so._is_runtime_path("templates/base.html") is True)
check("runtime-path: static asset counts", _so._is_runtime_path("static/js/app.js") is True)
check("runtime-path: requirements counts", _so._is_runtime_path("requirements.txt") is True)
check("runtime-path: install.sh counts", _so._is_runtime_path("install.sh") is True)
check("runtime-path: README is noise", _so._is_runtime_path("README.md") is False)
check("runtime-path: any .md is noise", _so._is_runtime_path("docs/SECURITY.md") is False)
check("runtime-path: .github workflow is noise", _so._is_runtime_path(".github/workflows/ci.yml") is False)
check("runtime-path: tests are noise", _so._is_runtime_path("tests/unit_test.py") is False)
check("runtime-path: LICENSE is noise", _so._is_runtime_path("LICENSE") is False)
check("runtime-path: dotfiles are noise", _so._is_runtime_path(".gitignore") is False)
_orig_utr_git = _so._git
try:
    _so._git = lambda args, timeout=45: ("README.md\ndocs/x.md\n.github/workflows/ci.yml\n", "", 0)
    check("update-touches-runtime: docs-only diff -> no update", _so._update_touches_runtime("origin/main") is False)
    _so._git = lambda args, timeout=45: ("README.md\napp.py\n", "", 0)
    check("update-touches-runtime: any code change -> update", _so._update_touches_runtime("origin/main") is True)
    _so._git = lambda args, timeout=45: ("", "err", 1)
    check("update-touches-runtime: unknown diff -> assume update (fail safe)",
          _so._update_touches_runtime("origin/main") is True)
finally:
    _so._git = _orig_utr_git

# ── panel fail2ban: input validation rejects bad port / path before touching the host ──
check("panel-f2b: out-of-range port rejected", _so.configure_panel_fail2ban("/x", 70000)[0] is False)
check("panel-f2b: zero port rejected", _so.configure_panel_fail2ban("/x", 0)[0] is False)
check("panel-f2b: non-numeric port rejected", _so.configure_panel_fail2ban("/x", "nope")[0] is False)
check("panel-f2b: newline in log path rejected", _so.configure_panel_fail2ban("bad\npath", 5000)[0] is False)

# ── panel_commit: always a string (short SHA, or '' when not a git checkout) ──
check("panel-commit: returns a string", isinstance(_so.panel_commit(), str))

# ── change panel port: port_in_use + restart_panel dispatch ──
_orig_sorun = _so._run
try:
    _so._run = lambda c, **k: ("0.0.0.0:5000\n127.0.0.1:22\n[::]:8080\n", "", 0)
    check("port_in_use: detects a listening port", _so.port_in_use(5000) is True)
    check("port_in_use: ignores a free port", _so.port_in_use(9999) is False)
    check("port_in_use: matches bracketed IPv6 address", _so.port_in_use(8080) is True)
finally:
    _so._run = _orig_sorun

_orig_sorun2 = _so._run
try:
    _so._run = lambda c, **k: ("127.0.0.1\n100.84.48.111\n45.76.63.211\n", "", 0)
    check("host_has_ip: recognises a local address", _so.host_has_ip("100.84.48.111") is True)
    check("host_has_ip: rejects an address not on the host", _so.host_has_ip("10.0.0.9") is False)
finally:
    _so._run = _orig_sorun2

# ── perf guard: the /server-management host probe (sudo ufw + tailscale + apt, ~1.2s of
#    CPU across several subprocesses) is cached for _STATUS_TTL, so a page render and its
#    follow-up poll don't each re-run it. Mock the single subprocess entrypoint and count
#    how often it's actually hit across cold call / cached call / after invalidation. ──
_orig_ss_run = _so._run
_ss = {"n": 0}
try:
    _so._run = lambda c, **k: (_ss.__setitem__("n", _ss["n"] + 1), ("", "", 0))[1]
    _so._status_cache["data"] = None
    _so.get_server_status(force=True)          # cold: must probe the host
    check("perf: get_server_status probes the host on a cold call", _ss["n"] > 0)
    _ss["n"] = 0
    _so.get_server_status()                    # within TTL: served from cache, no subprocess
    check("perf: get_server_status is cached (no host re-probe on the next render)", _ss["n"] == 0)
    _so.invalidate_server_status()
    _so.get_server_status()                    # cache dropped: must probe again
    check("perf: invalidate_server_status forces a fresh probe", _ss["n"] > 0)
finally:
    _so._run = _orig_ss_run
    _so._status_cache["data"] = None

_orig_popen = _so.subprocess.Popen
_cap = {}
try:
    _so.subprocess.Popen = lambda a, **k: (_cap.update(args=a), type("P", (), {})())[1]
    _ok, _ = _so.restart_panel()
    check("restart_panel: dispatches successfully", _ok is True)
    check("restart_panel: targets the panel service via systemd-run restart",
          "systemd-run" in _cap["args"] and "restart" in _cap["args"]
          and "linuxgsm-panel.service" in _cap["args"])
    check("restart_panel: delays so the HTTP response can flush",
          any(str(x).startswith("--on-active=") for x in _cap["args"]))
finally:
    _so.subprocess.Popen = _orig_popen
check("integrity: parses modified status",
      {"path": "app.py", "status": "modified"} in _intg["modified"])
check("integrity: parses deleted status",
      {"path": "templates/base.html", "status": "deleted"} in _intg["modified"])

# Repair must ONLY ever check out files git itself reported as changed — a caller
# can't smuggle in an arbitrary path (path-traversal / arbitrary checkout).
_co = {}
def _repair_git(args, timeout=45):
    a = list(args)
    if a[:1] == ["checkout"]:
        _co["args"] = a
        return ("", "", 0)
    if a == ["rev-parse", "--short", "HEAD"]:
        return ("abc1234\n", "", 0)
    if a == ["diff", "--name-status", "HEAD"]:
        return ("M\tapp.py\n", "", 0)
    return ("", "", 0)
_so._git = _repair_git
_ok, _msg, _restored = _so.panel_repair(["app.py", "/etc/passwd", "../../secret"])
check("repair: restores only git-reported files", _restored == ["app.py"])
check("repair: rejects paths not in tampered set",
      "/etc/passwd" not in _co.get("args", []) and "../../secret" not in _co.get("args", []))
check("repair: uses HEAD + '--' path guard", _co["args"][:3] == ["checkout", "HEAD", "--"])

_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "", 0))
_ok2, _msg2, _ = _so.panel_repair()
check("repair: no-op when nothing is tampered", _ok2 is True and "Nothing to repair" in _msg2)

# Fail-safe: if git itself errors we must NOT claim the files are verified-clean.
_so._git = lambda args, timeout=45: (
    ("abc1234\n", "", 0) if list(args) == ["rev-parse", "--short", "HEAD"] else ("", "fatal", 1))
_intgf = _so.panel_integrity(force=True)
check("integrity: fail-safe when git errors (not verified)",
      _intgf.get("verified") is False and _intgf["clean"] is True)
_okf, _msgf, _ = _so.panel_repair()
check("repair: refuses when integrity can't be verified", _okf is False)

_so._is_git_checkout = lambda: False
check("integrity: handles non-git checkout", _so.panel_integrity(force=True)["git"] is False)
_ok3, _msg3, _ = _so.panel_repair()
check("repair: refuses when not a git checkout", _ok3 is False)

# ── automatic security updates detection ──────────────────────
def _mk_run(installed_rc, apt_out):
    def _r(cmd, timeout=30, sudo=False, text=True):
        if "dpkg-query" in cmd:
            return ("", "", installed_rc)
        if "apt-config" in cmd:
            return (apt_out, "", 0)
        return ("", "", 0)
    return _r
_so._run = _mk_run(0, 'APT::Periodic::Unattended-Upgrade "1";')
_au = _so.unattended_upgrades_status()
check("auto-updates: installed + enabled detected", _au["installed"] and _au["enabled"])
_so._run = _mk_run(0, 'APT::Periodic::Unattended-Upgrade "0";')
_au = _so.unattended_upgrades_status()
check("auto-updates: installed but disabled detected", _au["installed"] and not _au["enabled"])
_so._run = _mk_run(1, "")
_au = _so.unattended_upgrades_status()
check("auto-updates: not installed detected", not _au["installed"] and not _au["enabled"])

# ── shell-identifier validation (the core injection defense) ──
from models import _validate_shell_ident as _vsi
for _bad in ("a;b", "a b", "a`b", "a$(x)", "a|b", "../x", "a&b", "a>b", "x'y", 'x"y', "a\nb", "a/b"):
    _rej = False
    try:
        _vsi("field", _bad)
    except ValueError:
        _rej = True
    check("shell-ident rejects %r" % _bad, _rej)
for _good in ("gmodserver", "cod", "my-server_1", "a.b", ""):
    _acc = True
    try:
        _vsi("field", _good)
    except ValueError:
        _acc = False
    check("shell-ident accepts %r" % _good, _acc)

# ── _quote() single-quoting neutralizes shell metacharacters ──
eq("_quote wraps a plain string in single quotes", sm._quote("abc"), "'abc'")
eq("_quote escapes an embedded single quote", sm._quote("a'b"), "'a'\\''b'")
_q = sm._quote("; rm -rf / #")
check("_quote fully single-quotes a metachar payload", _q[0] == "'" and _q[-1] == "'")
check("_quote leaves no unescaped quote to break out",
      _q.count("'") % 2 == 0)  # every quote is balanced/escaped

# ── cron builders generate correct + safe crontab lines ───────
# Capture what would be written instead of touching a real crontab.
_cron = {}
def _cap_rewrite(server, user, grep_args, add_lines, extra_pre=""):
    _cron.update(grep=grep_args, add=list(add_lines), pre=extra_pre)
    return True, "ok"
sm._rewrite_crontab = _cap_rewrite

sm.set_autostart(None, "gmodserver", True)
# Autostart is now the LinuxGSM monitor cron (every 5 min), NOT a @reboot start line — monitor
# respects the server's intended state via the lockfile. The managed line runs through the inline
# recorder so the command stays VISIBLE (grep-based detection/removal still works).
check("autostart(on): adds the */5 monitor line, recorder-wrapped",
      _cron["add"][0].startswith("*/5 * * * * ")
      and "/home/gmodserver/gmodserver monitor" in _cron["add"][0]
      and ".lgsm-cron/" in _cron["add"][0] and ".status" in _cron["add"][0])
check("autostart(on): also strips any legacy @reboot start line",
      "@reboot" in _cron["grep"] and "monitor" in _cron["grep"])
sm.set_autostart(None, "gmodserver", False)
eq("autostart(off): removes line, adds none", _cron["add"], [])

sm.install_game_cron(None, "gmodserver", supported={"monitor", "update-lgsm"})
check("install_game_cron: monitor every 5 min (recorder-wrapped, command visible)",
      any(ln.startswith("*/5 * * * * ") and "/home/gmodserver/gmodserver monitor" in ln
          and ".status" in ln for ln in _cron["add"]))
check("install_game_cron: weekly update-lgsm (recorder-wrapped)",
      any(ln.startswith("30 5 * * 0 ") and "/home/gmodserver/gmodserver update-lgsm" in ln
          and ".status" in ln for ln in _cron["add"]))
eq("install_game_cron: only supported commands scheduled", len(_cron["add"]), 2)

sm.set_daily_restart(None, "gmodserver", game_type="gmod", port=27015, enabled=True)
check("daily_restart(mapped): sets pending flag at 05:00 (recorder-wrapped)",
      _cron["add"][0].startswith("0 5 * * * ")
      and "touch /home/gmodserver/.restart-pending" in _cron["add"][0]
      and ".status" in _cron["add"][0])
check("daily_restart(mapped): queries gamedig for player count",
      "gamedig --type garrysmod 127.0.0.1:27015" in _cron["add"][1])
sm.set_daily_restart(None, "noqueryserver", game_type="noquerygame", port=28960, enabled=True)
check("daily_restart(unmapped game): skips gamedig, no player query",
      "gamedig" not in _cron["add"][1] and "P=; " in _cron["add"][1])
sm.set_daily_restart(None, "gmodserver", enabled=False)
check("daily_restart(disable): adds nothing and clears the flag",
      _cron["add"] == [] and "rm -f" in _cron["pre"])

# ── server_live_metrics parses SSH output into a numeric dict ──
_METRICS_OUT = "\n".join([
    "cpu 100 0 100 800 0 0 0", "GJA 1000",
    "cpu 110 0 110 880 0 0 0", "GJB 1100",
    "MEM 8000000000 4000000000", "LOAD 0.5 0.4 0.3",
    "DISK 100000000000 33000000000", "CORES 4", "UPTIME 123456",
    "GAMERAM 524288 3", "GUP 3600", "PORT 1",
])
sm.run_command = lambda server, cmd, timeout=30, sudo=None: (_METRICS_OUT, "", 0)
_m = sm.server_live_metrics(None, "gmodserver", 27015)
eq("metrics: ram_total parsed", _m["ram_total"], 8000000000)
eq("metrics: ram_percent computed", _m["ram_percent"], 50.0)
eq("metrics: disk_percent computed", _m["disk_percent"], 33.0)
eq("metrics: cores parsed", _m["cores"], 4)
eq("metrics: uptime parsed", _m["uptime_secs"], 123456)
eq("metrics: game_ram_mb parsed", _m["game_ram_mb"], 512)
eq("metrics: game_procs parsed", _m["game_procs"], 3)
check("metrics: port_open true when a socket is listening", _m["port_open"] is True)
eq("metrics: cpu_percent from the /proc/stat delta", _m["cpu_percent"], 20.0)
eq("metrics: game_cpu_percent from the jiffie delta", _m["game_cpu_percent"], 100.0)

# ── remote_live_metrics parses CPU/MEM/DISK sections (incl. new disk fields) ──
_RLM_OUT = "\n".join([
    "===A", "cpu 100 0 100 800 0 0 0", "cpu0 25 0 25 200 0 0 0",
    "===B", "cpu 110 0 110 880 0 0 0", "cpu0 28 0 28 220 0 0 0",
    "===MEM", "MemTotal: 8000000 kB", "MemAvailable: 4000000 kB",
    "SwapTotal: 0 kB", "SwapFree: 0 kB",
    "===DISK", "Filesystem 1B-blocks Used Available Use% Mounted on",
    "/dev/vda2 100000000000 40000000000 60000000000 40% /",
])
sm.run_command = lambda server, cmd, timeout=12, **k: (_RLM_OUT, "", 0)
_rlm = sm.remote_live_metrics(NS(is_local=False, auth_method="tailscale", host="x", name="x"))
eq("remote metrics: disk_total parsed", _rlm["disk_total"], 100000000000)
eq("remote metrics: disk_used parsed", _rlm["disk_used"], 40000000000)
eq("remote metrics: disk_percent computed", _rlm["disk_percent"], 40.0)
eq("remote metrics: swap 0 -> no divide-by-zero", _rlm["swap_percent"], 0)

# ── pro_status is cached (don't respawn the heavy Ubuntu Pro client every page load) ──
_pro_n = {"n": 0}
_orig_pro_run = sm.run_command
try:
    def _procount(s, c, **k):
        _pro_n["n"] += 1
        return ('{"attached": true, "services": []}', "", 0)
    sm.run_command = _procount
    sm._pro_status_cache.clear()
    _psrv = NS(id=42, host="h")
    sm.pro_status(_psrv)         # primes the cache; return value isn't checked
    _r2 = sm.pro_status(_psrv)   # served from cache — no second run_command
    check("pro_status: cached (one run_command for two reads)", _pro_n["n"] == 1 and _r2["attached"] is True)
    sm.pro_status(_psrv, force=True)
    check("pro_status: force=True bypasses cache", _pro_n["n"] == 2)
    sm._pro_cache_invalidate(_psrv)
    sm.pro_status(_psrv)
    check("pro_status: invalidate forces a refetch", _pro_n["n"] == 3)
finally:
    sm.run_command = _orig_pro_run
    sm._pro_status_cache.clear()

# ── host_specs is cached (static hardware — don't re-run lscpu every page load) ──
_hs_n = {"n": 0}
_orig_hs_run = sm.run_command
try:
    def _hscount(s, c, **k):
        _hs_n["n"] += 1
        return ("OS\tUbuntu\nCORES\t1\nMEM\t0.9\n", "", 0)
    sm.run_command = _hscount
    sm._specs_cache.clear()
    _hsrv = NS(id=7, host="h")
    sm.host_specs(_hsrv)
    sm.host_specs(_hsrv)   # cached
    check("host_specs: cached (one run_command for two reads)", _hs_n["n"] == 1)
finally:
    sm.run_command = _orig_hs_run
    sm._specs_cache.clear()

# ── set_game_priority renices the game user's processes as ROOT (negative nice needs root) ──
_gp_calls = []
_orig_gp = sm.run_privileged
try:
    # Asserts the VERB and its arguments now, not a "sudo bash -c" substring. Same guarantee, and
    # it no longer passes just because the string happened to contain the right words.
    sm.run_privileged = lambda s, v, a=(), **k: (_gp_calls.append((v, list(a))), ("", "", 0))[1]
    sm.set_game_priority(None, "codserver")
    check("set_game_priority: renices the game user as root, via the verb",
          _gp_calls == [("renice-users", ["-1", "codserver"])], str(_gp_calls))
    _gp_calls.clear()
    sm.set_game_priority_bulk(None, ["codserver", "gmodserver"])
    check("set_game_priority_bulk: renices every game user in ONE call (keeper for cron restarts)",
          _gp_calls == [("renice-users", ["-1", "codserver", "gmodserver"])], str(_gp_calls))
    _gp_calls.clear()
    sm.set_game_priority_bulk(None, [])
    check("set_game_priority_bulk: no users -> no call", _gp_calls == [])
finally:
    sm.run_privileged = _orig_gp

# ── remote_uptime is ONE ssh round-trip (was eight) + parses the composite output + caches ──
_orig_ru = sm.run_command
try:
    _ru_n = {"n": 0}
    _ru_out = "\n".join([
        "UPTIME up 3 days, 4 hours", "LOAD 0.15 0.10 0.05", "DISK 5.0G/20G",
        "MEM 1.2G/4.0G", "MEMPCT 30.0", "KERNEL 6.1.0", "CORES 2",
        "cpu 100 0 100 800 0 0 0",   # sample A: total 1000, idle 800
        "cpu 150 0 150 900 0 0 0",   # sample B: total 1200, idle 900 → idleΔ100/totalΔ200 = 50% busy
    ])

    def _ru_fake(server, cmd, **k):
        _ru_n["n"] += 1
        return (_ru_out, "", 0)
    sm.run_command = _ru_fake
    sm._uptime_cache.clear()
    _usrv = NS(id=7)
    _ru = sm.remote_uptime(_usrv)
    check("uptime: a SINGLE ssh round-trip (was 8 separate commands)", _ru_n["n"] == 1)
    eq("uptime: parses the uptime string", _ru["uptime"], "3 days, 4 hours")
    eq("uptime: parses cores", _ru["cpu_cores"], "2")
    eq("uptime: parses memory", _ru["memory"], "1.2G/4.0G")
    eq("uptime: cpu% from /proc/stat delta", _ru["cpu_percent"], "50.0")
    eq("uptime: cpu per-core derived", _ru["cpu_per_core"], "25.0")
    sm.remote_uptime(_usrv)   # within TTL → served from cache, no 2nd ssh
    check("uptime: second call served from cache", _ru_n["n"] == 1)
    sm.remote_uptime(_usrv, force=True)   # force bypasses cache
    check("uptime: force=True re-reads", _ru_n["n"] == 2)
finally:
    sm.run_command = _orig_ru
    sm._uptime_cache.clear()

# ── apt upgradable parsing: name + old→new version ──
_APT_OUT = "\n".join([
    "Listing...",
    "libssl3/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.12]",
    "curl/jammy-updates 7.81.0-1ubuntu1.16 amd64 [upgradable from: 7.81.0-1ubuntu1.15]",
    "",
])
_pu = sm._parse_upgradable(_APT_OUT)
eq("apt parse: count (Listing/blank skipped)", len(_pu), 2)
eq("apt parse: sorted by name (curl first)", _pu[0]["name"], "curl")
eq("apt parse: new version", _pu[1]["name"] == "libssl3" and _pu[1]["version"], "3.0.2-0ubuntu1.15")
eq("apt parse: old (from) version", _pu[1]["from"], "3.0.2-0ubuntu1.12")
_pu2 = sm._parse_upgradable("")
eq("apt parse: empty -> no packages", len(_pu2), 0)
# The suite is the ONLY field distinguishing a security update from a routine one, and the OS-update
# alert titles itself off it. Without this, dropping the field is invisible: the smoke test feeds the
# alert ready-made dicts, so nothing else exercises the parse.
eq("apt parse: suite kept (this is what marks a security update)", _pu[1]["suite"], "jammy-security")
eq("apt parse: a non-security suite is kept as-is", _pu[0]["suite"], "jammy-updates")
check("apt parse: -security is detectable from the suite",
      "-security" in _pu[1]["suite"] and "-security" not in _pu[0]["suite"])
# apt writes "N: ..." notices to stdout, and the pipeline no longer greps them out (its exit status
# was masking apt's own — see remote_os_check_updates). They must not parse as packages.
_pu3 = sm._parse_upgradable("\n".join([
    "Listing...",
    "N: There is 1 additional version. Please use the '-a' switch to see it",
    "bash/jammy-security 5.1-6ubuntu1.1 amd64 [upgradable from: 5.1-6ubuntu1]",
]))
eq("apt parse: apt notices are not packages", [p["name"] for p in _pu3], ["bash"])
# Both hosts parse the same apt output, so they go through one parser.
check("apt parse: local and remote share one implementation",
      SO.parse_upgradable(_APT_OUT) == _pu)

# Two more shapes main's checks above don't reach. A package in BOTH pockets is listed with a
# comma, which is the real shape of most security updates — "-security" has to still be found in it.
_pu_comma = sm._parse_upgradable(
    "libc6/jammy-updates,jammy-security 2.35-0ubuntu3.8 amd64 [upgradable from: 2.35-0ubuntu3.6]")
eq("apt parse: comma-joined suites kept whole", _pu_comma[0]["suite"], "jammy-updates,jammy-security")
check("apt parse: a comma-joined suite still reads as security",
      "-security" in _pu_comma[0]["suite"])
# And the local path end to end, through the same parser, with apt's exit status carried out as
# `ok` — a failed check must not be readable as "nothing waiting". Stub _run so this stays offline.
_sv_run = SO._run
try:
    SO._run = lambda cmd, **kw: (_APT_OUT, "", 0)
    _loc = SO.os_update_available(refresh=False)
    eq("os_update_available: count matches the shared parser", _loc["count"], 2)
    eq("os_update_available: keeps the suite too",
       [p["suite"] for p in _loc["packages"]], ["jammy-updates", "jammy-security"])
    check("os_update_available: a good check reports ok", _loc["ok"] is True)
    SO._run = lambda cmd, **kw: ("", "E: Could not get lock", 100)
    _bad = SO.os_update_available(refresh=False)
    check("os_update_available: a FAILED check is not silently 'nothing waiting'",
          _bad["ok"] is False and _bad["count"] == 0)
finally:
    SO._run = _sv_run

# ── The snapshot the login banner and the OS Updates card read ────────────────────────
# Both used to show nothing until someone pressed "Check": the panel knew what each host had
# waiting (the daily sweep asks) but never kept the answer anywhere a page could read it. This is
# that store. What it must NOT do is record a failed check — apt emits nothing when it fails, which
# is byte-for-byte what a clean host emits, so storing it would clear a real banner and state that
# the host is up to date when in fact nobody managed to ask it.
from app import _os_update_note as _oun, _os_update_seen as _seen, _is_security_pkg as _isec

check("security pkg: the -security suite is what marks one",
      _isec({"suite": "jammy-security"}) and not _isec({"suite": "jammy-updates"}))
check("security pkg: a comma-joined suite still reads as security",
      _isec({"suite": "jammy-updates,jammy-security"}))
check("security pkg: a package with no suite at all is not a security update",
      not _isec({"name": "vim"}) and not _isec({}) and not _isec(None))

_host = NS(id=4242, display_name="Panel Server")
_seen.pop(_host.id, None)
try:
    _oun(_host, {"ok": True, "packages": [{"name": "vim", "suite": "jammy-updates"},
                                          {"name": "openssl", "suite": "jammy-security"}]})
    eq("os-update snapshot: records what the host has waiting", _seen[_host.id]["count"], 2)
    eq("os-update snapshot: counts the security ones separately", _seen[_host.id]["security"], 1)
    eq("os-update snapshot: keeps the package list for the card",
       [p["name"] for p in _seen[_host.id]["packages"]], ["vim", "openssl"])
    eq("os-update snapshot: names the host for the banner", _seen[_host.id]["name"], "Panel Server")

    # The guarantee: a check that FAILED leaves the last real answer standing.
    _oun(_host, {"ok": False, "packages": []})
    eq("os-update snapshot: a FAILED check does not erase what we knew",
       _seen[_host.id]["count"], 2)
    _oun(_host, None)
    eq("os-update snapshot: no result at all does not erase it either",
       _seen[_host.id]["count"], 2)

    # ...but a check that SUCCEEDS and finds nothing does clear it, which is how installing the
    # updates from the panel takes the banner down instead of leaving it up until tomorrow.
    _oun(_host, {"ok": True, "packages": []})
    eq("os-update snapshot: a clean host clears the count", _seen[_host.id]["count"], 0)
    eq("os-update snapshot: and its security count", _seen[_host.id]["security"], 0)
finally:
    _seen.pop(_host.id, None)

# ── config save/load round-trips (guards the atomic-write path) ─
_cfg_backup = config.CONFIG_FILE.read_text() if config.CONFIG_FILE.exists() else None
try:
    _c = config.load_config()
    _c["_roundtrip_probe"] = "value-123"
    config.save_config(_c)
    check("config: value survives a save/load round-trip",
          config.load_config().get("_roundtrip_probe") == "value-123")
    check("config: file exists after atomic save", config.CONFIG_FILE.exists())
finally:
    if _cfg_backup is not None:
        config.CONFIG_FILE.write_text(_cfg_backup)

# ── database corruption detection + self-heal (bad drive / power loss) ─
import sqlite3 as _sqlite
import tempfile as _tempfile
import shutil as _shutil
from models import _db_quick_check, _ensure_db_healthy
_dbdir = _tempfile.mkdtemp()
_dbp = os.path.join(_dbdir, "t.db")
try:
    _c = _sqlite.connect(_dbp)
    _c.execute("CREATE TABLE x (a INTEGER)")
    _c.executemany("INSERT INTO x VALUES (?)", [(i,) for i in range(200)])
    _c.commit()
    _c.close()
    check("corrupt: a healthy DB passes quick_check", _db_quick_check(_dbp) is True)

    # A healthy startup makes/refreshes the rolling backup.
    _ensure_db_healthy(_dbp)
    check("corrupt: a rolling backup is created for a healthy DB", os.path.exists(_dbp + ".backup"))

    # Simulate a bad drive: clobber the middle of the file (leave the 100-byte
    # header so it still 'opens' as a DB but is malformed).
    with open(_dbp, "r+b") as _f:
        _f.seek(100)
        _f.write(b"\x00" * 4000)
    check("corrupt: a malformed DB fails quick_check", _db_quick_check(_dbp) is False)

    # Self-heal: restore from the backup, preserve the corrupt file aside, keep data.
    _ensure_db_healthy(_dbp)
    check("corrupt: DB is auto-restored to a healthy state", _db_quick_check(_dbp) is True)
    check("corrupt: the corrupt file is preserved aside (not destroyed)",
          any(fn.startswith("t.db.corrupt-") for fn in os.listdir(_dbdir)))
    _r = _sqlite.connect(_dbp).execute("SELECT COUNT(*) FROM x").fetchone()[0]
    eq("corrupt: restored data is intact", _r, 200)

    # No good backup + corrupt live DB -> move the corrupt file aside so the app can
    # start fresh instead of crash-looping (the bad file is preserved, not deleted).
    _dbp2 = os.path.join(_dbdir, "u.db")
    with open(_dbp2, "wb") as _f:
        _f.write(b"this is not a database at all, just garbage bytes" * 50)
    _ensure_db_healthy(_dbp2)   # no u.db.backup exists — must not raise
    check("corrupt: with no backup, the corrupt DB is moved aside (start-fresh)",
          not os.path.exists(_dbp2) and any(fn.startswith("u.db.corrupt-")
                                            for fn in os.listdir(_dbdir)))
finally:
    _shutil.rmtree(_dbdir, ignore_errors=True)

# ── config._create_key_once: atomic create-exactly-once (race-safe key files) ──
# Guards against two concurrent first-time saves each generating a different cred_key and
# clobbering the other (which would make the first-encrypted secret undecryptable).
_kd = _tempfile.mkdtemp()
try:
    _kp = os.path.join(_kd, "k")
    config._create_key_once(_kp, lambda: b"FIRST")
    with open(_kp, "rb") as _f:
        check("keyonce: creates the file with the generated bytes", _f.read() == b"FIRST")
    config._create_key_once(_kp, lambda: b"SECOND")   # must be a no-op (O_EXCL)
    with open(_kp, "rb") as _f:
        check("keyonce: never overwrites an existing key file", _f.read() == b"FIRST")
    # And a full encrypt→decrypt round-trip still works against a created cred key.
    _sec = config.encrypt_secret("hunter2-secret")
    check("keyonce: encrypt produces an enc:v1: blob", config.is_encrypted(_sec))
    check("keyonce: decrypt round-trips the plaintext", config.decrypt_secret(_sec) == "hunter2-secret")
finally:
    _shutil.rmtree(_kd, ignore_errors=True)

# ── Ubuntu Pro status persists (set-and-forget: no re-running the slow client every visit) ──
from models import RemoteServer as _RS
_pr = _RS()
check("pro-cache: empty -> None", _pr.cached_pro is None)
_pr.update_pro_cache({"attached": True, "installed": True, "services": []})
_pc = _pr.cached_pro
check("pro-cache: round-trips the status dict", bool(_pc) and _pc["data"]["attached"] is True)
check("pro-cache: stamps a timestamp for staleness checks", isinstance(_pc.get("ts"), int) and _pc["ts"] > 0)
_pr.pro_cache = "{not valid json"
check("pro-cache: malformed stored value -> None (never raises)", _pr.cached_pro is None)

# ── dashboard port-scan cache: concurrent polls share ONE ssh scan per remote ──
_app = sys.modules["app"]   # already imported via `from app import ...` above
# The scan and its cache live in ssh_manager now, so the stub has to replace THAT module's
# run_command — patching app's would leave the real one in place and make every assertion below
# measure nothing.
_o_ps_rc = sm.run_command
try:
    _scan_n = {"n": 0}

    def _fake_ss(remote, cmd, **k):
        _scan_n["n"] += 1
        return ("127.0.0.1:22\n*:27015\n[::]:27016", "", 0)

    sm.run_command = _fake_ss
    sm._port_scan_cache.clear()
    _rem = NS(id=99)
    _p1 = _app._remote_listening_ports(_rem)
    _app._remote_listening_ports(_rem)   # within TTL → cache hit, no 2nd ssh
    check("portscan: parses listening ports", 27015 in _p1 and 22 in _p1 and 27016 in _p1)
    check("portscan: second concurrent poll served from cache (one ssh)", _scan_n["n"] == 1)
    _app._invalidate_port_scan(99)
    _app._remote_listening_ports(_rem)   # invalidated → re-scans
    check("portscan: invalidate forces a fresh scan", _scan_n["n"] == 2)
    # A failed scan (empty output) must NOT be cached, so a blip doesn't pin servers offline.
    sm.run_command = lambda remote, cmd, **k: ("", "err", -1)
    sm._port_scan_cache.clear()
    _app._remote_listening_ports(_rem)
    check("portscan: an empty/failed scan is not cached", 99 not in sm._port_scan_cache)
finally:
    sm.run_command = _o_ps_rc
    sm._port_scan_cache.clear()

# ── debug report: redaction + secret-key whitelist (must not leak) ─
_rd = _so._redact
check("redact: masks email addresses", "[email]" in _rd("reach me at admin@example.com now"))
check("redact: masks long token/key strings",
      "[redacted]" in _rd("key exampletokenexampletokenexampletoken12345"))
check("redact: masks key=value secrets", "[redacted]" in _rd("password=hunter2superSecret"))
check("redact: masks token: value", "[redacted]" in _rd("auth_token: abc.def.ghi"))
check("redact: leaves ordinary text intact", "server is offline" in _rd("server is offline"))
_secret_keys = {"secret_key", "cred_key", "secret", "credentials", "auth_credential",
                "host_key", "totp_secret", "backup_codes", "password"}
check("debug whitelist excludes every secret key",
      not (set(_so._DEBUG_CONFIG_KEYS) & _secret_keys))

# ── panel self-update CI gate: don't offer an update until its CI has passed ──
# _repo_slug must parse both HTTPS and SSH remote URLs (so the check works on forks).
_orig_rslug_git = _so._git
try:
    def _slug_git(args, timeout=45):
        return ("https://github.com/FMSMITH91/linuxgsm-panel.git\n", "", 0)
    _so._git = _slug_git
    eq("update: repo slug parsed from origin URL", _so._repo_slug(), "FMSMITH91/linuxgsm-panel")
finally:
    _so._git = _orig_rslug_git

# _remote_ci_state maps GitHub's Actions API response to passing/pending/failing, and
# never raises on a network/parse error (returns 'unknown', treated leniently).
import io as _io
_orig_ci_slug = _so._repo_slug
_orig_urlopen = _so.urllib.request.urlopen
try:
    _so._repo_slug = lambda: "o/r"

    def _fake_open(payload):
        def _op(req, timeout=8):
            return _io.BytesIO(payload.encode() if isinstance(payload, str) else payload)
        return _op

    # The gate now requires EVERY check-run (except 'deploy') to be completed + successful.
    _all_ok = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
               '{"name":"Analyze (python)","status":"completed","conclusion":"success"},'
               '{"name":"lighthouse","status":"completed","conclusion":"success"}]}')
    _so.urllib.request.urlopen = _fake_open(_all_ok)
    eq("ci-gate: all checks passed -> passing", _so._remote_ci_state("a"*40), "passing")
    # CI passed but Lighthouse still running -> pending (the exact case the user hit).
    _lh_running = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                   '{"name":"lighthouse","status":"in_progress","conclusion":null}]}')
    _so.urllib.request.urlopen = _fake_open(_lh_running)
    eq("ci-gate: one check still running -> pending", _so._remote_ci_state("a"*40), "pending")
    # One check failed (even if the rest passed) -> failing.
    _one_fail = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                 '{"name":"lighthouse","status":"completed","conclusion":"failure"}]}')
    _so.urllib.request.urlopen = _fake_open(_one_fail)
    eq("ci-gate: any check failed -> failing", _so._remote_ci_state("a"*40), "failing")
    # 'deploy' is ignored: a pending deploy alongside all-passing checks is still passing.
    _deploy_pending = ('{"check_runs":[{"name":"checks","status":"completed","conclusion":"success"},'
                       '{"name":"deploy","status":"in_progress","conclusion":null}]}')
    _so.urllib.request.urlopen = _fake_open(_deploy_pending)
    eq("ci-gate: pending 'deploy' is ignored -> passing", _so._remote_ci_state("a"*40), "passing")
    _so.urllib.request.urlopen = _fake_open('{"check_runs":[]}')
    eq("ci-gate: no checks yet -> pending", _so._remote_ci_state("a"*40), "pending")

    def _boom(req, timeout=8):
        raise _so.urllib.error.URLError("offline")
    _so.urllib.request.urlopen = _boom
    eq("ci-gate: network error -> unknown (never raises)", _so._remote_ci_state("a"*40), "unknown")
finally:
    _so._repo_slug = _orig_ci_slug
    _so.urllib.request.urlopen = _orig_urlopen

# panel_self_update ENFORCES the CI gate server-side (not just by hiding the button), and
# re-checks fresh so it also catches a bad commit that landed between page-load and click.
_orig_isgit = _so._is_git_checkout
_orig_pus = _so.panel_update_status
_orig_isfile = _so.os.path.isfile
try:
    _so._is_git_checkout = lambda: True
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "failing"}
    _ok, _m = _so.panel_self_update()
    check("self-update: refuses a commit that FAILED CI", _ok is False and "didn't pass" in _m)
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "pending"}
    _ok, _m = _so.panel_self_update()
    check("self-update: refuses while CI is still running", _ok is False and "being verified" in _m)
    # A CI-passing commit must get PAST the gate. Make install.sh look missing so it stops
    # there (proving the gate let it through) instead of actually launching an update.
    _so.os.path.isfile = lambda p: False
    _so.panel_update_status = lambda force=False: {"behind": 1, "ci_state": "passing"}
    _ok, _m = _so.panel_self_update()
    check("self-update: a CI-passing commit is NOT blocked by the gate",
          _ok is False and "install.sh is missing" in _m)
finally:
    _so._is_git_checkout = _orig_isgit
    _so.panel_update_status = _orig_pus
    _so.os.path.isfile = _orig_isfile

# ── _compute_update_status targets the newest VERIFIED commit ──
# When the tip is still verifying but an earlier commit already passed CI, the panel must
# offer that earlier verified commit (not block entirely, and not jump to the pending tip).
_cus_git = _so._git
_cus_isco = _so._is_git_checkout
_cus_ver = _so.panel_version
_cus_ci = _so._remote_ci_state
try:
    _so._is_git_checkout = lambda: True
    _so.panel_version = lambda: "1.0.0"

    def _mk_git(behind, commits):
        # commits: full SHAs, newest (tip) first.
        def _g(args, timeout=45):
            if args[0] == "fetch":
                return ("", "", 0)
            if args[:3] == ["rev-parse", "--short", "HEAD"]:
                return ("headabc", "", 0)
            if args[:2] == ["rev-list", "--count"]:
                return (str(behind), "", 0)
            if args[:3] == ["rev-parse", "--short", "origin/main"]:
                return (commits[0][:7] if commits else "", "", 0)
            if args[0] == "rev-list" and "-n" in args:
                return ("\n".join(commits), "", 0)
            if args[0] == "show" and str(args[-1]).endswith(":VERSION"):
                return ("9.9.9", "", 0)
            if args[0] == "log":
                return ("c1 a change", "", 0)
            return ("", "", 0)
        return _g

    _C = ["a" * 40, "b" * 40, "c" * 40]   # tip=a, mid=b, old=c

    # tip pending, middle passed → offer the middle (skip the pending tip).
    _so._git = _mk_git(3, _C)
    _so._remote_ci_state = lambda sha: {"a" * 40: "pending", "b" * 40: "passing",
                                        "c" * 40: "passing"}.get(sha, "unknown")
    _r = _so._compute_update_status()
    check("update-target: offers the verified commit when the tip is pending",
          _r["update_available"] and _r["target_sha"] == "b" * 40)
    eq("update-target: newer unverified counted", _r.get("newer_unverified"), 1)
    eq("update-target: behind is measured to the target, not the tip", _r["behind"], 2)

    # tip passed → target is the tip, nothing pending above it.
    _so._remote_ci_state = lambda sha: "passing"
    _r = _so._compute_update_status()
    check("update-target: tip passed -> target is the tip",
          _r["update_available"] and _r["target_sha"] == "a" * 40 and _r["newer_unverified"] == 0)

    # everything still verifying → offer nothing, explain why.
    _so._remote_ci_state = lambda sha: "pending"
    _r = _so._compute_update_status()
    check("update-target: all pending -> no update offered",
          _r["update_available"] is False and _r["ci_state"] == "pending")
finally:
    _so._git = _cus_git
    _so._is_git_checkout = _cus_isco
    _so.panel_version = _cus_ver
    _so._remote_ci_state = _cus_ci

# ── Tailscale: installed-but-not-authenticated (NeedsLogin) must not 500 ─
import tailscale_integration as _tsi
_tsi._run_ts = lambda args, timeout=5: (("1.0", "", 0) if args and args[0] in ("version", "--version")
                                        else ("", "", 0))
# After `tailscale up` prints a login URL the user hasn't clicked, status --json has
# null Peer/Self/TailscaleIPs — the page used to crash iterating None.
_tsi._run_ts_json = lambda args, timeout=5: {"BackendState": "NeedsLogin",
                                             "Self": None, "Peer": None, "TailscaleIPs": None}
_tsinfo = _tsi._get_tailscale_info()
check("tailscale: NeedsLogin state parses without crashing", _tsinfo.installed and not _tsinfo.running)
check("tailscale: null Peer -> no peers (no None.items())", _tsinfo.peers == [])
check("tailscale: null TailscaleIPs -> empty list", _tsinfo.tailscale_ips == [])
check("tailscale: backend_state captured as NeedsLogin", _tsinfo.backend_state == "NeedsLogin")
# The bind suggestion must point the user at linking (not "no Tailscale detected") in NeedsLogin,
# so the page can offer a clear "Link this machine" action instead of looking un-installed.
_tsi._cache["info"] = None  # bypass the 15s cache so suggest_best_bind re-reads our mock
_tssug = _tsi.suggest_best_bind(5000)
check("tailscale: NeedsLogin suggestion tells user to link, not 'not detected'",
      "not linked" in _tssug["description"].lower())
_tsi._cache["info"] = None

# REGRESSION: Tailscale up WITH a MagicDNS name but Serve NOT configured must NOT bind to loopback
# (that hid the panel on 127.0.0.1 with nothing proxying to it — a fresh install was unreachable).
from tailscale_integration import TailscaleInfo   # noqa: E402
_orig_gti = _tsi.get_tailscale_info
try:
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net", serve_config={"services": [], "raw": "No serve config"})
    _tsi._cache["info"] = None
    _bns = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name but Serve NOT set up -> does NOT bind loopback",
          _bns["bind_host"] != "127.0.0.1")
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net",
        serve_config={"services": [{"url": "https://host.example.ts.net", "routes": [{}]}], "raw": "x"})
    _tsi._cache["info"] = None
    _bys = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name + Serve configured -> binds loopback for Serve",
          _bys["bind_host"] == "127.0.0.1" and _bys["method"] == "tailscale-serve")
finally:
    _tsi.get_tailscale_info = _orig_gti
    _tsi._cache["info"] = None

# ── Debug report: repeated tracebacks in the log tail get collapsed ───
_pfx = "Jul 05 23:44:%02d vultr python[74699]: "
_one_tb = [
    _pfx % 14 + "Traceback (most recent call last):",
    _pfx % 14 + '  File "/x.py", line 1, in main',
    _pfx % 14 + "    do()",
    _pfx % 14 + "ssl.SSLError: sslv3 alert certificate unknown",
]
# same traceback logged 3× at different timestamps, interleaved with unique lines
_noisy = "\n".join(
    _one_tb + [_pfx % 15 + "Removing descriptor: 12"]
    + _one_tb + [_pfx % 16 + "Removing descriptor: 13"]
    + _one_tb + [_pfx % 17 + "Removing descriptor: 14"]
)
_dd = _so._dedupe_log_tracebacks(_noisy)
check("log dedupe: keeps exactly one full copy of a repeated traceback",
      _dd.count("Traceback (most recent call last):") == 1)
check("log dedupe: annotates the collapsed repeats", "repeated 2× more" in _dd)
check("log dedupe: preserves the surrounding unique lines",
      "Removing descriptor: 12" in _dd and "Removing descriptor: 14" in _dd)
# distinct tracebacks must NOT be collapsed into each other
_distinct = "\n".join([
    _pfx % 14 + "Traceback (most recent call last):",
    _pfx % 14 + "ValueError: bad",
    _pfx % 15 + "Traceback (most recent call last):",
    _pfx % 15 + "KeyError: nope",
])
_dd2 = _so._dedupe_log_tracebacks(_distinct)
check("log dedupe: distinct tracebacks are both kept",
      _dd2.count("Traceback (most recent call last):") == 2
      and "ValueError" in _dd2 and "KeyError" in _dd2)

# ── mods parsing (real LinuxGSM formats, verified on a live Garry's Mod box) ──
_mods_avail_out = (
    "\x1b[1mGarry's Mod Installing Mods\x1b[0m\n"
    "=================================\n"
    "Available addons/mods\n"
    "=================================\n"
    "Metamod: Source - Plugins Framework - https://www.sourcemm.net\n"
    " * \x1b[36mmetamodsource\x1b[0m\n"
    "SourceMod - Admin Features (requires Metamod: Source) - http://www.sourcemod.net\n"
    " * \x1b[36msourcemod\x1b[0m\n"
    "Wiremod Extras - Addition to Wiremod - https://github.com/wiremod/wire-extras/\n"
    " * \x1b[36mwiremod-extras\x1b[0m\n"
)
_av = sm._parse_mods_available(_mods_avail_out)
check("mods: available parses id + name from ' * <id>' format",
      [m["id"] for m in _av] == ["metamodsource", "sourcemod", "wiremod-extras"]
      and _av[0]["name"] == "Metamod: Source")
# REGRESSION: LinuxGSM lists an 'Installed addons/mods' section (bare ' * <id>' lines, no
# description) BEFORE 'Available addons/mods'. Those bare ids must NOT be emitted as phantom mods
# named after the section header, nor duplicate the real Available rows (bug: ulib/ulx showed twice).
_mods_avail_full = (
    "Garry's Mod Installing Mods\n"
    "=================================\n"
    "Installed addons/mods\n"
    "=================================\n"
    " * ulib\n"
    " * ulx\n"
    "\n"
    "Available addons/mods\n"
    "=================================\n"
    "Metamod: Source - Plugins Framework - https://www.sourcemm.net\n"
    " * metamodsource\n"
    "ULib - Complete Framework - http://ulyssesmod.net\n"
    " * ulib\n"
    "ULX - Admin Panel (requires ULib) - http://ulyssesmod.net\n"
    " * ulx\n"
    "Enter an addon/mod to install (or exit to abort):\n"
)
_avf = sm._parse_mods_available(_mods_avail_full)
_avf_ids = [m["id"] for m in _avf]
check("mods: the 'Installed addons/mods' section is not emitted as phantom entries",
      not any(m["name"].lower() == "installed addons/mods" for m in _avf))
check("mods: each available id appears exactly once (ulib/ulx not duplicated)",
      _avf_ids == ["metamodsource", "ulib", "ulx"])
check("mods: the deduped ulib/ulx keep their real names, not the section header",
      {m["id"]: m["name"] for m in _avf}.get("ulib") == "ULib"
      and {m["id"]: m["name"] for m in _avf}.get("ulx") == "ULX")
_mods_inst_out = (
    "Garry's Mod Removing Mods\n"
    "=================================\n"
    "Remove addons/mods\n"
    "=================================\n"
    "metamodsource - Metamod: Source - Plugins Framework\n"
    "Enter an addon/mod to remove (or exit to abort): "
)
_in = sm._parse_mods_installed(_mods_inst_out)
check("mods: installed parses '<id> - <name>' format",
      len(_in) == 1 and _in[0]["id"] == "metamodsource" and _in[0]["name"] == "Metamod: Source")
check("mods: 'No installed mods' output yields empty list",
      sm._parse_mods_installed("Failure! No installed mods or addons were found") == [])
# A game with no mods installer (cod) prints 'Unknown command' + a 'LinuxGSM - <Game> - Version …'
# banner — that banner must NOT be parsed as an installed mod.
_cod_out = ("Error! Unknown command: ./codserver mods-remove\n"
            "LinuxGSM - Call of Duty - Version v26.1.0\nstart st | Start the server.")
check("mods: 'Unknown command' output -> game not supported", sm._game_supports_mods(_cod_out) is False)
check("mods: version banner isn't parsed as an installed mod",
      not any(m["id"] == "LinuxGSM" for m in sm._parse_mods_installed(_cod_out)))
check("mods: a real mods list is still 'supported'",
      sm._game_supports_mods("metamodsource - Metamod: Source - desc") is True)
# mods_action rejects unsafe ids before ever building a shell command (injection guard)
check("mods: mods_action rejects an unsafe id",
      sm.mods_action(None, "u", "u", "install", "foo; rm -rf x")[1] == "invalid mod id")

# game-backup download/delete validate the file name before touching any path (server=None here,
# so a passing regex would crash — proving rejection happens purely on the name)
check("game backup: delete rejects an unsafe name",
      sm.delete_game_backup(None, "u", "x; rm -rf y") is False)
check("game backup: delete rejects a path-traversal name",
      sm.delete_game_backup(None, "u", "../../etc/passwd") is False)
check("game backup: stream yields nothing for an unsafe name",
      list(sm.stream_game_backup(None, "u", "../../etc/passwd")) == [])
check("game backup: name shape accepts a real archive",
      bool(sm._GAME_BACKUP_NAME.match("gmodserver-2026-07-06-141117.tar.zst")))

# ── discover_linuxgsm_servers: parse the one-shot host scan output ──
_orig_disc_rc = sm.run_command
try:
    sm.run_command = lambda *a, **k: (
        "FOUND|gmodserver|gmodserver|27015|3|2|4|1\n"
        "FOUND|myrust|rustserver|28015|0|0|0|0\n"
        "some unrelated line\n"
        "FOUND|shortline|gmodserver|0\n"          # missing the count fields -> skipped
        "FOUND|zeroport|csgoserver|0|0|0|0|0\n", "", 0)
    _disc = sm.discover_linuxgsm_servers(None)
    eq("discover: keeps only well-formed (8-field) FOUND lines", len(_disc), 3)
    check("discover: parses user / lgsm_name / port + backup/mod/cron counts + autostart",
          _disc[0] == {"user": "gmodserver", "lgsm_name": "gmodserver", "port": 27015,
                       "backups": 3, "mods": 2, "cron": 4, "autostart": True})
    check("discover: a 0/blank port becomes None and autostart is False",
          _disc[2]["user"] == "zeroport" and _disc[2]["port"] is None
          and _disc[2]["autostart"] is False)
    sm.run_command = lambda *a, **k: ("", "err", 1)
    check("discover: returns [] when the scan command fails", sm.discover_linuxgsm_servers(None) == [])
finally:
    sm.run_command = _orig_disc_rc

# ── lgsm_name_to_game_type: gameservername -> panel game_type, from serverlist.csv ──
check("lgsm-name map: gmodserver -> gmod", _app.lgsm_name_to_game_type("gmodserver") == "gmod")
check("lgsm-name map: rustserver -> rust", _app.lgsm_name_to_game_type("rustserver") == "rust")
check("lgsm-name map: an unknown script -> None", _app.lgsm_name_to_game_type("notagameserver") is None)

# ── GameServer.supports_update: drives the (bulk) Update button + backend skip per game ──
check("supports_update: fetched list exposing 'update' -> True",
      _GS(commands='[{"cmd":"update"},{"cmd":"start"}]').supports_update is True)
check("supports_update: fetched list with no 'update' -> False",
      _GS(commands='[{"cmd":"start"},{"cmd":"stop"}]').supports_update is False)
check("supports_update: empty list + known no-update game (cod) -> False",
      _GS(commands='[]', game_type='cod').supports_update is False)
check("supports_update: empty list + SteamCMD game -> True (fail open)",
      _GS(commands='[]', game_type='csgo').supports_update is True)

# ── list_server_commands: parse LinuxGSM's command menu. This is what populates the
#    "Supported Commands" panel; import now auto-caches it in the background, so lock in
#    that a realistic menu (with ANSI colour + non-menu noise lines) parses correctly. ──
_LGSM_MENU = (
    "\x1b[0m./gmodserver [option]\n"
    "start         st   | Start the server.\n"
    "stop          sp   | Stop the server.\n"
    "update        u    | Check and apply any updates.\n"
    "some banner line without a pipe here\n"
    "details       dt   | Display server information.\n"
)
_saved_run = sm.run_command
try:
    sm.run_command = lambda *a, **k: (_LGSM_MENU, "", 0)
    _parsed = sm.list_server_commands(NS(), "gmodserver")
finally:
    sm.run_command = _saved_run
_pc = {c["cmd"]: c for c in _parsed}
check("list_server_commands: parses start (with short code)",
      _pc.get("start", {}).get("short") == "st")
check("list_server_commands: parses update", "update" in _pc)
eq("list_server_commands: captures description", _pc.get("details", {}).get("desc"),
   "Display server information.")
check("list_server_commands: ignores the ./script header + no-pipe banner lines",
      "some" not in _pc and "gmodserver" not in _pc and len(_pc) == 4)

# ── player moderation: engine-aware caps, status/list parsers + injection-safe commands ──
check("moderation: gmod (valve) supports kick + ban + say",
      sm.moderation_caps("gmod") == {"kick": True, "ban": True, "say": True})
check("moderation: minecraft supports kick + ban + say",
      sm.moderation_caps("mc") == {"kick": True, "ban": True, "say": True})
check("moderation: cod (idTech3) supports kick + ban + say",
      sm.moderation_caps("cod") == {"kick": True, "ban": True, "say": True})
check("moderation: a non-console game (rust) supports nothing",
      sm.moderation_caps("rust") == {"kick": False, "ban": False, "say": False})
check("engine: gmod->valve, cod->idtech3, mc->minecraft, rust->''",
      (sm.game_engine("gmod"), sm.game_engine("cod"), sm.game_engine("mc"), sm.game_engine("rust"))
      == ("valve", "idtech3", "minecraft", ""))
check("moderation: cod is now queryable (via console); a game with neither engine nor gamedig is not",
      sm.is_player_queryable("cod") is True and sm.is_player_queryable("nosuchgame") is False)
check("moderation: console metacharacters are stripped from a name (no injection)",
      sm._mod_sanitize('a;b"c`d\ne') == "abcde")

# per-engine status/list parsers (sample output — I can't live-fire each engine)
_SRC = ('# userid name uniqueid connected ping loss state adr\n'
        '#  2 "Alice" STEAM_0:1:12345 15:30 45 0 active 5.6.7.8:27005\n'
        '#  5 "Bob ^S" [U:1:99] 02:11 67 0 active 9.9.9.9:27005\n'
        '#  7 "aBot" BOT 00:00 0 0 active\n')
check("parser(valve): names + steamids (legacy / modern / bot-empty)",
      [(p["name"], p["steamid"]) for p in sm._parse_valve_status(_SRC)]
      == [("Alice", "STEAM_0:1:12345"), ("Bob ^S", "[U:1:99]"), ("aBot", "")])
_COD = ('num score ping guid                             name            lastmsg address       qport rate\n'
        '--- ----- ---- -------------------------------- --------------- ------- ------------- ----- ----\n'
        '  0     5   45 1100001aaaaaaaaaaaaaaaaaaaaaaaaa ^1Alice^7             0 5.6.7.8:28960 12345 25000\n'
        '  1     0   67 1100001bbbbbbbbbbbbbbbbbbbbbbbbb Bob Smith            50 9.9.9.9:28961 54321 25000\n')
check("parser(idtech3): slot numbers + names (colours stripped, spaces kept)",
      [(p["num"], p["name"]) for p in sm._parse_idtech3_status(_COD)] == [(0, "Alice"), (1, "Bob Smith")])
_MC = "[12:34:56] [Server thread/INFO]: There are 2 of a max of 20 players online: Alice, Bob_1"
check("parser(minecraft): names from a prefixed log line",
      [p["name"] for p in sm._parse_minecraft_list(_MC)] == ["Alice", "Bob_1"])
check("parser(minecraft): empty server -> no players",
      sm._parse_minecraft_list("There are 0 of a max of 20 players online: ") == [])

# _gamedig_host: Source servers reply to A2S from the host's real IP, so a 127.0.0.1 query is
# silently dropped — the panel must query the host's primary IP. (run_command runs the awk pipeline
# remotely, so the stub returns what awk WOULD emit: just the IP, or nothing.)
class _FakeRemote:
    def __init__(self, rid): self.id = rid
_orig_rc = sm.run_command
try:
    sm._gamedig_host_cache.clear()
    sm.run_command = lambda *a, **k: ("45.76.63.211\n", "", 0)
    check("gamedig-host: uses the host's primary IP, not 127.0.0.1",
          sm._gamedig_host(_FakeRemote(9001)) == "45.76.63.211")
    sm._gamedig_host_cache.clear()
    sm.run_command = lambda *a, **k: ("", "", 0)          # no default route / no output
    check("gamedig-host: falls back to 127.0.0.1 when the IP can't be resolved",
          sm._gamedig_host(_FakeRemote(9002)) == "127.0.0.1")
    sm._gamedig_host_cache.clear()
    _calls = {"n": 0}
    def _counting_rc(*a, **k):
        _calls["n"] += 1
        return ("10.0.0.5\n", "", 0)
    sm.run_command = _counting_rc
    _r = _FakeRemote(9003)
    sm._gamedig_host(_r); sm._gamedig_host(_r)
    check("gamedig-host: caches per remote (one lookup, not one per query)", _calls["n"] == 1)
finally:
    sm.run_command = _orig_rc
    sm._gamedig_host_cache.clear()

# _tmux_live_socket_sh: LinuxGSM leaves a stale <selfname>-<random> socket behind on every restart,
# so the console targeting must pick the socket with a LIVE session (via has-session) rather than the
# first match — otherwise send-keys/capture-pane hit a dead socket and kick/ban/say/status all no-op.
_snip = sm._tmux_live_socket_sh("gmodserver")
check("tmux-socket: verifies a live session instead of grabbing the first socket",
      "has-session -t gmodserver" in _snip and "grep -m1" not in _snip)
check("tmux-socket: still signals NO_SESSION when nothing is live",
      "NO_SESSION" in _snip and "exit 3" in _snip)

# ensure_persistent_bans: a banid ban only survives a restart if the server config execs
# banned_user.cfg — this appends that (idempotently) to the resolved servercfg (${selfname}.cfg).
_orig_lgv2, _orig_rc3 = sm.lgsm_get_values, sm.run_command
try:
    sm.lgsm_get_values = lambda *a, **k: {"servercfg": "${selfname}.cfg"}
    _pb = {}
    sm.run_command = lambda server, cmd, timeout=15, sudo=False: (_pb.__setitem__("cmd", cmd), ("", "", 0))[1]
    _ok_pb = sm.ensure_persistent_bans(object(), "gmodserver2", "gmodserver")
    check("persistent-bans: targets the resolved servercfg, adds the exec, guards duplicates",
          _ok_pb is True and "*/cfg/gmodserver.cfg" in _pb["cmd"]
          and "exec banned_user.cfg" in _pb["cmd"] and "grep -qiE" in _pb["cmd"])
finally:
    sm.lgsm_get_values, sm.run_command = _orig_lgv2, _orig_rc3

# game_map: a separate cached gamedig read for the current map, kept out of the player-count path.
_orig_rc5 = sm.run_command
try:
    sm._game_map_cache.clear(); sm.run_command = lambda *a, **k: ("de_dust2\n", "", 0)
    check("game-map: parses the map name from gamedig", sm.game_map(object(), "u", "css", 27015) == "de_dust2")
    sm._game_map_cache.clear(); sm.run_command = lambda *a, **k: ("null\n", "", 0)
    check("game-map: 'null'/empty gamedig output -> ''", sm.game_map(object(), "u", "css", 27015) == "")
    sm._game_map_cache.clear(); sm.run_command = lambda *a, **k: ("<b>gm_x\n", "", 0)
    check("game-map: strips angle brackets from game-supplied text",
          "<" not in sm.game_map(object(), "u", "css", 27015) and ">" not in sm.game_map(object(), "u", "css", 27015))
    check("game-map: no gamedig type/port -> '' (no query)", sm.game_map(object(), "u", "css", None) == "")
finally:
    sm.run_command = _orig_rc5; sm._game_map_cache.clear()

# player_list: gamedig is PRIMARY (no console spam). The console is a backup used ONLY when the
# caller explicitly passes allow_console=True (a user action) — the automatic path (default) never
# touches the console: it returns None ('unknown') so the UI shows a GSLT hint instead of querying.
_orig_cpl, _orig_gpl = sm.console_player_list, sm._gamedig_player_list
try:
    sm.console_player_list = lambda *a, **k: [{"name": "Ace"}]
    sm._gamedig_player_list = lambda *a, **k: [{"name": "Zed", "steamid": "", "num": None,
                                                "score": None, "time": None}]
    check("player_list: gamedig is primary — the console isn't touched when gamedig answers",
          [p["name"] for p in sm.player_list(None, "u", "cod", 28960, None, "codserver")] == ["Zed"])
    sm._gamedig_player_list = lambda *a, **k: []   # gamedig says the server is empty
    check("player_list: a gamedig-confirmed empty server does NOT fall back to the console",
          sm.player_list(None, "u", "cod", 28960, None, "codserver") == [])
    sm._gamedig_player_list = lambda *a, **k: None  # gamedig couldn't query at all
    check("player_list: the automatic path is gamedig-only — no console, returns None when unread",
          sm.player_list(None, "u", "cod", 28960, None, "codserver") is None)
    check("player_list: the console backup runs ONLY when allow_console=True (an explicit action)",
          [p["name"] for p in sm.player_list(None, "u", "cod", 28960, None, "codserver",
                                             allow_console=True)] == ["Ace"])
finally:
    sm.console_player_list, sm._gamedig_player_list = _orig_cpl, _orig_gpl

# injection-safe command building, dispatched by engine
_msent = {}
_orig_scc = sm.send_console_command
_orig_cpl_m = sm.console_player_list
try:
    sm.send_console_command = lambda *a, **k: (_msent.__setitem__("cmd", a[2]), ("", "", 0))[1]
    sm.moderate(None, "u", "gmod", "kick", target='Bad;Guy"x')
    check("moderation: valve kick quotes the sanitized name (injection neutralised)",
          _msent.get("cmd") == 'kick "BadGuyx"')
    sm.moderate(None, "u", "gmod", "ban", steamid="STEAM_0:1:5; rcon x")
    check("moderation: valve ban bans + kicks the re-validated SteamID only (injection stripped)",
          _msent.get("cmd") == "banid 0 STEAM_0:1:5 kick; writeid")
    check("moderation: valve ban with no SteamID and no name is refused",
          sm.moderate(None, "u", "gmod", "ban", steamid="")[0] is False)
    sm.moderate(None, "u", "cod", "kick", num="3")
    check("moderation: idTech3 kick is clientkick <slot>", _msent.get("cmd") == "clientkick 3")
    sm.moderate(None, "u", "cod", "ban", num="3")
    check("moderation: idTech3 ban is banclient <slot>", _msent.get("cmd") == "banclient 3")
    check("moderation: idTech3 with a junk slot and no name is refused",
          sm.moderate(None, "u", "cod", "ban", num="3; quit")[0] is False)
    sm.moderate(None, "u", "mc", "ban", target="Steve")
    check("moderation: minecraft ban is a bare name command", _msent.get("cmd") == "ban Steve")
    check("moderation: a non-console game (rust) refuses moderation",
          sm.moderate(None, "u", "rust", "ban", target="x")[0] is False)
    # on-demand id resolution: a gamedig-sourced list carries no ids, so kick/ban looks the player
    # up on the console by name and uses the slot / SteamID it finds there.
    sm.console_player_list = lambda *a, **k: [{"name": "Ace", "num": 4, "steamid": "STEAM_0:1:9"}]
    _msent.clear()
    sm.moderate(None, "u", "cod", "kick", target="Ace")   # no num supplied
    check("moderation: idTech3 kick resolves the slot from the console when given only a name",
          _msent.get("cmd") == "clientkick 4")
    _msent.clear()
    sm.moderate(None, "u", "gmod", "ban", target="Ace")   # no steamid supplied
    check("moderation: valve ban resolves the SteamID from the console when given only a name",
          _msent.get("cmd") == "banid 0 STEAM_0:1:9 kick; writeid")
finally:
    sm.send_console_command = _orig_scc
    sm.console_player_list = _orig_cpl_m

# ── gamedig query type: per-server override wins over the built-in map, sanitized ──
check("query-type: an explicit override wins over the built-in map",
      sm._gamedig_type("gmod", "customtype") == "customtype")
check("query-type: unmapped game with no override -> '' (no gamedig type)",
      sm._gamedig_type("noquerygame", None) == "")
check("query-type: a mapped game with no override uses the map",
      sm._gamedig_type("gmod", None) == "garrysmod")
check("query-type: the override is sanitized to a gamedig-safe charset",
      sm._gamedig_type("cod", "co d;rm -rf") == "codrm-rf")
check("query-type: the Call of Duty family is mapped, so its player count (restart/backup) works",
      sm._gamedig_type("cod", None) == "cod" and sm._gamedig_type("cod4", None) == "cod4")
check("query-type: a game with neither engine nor map becomes queryable once an override is set",
      sm.is_player_queryable("nosuchgame", None) is False
      and sm.is_player_queryable("nosuchgame", "quake3") is True)

# ── change_ssh_port: input validation rejects bad ports BEFORE touching the host ──
check("ssh-port: non-numeric rejected", sm.change_ssh_port(None, "abc")[0] is False)
check("ssh-port: port 0 rejected", sm.change_ssh_port(None, 0)[0] is False)
check("ssh-port: port 70000 (out of range) rejected", sm.change_ssh_port(None, 70000)[0] is False)
check("ssh-port: negative port rejected", sm.change_ssh_port(None, -5)[0] is False)
check("ssh-port: invalid bind IP rejected", sm.change_ssh_port(None, 2222, "not-an-ip")[0] is False)
check("valid-ip: accepts IPv4", sm._valid_ip("192.168.1.5") is True)
check("valid-ip: accepts IPv6", sm._valid_ip("::1") is True)
check("valid-ip: rejects junk", sm._valid_ip("nope") is False)
check("valid-ip: rejects host:port form", sm._valid_ip("1.2.3.4:22") is False)

# ── db_maintenance: offline SQLite check / repair / optimize (updater + health card) ──
import db_maintenance as _dbm
import sqlite3 as _sq3
import tempfile as _tf
import shutil as _sh

_dbm_dir = _tf.mkdtemp(prefix="dbm-")


def _mk_db(p, rows=40):
    c = _sq3.connect(p)
    try:
        c.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        c.executemany("INSERT INTO t (v) VALUES (?)", [("x" * 80,) for _ in range(rows)])
        c.commit()
    finally:
        c.close()


def _garbage(p, n=9000):
    with open(p, "wb") as f:
        f.write(os.urandom(n))


try:
    _good = os.path.join(_dbm_dir, "good.db")
    _mk_db(_good)
    check("db-maint: a healthy DB passes integrity_check", _dbm.integrity_check(_good)[0] is True)
    check("db-maint: a missing DB counts as healthy (fresh install)",
          _dbm.integrity_check(os.path.join(_dbm_dir, "nope.db"))[0] is True)
    _garbage(os.path.join(_dbm_dir, "bad.db"))
    check("db-maint: a non-database file is flagged as unhealthy",
          _dbm.integrity_check(os.path.join(_dbm_dir, "bad.db"))[0] is False)
    check("db-maint: optimize a healthy DB succeeds", _dbm.optimize(_good)[0] is True)

    # repair a healthy DB → rebuilds it, and it stays healthy
    _rep_ok, _ = _dbm.repair(_good, None)
    check("db-maint: repair rebuilds a DB that verifies healthy",
          _rep_ok is True and _dbm.integrity_check(_good)[0] is True)

    # corrupt DB + healthy backup → restores the backup, keeps the corrupt copy aside
    _main = os.path.join(_dbm_dir, "main.db")
    _garbage(_main)
    _bkp = _main + ".backup"
    _mk_db(_bkp, rows=8)
    _r2_ok, _ = _dbm.repair(_main, _bkp)
    _aside = any(f.startswith("main.db.corrupt-") for f in os.listdir(_dbm_dir))
    check("db-maint: repair restores a healthy backup when a rebuild can't salvage",
          _r2_ok is True and _dbm.integrity_check(_main)[0] is True and _aside)

    # unsalvageable + no backup → fails safely, original never deleted
    _m2 = os.path.join(_dbm_dir, "m2.db")
    _garbage(_m2)
    _r3_ok, _ = _dbm.repair(_m2, os.path.join(_dbm_dir, "absent.backup"))
    check("db-maint: repair fails safely (keeps the original) when nothing is salvageable",
          _r3_ok is False and os.path.exists(_m2))
finally:
    _sh.rmtree(_dbm_dir, ignore_errors=True)

# ── granular moderation permissions + custom-command scope/argument safety ──
import re as _re
from types import SimpleNamespace as _NS
from auth import can_moderate_action, _custom_command_scope_matches
from models import CUSTOM_ARG_DEFAULT_PATTERN


class _FakeGroup:
    def __init__(self, perms):
        self._p = set(perms)

    def get_permissions(self):
        return self._p


def _u(perms=(), superadmin=False):
    return _NS(is_superadmin=superadmin, groups=[_FakeGroup(perms)])


# A mod granted ONLY kick can kick, but not ban or announce.
_kicker = _u(["kick_player"])
check("mod perm: kick_player -> can kick", can_moderate_action(_kicker, "kick"))
check("mod perm: kick_player -> can NOT ban", not can_moderate_action(_kicker, "ban"))
check("mod perm: kick_player -> can NOT say", not can_moderate_action(_kicker, "say"))
# The umbrella moderate_server (legacy groups) still grants all three.
_umb = _u(["moderate_server"])
check("mod perm: umbrella grants kick+ban+say",
      can_moderate_action(_umb, "kick") and can_moderate_action(_umb, "ban")
      and can_moderate_action(_umb, "say"))
# Full console access implies moderation; no perms implies none; superadmin gets all.
check("mod perm: send_command implies ban", can_moderate_action(_u(["send_command"]), "ban"))
check("mod perm: no perms -> cannot kick", not can_moderate_action(_u([]), "kick"))
check("mod perm: superadmin can do everything",
      can_moderate_action(_u(superadmin=True), "ban"))

# Custom-command scope matching (all / by engine / by game).
_cod2 = _NS(game_type="cod2")
_gmod = _NS(game_type="gmod")
check("cmd scope all -> matches any game",
      _custom_command_scope_matches(_NS(scope_type="all", scope_value=""), _cod2))
check("cmd scope game=cod2 -> matches cod2",
      _custom_command_scope_matches(_NS(scope_type="game", scope_value="cod2"), _cod2))
check("cmd scope game=cod2 -> does NOT match gmod",
      not _custom_command_scope_matches(_NS(scope_type="game", scope_value="cod2"), _gmod))
check("cmd scope engine=idtech3 -> matches cod2 (idTech3)",
      _custom_command_scope_matches(_NS(scope_type="engine", scope_value="idtech3"), _cod2))
check("cmd scope engine=idtech3 -> does NOT match gmod (valve)",
      not _custom_command_scope_matches(_NS(scope_type="engine", scope_value="idtech3"), _gmod))

# Argument charset: real map/entity names pass; anything that could break out of the console
# line (metacharacters, spaces, command substitution, empty) is rejected.
_arg_ok = lambda v: _re.fullmatch(CUSTOM_ARG_DEFAULT_PATTERN, v) is not None
check("custom arg: map name accepted", _arg_ok("mp_toujane"))
check("custom arg: dotted/dashed accepted", _arg_ok("de_dust2-v2.1"))
check("custom arg: rejects ; injection", not _arg_ok("a;rm -rf /"))
check("custom arg: rejects command substitution", not _arg_ok("$(reboot)"))
check("custom arg: rejects backtick", not _arg_ok("`id`"))
check("custom arg: rejects spaces", not _arg_ok("mp toujane"))
check("custom arg: rejects newline", not _arg_ok("a\nb"))
check("custom arg: rejects empty", not _arg_ok(""))

# ── panel branch-switch: git-ref name validation (fed to git + the root installer) ──
# _so is the `import system_ops as _so` from the integrity-tests section above.
check("branch: main valid", _so._valid_branch("main"))
check("branch: feature/x valid", _so._valid_branch("feature/moderation-permissions"))
check("branch: release/v1.2.3 valid", _so._valid_branch("release/v1.2.3"))
check("branch: rejects leading dash (option injection)", not _so._valid_branch("-oProxyCommand=x"))
check("branch: rejects traversal", not _so._valid_branch("a..b"))
check("branch: rejects space", not _so._valid_branch("a b"))
check("branch: rejects ; metachar", not _so._valid_branch("a;reboot"))
check("branch: rejects command substitution", not _so._valid_branch("$(id)"))
check("branch: rejects empty", not _so._valid_branch(""))

# ── cleanup: remove key/config files this run created ─────────
for p in (config.CRED_KEY_FILE, config.SECRET_FILE, config.CONFIG_FILE):
    if p not in _pre and os.path.exists(p):
        try:
            p.unlink()
        except OSError:
            pass

# ── Notifications: SSRF guards, provider validation, and event-key wiring ──
import pathlib as _pl   # noqa: E402
import re as _re        # noqa: E402

# Discord webhook is rebuilt onto a CONSTANT host from a validated id/token (no user-controlled host).
check("notify: valid discord webhook is accepted + kept on discord.com",
      N._discord_api_url("https://discord.com/api/webhooks/123456789012/AbC-dEf_ghIJKLmnop")
      == "https://discord.com/api/webhooks/123456789012/AbC-dEf_ghIJKLmnop")
check("notify: discordapp.com webhook is canonicalised to discord.com",
      N._discord_api_url("https://discordapp.com/api/webhooks/123456789012/tok_ABCdef")
      == "https://discord.com/api/webhooks/123456789012/tok_ABCdef")
check("notify: SSRF - an internal host is rejected",
      N._discord_api_url("https://169.254.169.254/api/webhooks/123456789012/x") is None)
check("notify: SSRF - a non-webhook discord path is rejected",
      N._discord_api_url("https://discord.com/evil") is None)
check("notify: SSRF - _post refuses a non-allow-listed host",
      N._post("https://evil.example.com/x", b"", {}) == (False, "blocked"))
check("notify: SSRF - _post refuses a non-https URL",
      N._post("http://api.telegram.org/botX/sendMessage", b"", {})[0] is False)
# Telegram token/chat validation short-circuits before any network call.
check("notify: telegram rejects a malformed bot token",
      N.send_telegram("not-a-real-token", "123456", "hi")[0] is False)
check("notify: telegram rejects an empty chat id",
      N.send_telegram("123456:AAABBBCCCDDDEEEFFF_gg-hh", "", "hi")[0] is False)
# EVENTS registry shape, and every notify() call in app.py uses a registered key (a typo'd key would
# silently never fire — like a data-action with no handler).
check("notify: EVENTS entries are (label:str, default:bool)",
      all(isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], bool)
          for v in N.EVENTS.values()))
_app_src = (_pl.Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
_used_keys = set(_re.findall(r'notifications\.notify\(\s*"(\w+)"', _app_src))
check("notify: every notify() key in app.py is registered in EVENTS",
      _used_keys and _used_keys <= set(N.EVENTS), "unregistered: %s" % sorted(_used_keys - set(N.EVENTS)))

# The global 'enabled' master switch was removed (a channel's own toggle is the on/off). The one-time
# migration must PRESERVE a previously-muted state: master off -> disable both channels, then drop the
# key — otherwise removing the gate would silently start sending to still-enabled channels.
_m_off = {"enabled": False, "telegram": {"enabled": True}, "discord": {"enabled": True}}
check("master-switch drop: was off -> both channels disabled + key removed",
      N._drop_master_switch(_m_off) is True and "enabled" not in _m_off
      and _m_off["telegram"]["enabled"] is False and _m_off["discord"]["enabled"] is False)
_m_on = {"enabled": True, "telegram": {"enabled": True}, "discord": {"enabled": False}}
check("master-switch drop: was on -> channels untouched, key removed",
      N._drop_master_switch(_m_on) is True and "enabled" not in _m_on
      and _m_on["telegram"]["enabled"] is True and _m_on["discord"]["enabled"] is False)
_m_none = {"telegram": {"enabled": True}}
check("master-switch drop: already migrated (no key) -> no change",
      N._drop_master_switch(_m_none) is False and _m_none == {"telegram": {"enabled": True}})

# Alert thresholds: disk %/mem % are real percents (<=99); CPU 'load' is a per-core loadavg % that can
# exceed 100; load_mins is the sustained window. Each is clamped to its own range with defaults.
_orig_thr_cfg = N._cfg
try:
    N._cfg = lambda: {}
    check("thresholds: sensible defaults when unset",
          N.get_thresholds() == {"disk_pct": 90, "load_pct": 200, "mem_pct": 90, "load_mins": 5})
    N._cfg = lambda: {"thresholds": {"disk_pct": 250, "mem_pct": 250, "load_pct": 250, "load_mins": 999}}
    _thi = N.get_thresholds()
    check("thresholds: disk % and mem % are capped at 99 (real percentages)",
          _thi["disk_pct"] == 99 and _thi["mem_pct"] == 99)
    check("thresholds: CPU load may exceed 100% (loadavg-based, ceiling 800)", _thi["load_pct"] == 250)
    check("thresholds: the sustained-minutes window is capped at 120", _thi["load_mins"] == 120)
    N._cfg = lambda: {"thresholds": {"load_pct": 5, "load_mins": 0}}
    _thlo = N.get_thresholds()
    check("thresholds: values below the floor clamp up (load>=50, mins>=1)",
          _thlo["load_pct"] == 50 and _thlo["load_mins"] == 1)
finally:
    N._cfg = _orig_thr_cfg
# The monitor's sustained window maps minutes -> consecutive passes at the 60s monitor cadence.
import app as _app_thr  # noqa: E402
check("thresholds: 60s monitor cadence means load_mins == required consecutive passes",
      _app_thr._MONITOR_SECONDS == 60 and max(1, round(10 * 60 / _app_thr._MONITOR_SECONDS)) == 10)

# ── Login-security whitelist + auto-block threshold ──
import ipaddress as _ipaddr  # noqa: E402

check("whitelist: a bare IP is accepted + canonicalised", _valid_ip_or_cidr("  1.2.3.4 ") == "1.2.3.4")
check("whitelist: a CIDR is accepted + canonicalised to its network", _valid_ip_or_cidr("10.0.0.5/24") == "10.0.0.0/24")
check("whitelist: junk / empty is rejected", _valid_ip_or_cidr("not-an-ip") is None and _valid_ip_or_cidr("") is None)
check("whitelist: an out-of-range octet is rejected", _valid_ip_or_cidr("999.1.1.1") is None)
_wl_nets = [_ipaddr.ip_network("10.0.0.0/8"), _ipaddr.ip_network("203.0.113.7")]
check("whitelist: a CIDR entry covers an address inside it", _whitelisted("10.1.2.3", _wl_nets) is True)
check("whitelist: an exact-IP entry matches that IP", _whitelisted("203.0.113.7", _wl_nets) is True)
check("whitelist: an address outside every entry does not match", _whitelisted("8.8.8.8", _wl_nets) is False)
check("whitelist: a non-IP string never matches", _whitelisted("garbage", _wl_nets) is False)

# The fail2ban ignoreip line is built ONLY from entries that re-parse as an IP/CIDR — defence-in-depth
# so no attacker-influenced token can ever be written into the root-owned jail file.
_ign = SO._f2b_ignoreip_line(["1.2.3.4", "10.0.0.0/8", "evil; rm -rf /", "$(whoami)", "not-an-ip"])
check("f2b: ignoreip always includes localhost", "127.0.0.1/8" in _ign and "::1" in _ign)
check("f2b: ignoreip keeps the valid IP + CIDR entries", "1.2.3.4" in _ign and "10.0.0.0/8" in _ign)
check("f2b: ignoreip drops every non-IP token (no shell metachars reach the jail file)",
      not any(bad in _ign for bad in (";", "$", "rm", "whoami", "not-an-ip")))
_jail = SO._panel_f2b_jail_body("/data/auth.log", 5000, ["1.2.3.4", "junk"])
check("f2b: the jail body carries an ignoreip line with the valid entry only",
      "\nignoreip = " in _jail and "1.2.3.4" in _jail and "junk" not in _jail)

# top-offenders parsing: the counting pipeline emits "<attempts>\t<bans>\t<ip>\t<jail,jail>"; each row
# must surface which fail2ban jail(s) caught the IP. Old 3-field lines (no jail) parse with jails=[].
_top = SO._parse_top_ips("9\t3\t1.2.3.4\tsshd,recidive\n5\t0\t5.6.7.8\tpanel-login\n2\t0\t9.9.9.9",
                         banned_now={"1.2.3.4"}, blocked={"5.6.7.8": "panel-block"})
check("f2b top: attempts/bans/ip parse in order",
      [(r["ip"], r["attempts"], r["bans"]) for r in _top]
      == [("1.2.3.4", 9, 3), ("5.6.7.8", 5, 0), ("9.9.9.9", 2, 0)])
check("f2b top: the jail column surfaces every jail that caught the IP",
      _top[0]["jails"] == ["sshd", "recidive"] and _top[1]["jails"] == ["panel-login"])
check("f2b top: a legacy 3-field line (no jail) parses with an empty jail list",
      _top[2]["jails"] == [])
check("f2b top: banned_now / blocked flags still track the passed-in sets",
      _top[0]["banned_now"] is True and _top[1]["blocked"] is True and _top[2]["blocked"] is False)

# Telegram command parsing: normalise '/Cmd@Bot arg' to a bare lowercase verb; non-commands -> ''.
check("telegram: /update parses to 'update'", _parse_tg_command("/update") == "update")
check("telegram: a bot-mention + args is stripped", _parse_tg_command("/Update@MyBot now") == "update")
check("telegram: /STATUS is lowercased", _parse_tg_command("/STATUS") == "status")
check("telegram: a non-command is empty", _parse_tg_command("hello there") == "" and _parse_tg_command("") == "")
check("telegram: /restart <name> extracts the argument", _tg_command_arg("/restart my server") == "my server")
check("telegram: a bare command has no argument", _tg_command_arg("/status") == "")

# telegram_set_commands registers the '/' autocomplete menu via setMyCommands (through _post).
import json as _json_tg  # noqa: E402
_tg_posts = []
_orig_post = N._post
try:
    N._post = lambda url, data, headers: (_tg_posts.append((url, data)), (True, "sent"))[1]
    check("telegram: set_commands posts to setMyCommands with the registered command set",
          N.telegram_set_commands("123456:AAABBBCCCDDDEEEFFF_gg-hh")
          and _tg_posts[-1][0].endswith("/setMyCommands")
          and {c["command"] for c in _json_tg.loads(_tg_posts[-1][1].decode())["commands"]}
          == {c for c, _ in N.TG_COMMANDS})
    N.telegram_set_commands("123456:AAABBBCCCDDDEEEFFF_gg-hh", clear=True)
    check("telegram: set_commands(clear=True) sends an empty command list",
          _json_tg.loads(_tg_posts[-1][1].decode())["commands"] == [])
    check("telegram: set_commands rejects a malformed token", N.telegram_set_commands("nope") is False)
finally:
    N._post = _orig_post

# ── Discord command bot (Gateway): parsing, SSRF-safe reply path, and the message pump ──
from app import _parse_dc_command  # noqa: E402

# Command parsing accepts either '!' (types cleanly — Discord reserves '/') or '/'; mention + args stripped.
check("discord: !status parses to 'status'", _parse_dc_command("!status") == "status")
check("discord: a '/' prefix also parses", _parse_dc_command("/restart foo") == "restart")
check("discord: a bot-mention + args is stripped + lowercased", _parse_dc_command("!Restart@bot Now") == "restart")
check("discord: a non-command / bare prefix is empty",
      _parse_dc_command("hello") == "" and _parse_dc_command("! ") == "" and _parse_dc_command("") == "")

# The bot reply URL is rebuilt onto the CONSTANT discord.com host with a digits-only channel id, and the
# same _ALLOWED_PREFIXES barrier that guards the webhook sender now also covers the /channels/ API.
check("discord: bot message URL is built on the constant host from a snowflake channel id",
      N._discord_bot_message_url("112233445566778899")
      == "https://discord.com/api/v10/channels/112233445566778899/messages")
check("discord: SSRF - a non-numeric / traversal channel id is rejected",
      N._discord_bot_message_url("../evil") is None and N._discord_bot_message_url("") is None)
check("discord: SSRF - the bot channels URL sits on an allow-listed prefix",
      "https://discord.com/api/v10/channels/1/messages".startswith(N._ALLOWED_PREFIXES))
check("discord: SSRF - a discord.com look-alike host is not allow-listed",
      not "https://discord.com.evil.example/api/x".startswith(N._ALLOWED_PREFIXES))

# The bot token only ever rides in an Authorization header — the charset forbids whitespace/newlines so
# it can't inject one, and it's loose on the internal '.'-separated shape so future formats still pass.
# A dotted, real-shaped fixture that is deliberately NOT a valid Discord token layout (lowercase, wrong
# segment lengths) so GitHub push-protection doesn't flag it — it only needs to exercise the charset.
check("discord: a plausible bot token validates",
      N._valid_discord_bot_token("panel.fixture.not_a_real_token_" + "a" * 30))
check("discord: a bot token with a space is rejected", not N._valid_discord_bot_token("has a space " + "x" * 40))
check("discord: a bot token with a newline (header injection) is rejected",
      not N._valid_discord_bot_token("tok\nX-Evil: 1 " + "x" * 40))

# discord_bot_send validates BEFORE any network call, and posts to the constant host with a Bot header.
_dc_posts = []
_orig_post2 = N._post
try:
    N._post = lambda url, data, headers: (_dc_posts.append((url, headers)), (True, "sent"))[1]
    _ok_send, _ = N.discord_bot_send("A" * 50, "112233445566778899", "hi")
    check("discord: a bot reply posts to the constant discord.com channels API",
          _ok_send and _dc_posts[-1][0] == "https://discord.com/api/v10/channels/112233445566778899/messages")
    check("discord: a bot reply carries an 'Authorization: Bot' header",
          _dc_posts[-1][1].get("Authorization", "").startswith("Bot "))
    check("discord: bot send rejects a malformed channel id without a network call",
          N.discord_bot_send("A" * 50, "../evil", "hi")[0] is False)
    check("discord: bot send rejects a malformed token without a network call",
          N.discord_bot_send("bad token", "112233445566778899", "hi")[0] is False)
finally:
    N._post = _orig_post2


# The Gateway pump: HELLO -> IDENTIFY (with the message-content intent) -> deliver MESSAGE_CREATE to the
# handler -> return on EOF. A fake socket stands in for the WebSocket so no network is touched.
class _FakeWS:
    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []
    def recv(self):
        return self._frames.pop(0) if self._frames else ""   # "" == EOF -> the loop breaks
    def send(self, s):
        self.sent.append(s)
    def close(self):
        pass


_dc_seen = []
_fake_ws = _FakeWS([
    '{"op":10,"d":{"heartbeat_interval":600000}}',
    '{"op":0,"s":1,"t":"MESSAGE_CREATE","d":{"channel_id":"999","author":{"bot":false},"content":"!status"}}',
])
N.discord_gateway_run("A" * 50, lambda ch, is_bot, content, author=None: _dc_seen.append((ch, is_bot, content)),
                      _connect=lambda: _fake_ws)
check("discord: the gateway IDENTIFYs with the message-content intent",
      any('"op": 2' in s and str(N._DISCORD_INTENTS) in s for s in _fake_ws.sent))
check("discord: a MESSAGE_CREATE is delivered to the handler with (channel, is_bot, content)",
      _dc_seen == [("999", False, "!status")])
check("discord: the message-content intent bit (1<<15) is set", N._DISCORD_INTENTS & (1 << 15))

# player_slots parses gamedig's compact JSON into (count, max, name); a name with spaces/quotes
# round-trips and junk output is rejected. run_command is stubbed so no SSH/gamedig is needed.
_orig_rc = sm.run_command
try:
    sm.run_command = lambda *a, **k: ('{"c":7,"m":24,"n":"[EU] Bob\'s \\"Fun\\" Server","ok":true}', "", 0)
    check("player_slots: parses count/max/name from gamedig JSON",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo")
          == (7, 24, "[EU] Bob's \"Fun\" Server"))
    sm.run_command = lambda *a, **k: ('{"c":0,"m":null,"n":"","ok":true}', "", 0)
    check("player_slots: null max + empty name -> (0, None, None)",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (0, None, None))
    # A gamedig FAILURE ({"error":...} -> ok=false) is 'unknown', NOT 0 players, so the caller can
    # fall back to the console instead of showing a bogus 0.
    sm.run_command = lambda *a, **k: ('{"c":0,"m":null,"n":"","ok":false}', "", 0)
    check("player_slots: a failed query (ok=false) -> (None, None, None), not a fake 0",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (None, None, None))
    sm.run_command = lambda *a, **k: ("not json", "", 0)
    check("player_slots: junk output -> (None, None, None)",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (None, None, None))
finally:
    sm.run_command = _orig_rc

# Global ban: console_steamid_ban builds the right native ban/unban command from a VALIDATED SteamID,
# and refuses junk before anything reaches the console (send_console_command is stubbed to record it).
_gb_cmds = []
_orig_scc = sm.send_console_command
try:
    sm.send_console_command = lambda server, user, command, timeout=20, selfname=None: (_gb_cmds.append(command), ("", "", 0))[1]
    _ok, _reason = sm.console_steamid_ban(object(), "u", "csgoserver", "STEAM_0:1:5")
    check("global-ban: ban builds 'banid 0 <id> kick; writeid'",
          _ok and _gb_cmds[-1] == "banid 0 STEAM_0:1:5 kick; writeid")
    sm.console_steamid_ban(object(), "u", "csgoserver", "[U:1:11]", unban=True)
    check("global-ban: unban builds 'removeid <id>; writeid'", _gb_cmds[-1] == "removeid [U:1:11]; writeid")
    check("global-ban: an invalid SteamID is rejected before the console",
          sm.console_steamid_ban(object(), "u", "s", "garbage; rm -rf") == (False, "invalid"))
finally:
    sm.send_console_command = _orig_scc

# The REMOTE ignoreip drop-in (pushed to remotes over SSH) is built from the same validated entries.
_dropin = sm._f2b_dropin_ignoreip_body(["9.9.9.9", "10.0.0.0/8", "bad; rm -rf /"])
check("remote-f2b: drop-in is a [DEFAULT] ignoreip block including localhost",
      "[DEFAULT]" in _dropin and "ignoreip = " in _dropin and "127.0.0.1/8" in _dropin)
check("remote-f2b: drop-in keeps the valid IP + CIDR entries", "9.9.9.9" in _dropin and "10.0.0.0/8" in _dropin)
check("remote-f2b: drop-in drops non-IP tokens (no shell metachars in the file)",
      not any(bad in _dropin for bad in (";", "$", "rm", "bad")))

# ── The maintenance probe that keeps a scheduled LinuxGSM update from reading as a crash. The
# monitor tests stub this function out wholesale, so the shell command it builds — the one place a
# real bug can hide — is only ever asserted here.
# Patch the module the function actually RESOLVES run_command from. _lgsm_maintenance_running
# used to live in app.py, so patching app.run_command intercepted it; it lives in monitoring now
# and looks the name up in monitoring's namespace, so patching app's would silently no-op and the
# stub would never be called. (That is exactly how this test failed during the move.)
import monitoring as _mapp
from monitoring import _lgsm_maintenance_running as _lmr

_sent = []


def _fake_run(remote, cmd, timeout=None):
    _sent.append(cmd)
    return ("BUSY\n", "", 0)


_GS = lambda **kw: NS(**dict(dict(short_name="gmodserver", game_type="gmod", name="Gmod",
                                  lgsm_name="gmodserver"), **kw))
_orig_rc = _mapp.run_command
try:
    _mapp.run_command = _fake_run
    check("maintenance probe: a running force-update reads as busy", _lmr(object(), _GS()) is True)
    _cmd = _sent[-1]
    check("maintenance probe: pgrep is scoped to that server's OWN unix user",
          "pgrep -u gmodserver " in _cmd or "pgrep -u 'gmodserver' " in _cmd, _cmd)
    check("maintenance probe: it matches the lgsm script name followed by a maintenance command",
          "gmodserver (update|force-update|" in _cmd, _cmd)
    check("maintenance probe: monitor is NOT a maintenance command (it would mute every alert)",
          "|monitor" not in _cmd and "(monitor" not in _cmd, _cmd)
    check("maintenance probe: update-lgsm is NOT one either — it never stops the server",
          "update-lgsm" not in _cmd, _cmd)

    _mapp.run_command = lambda remote, cmd, timeout=None: ("IDLE\n", "", 0)
    check("maintenance probe: nothing running reads as idle", _lmr(object(), _GS()) is False)

    # The command text itself contains the word BUSY, so a substring test would latch on forever.
    _mapp.run_command = lambda remote, cmd, timeout=None: ("echo BUSYIDLE\nIDLE\n", "", 0)
    check("maintenance probe: an echoed command line is not mistaken for a busy answer",
          _lmr(object(), _GS()) is False)

    def _boom(remote, cmd, timeout=None):
        raise OSError("host unreachable")

    _mapp.run_command = _boom
    check("maintenance probe: a probe that cannot answer must NOT hide a real outage",
          _lmr(object(), _GS()) is False)

    _mapp.run_command = _fake_run
    check("maintenance probe: no unix user -> no probe at all",
          _lmr(object(), _GS(short_name="")) is False)
    check("maintenance probe: no game type -> no probe (a bare 'server' pattern would over-match)",
          _lmr(object(), _GS(game_type="", lgsm_name="server")) is False)
    _sent.clear()
    _lmr(object(), _GS(short_name="", game_type=""))
    check("maintenance probe: the guards short-circuit before any SSH round trip", not _sent)

    # short_name/game_type are pinned to [A-Za-z0-9._-]; "." is the one ERE metacharacter that fits.
    _sent.clear()
    _lmr(object(), _GS(game_type="cs.source", lgsm_name="cs.sourceserver"))
    check("maintenance probe: a dot in the name is matched literally, not as 'any character'",
          "cs[.]sourceserver" in _sent[-1], _sent[-1])
finally:
    _mapp.run_command = _orig_rc

# ── API tokens: only a HASH is ever stored ────────────────────────────────────────────────────
# Bearer tokens authenticate scripts as their owner and inherit that user's full RBAC, and app.py
# exempts Bearer requests from CSRF — yet nothing exercised any of it. These are the pure half; the
# lookup half (a disabled owner, a replayed hash) is asserted against the real DB in smoke_test.
import hashlib as _hl
from models import User as _U, RemoteServer as _RS

_tu = _U(username="tok", password_hash="x")
_plain = _tu.generate_api_token()
check("api token: the minted token is handed back in plaintext, once",
      isinstance(_plain, str) and _plain.startswith("lgsm_") and len(_plain) >= 32, _plain[:12])
check("api token: the plaintext is NOT what gets stored", _tu.api_token != _plain)
check("api token: what IS stored is its sha256 — a leaked DB yields no usable token",
      _tu.api_token == _hl.sha256(_plain.encode()).hexdigest())
_plain2 = _tu.generate_api_token()
check("api token: minting again replaces the old one", _plain2 != _plain and
      _tu.api_token == _hl.sha256(_plain2.encode()).hexdigest())
check("api token: has_api_token reports the stored state", _tu.has_api_token is True)
_tu.revoke_api_token()
check("api token: revoking clears it", _tu.api_token is None and _tu.has_api_token is False)

# ── Pinned SSH host key: the fingerprint an operator eyeballs before trusting a host ───────────
import base64 as _b64
_blob = b"\x00\x00\x00\x07ssh-rsa" + bytes(range(256)) * 2
_key = "ssh-rsa " + _b64.b64encode(_blob).decode()
_want = "ssh-rsa SHA256:" + _b64.b64encode(_hl.sha256(_blob).digest()).decode().rstrip("=")
eq("host key: the fingerprint is sha256 of the DECODED key, in OpenSSH form",
   _RS(host_key=_key).host_key_fingerprint, _want)
check("host key: it is the base64 digest, not hex, and unpadded",
      ":" in _want and "=" not in _want.split(":")[1] and len(_want.split(":")[1]) == 43, _want)
eq("host key: nothing pinned yet reads as empty, not as an error",
   _RS(host_key="").host_key_fingerprint, "")
for _bad in ("not base64 !!!", "ssh-rsa", "ssh-rsa ***", "\x00\xff"):
    eq("host key: malformed pin %r degrades to empty rather than raising" % _bad[:14],
       _RS(host_key=_bad).host_key_fingerprint, "")

# ── File manager: the protected-path guard on `rm -rf` ────────────────────────────────────────
# delete_path deletes the RESOLVED absolute path, so the guard has to judge the resolved path too.
# It used to read the raw string: "./lgsm" and "x/../serverfiles" looked like ordinary sub-paths
# while resolving onto the LinuxGSM control tree and the entire game install.
_SELF = "csgoserver"
for _p in ("lgsm", "lgsm/data", "/lgsm", "lgsm/", "serverfiles", "linuxgsm.sh", _SELF,
           ".ssh", ".bashrc", "", "/", ".", "..", "../..", "a/../.."):
    check("file guard: %r is protected from deletion" % _p,
          sm._is_protected_path(_p, _SELF) is True)
# The bypasses. Each of these resolves onto something whose loss is unrecoverable.
for _p, _what in (("./lgsm", "the LinuxGSM control tree"),
                  (".//lgsm", "the LinuxGSM control tree"),
                  ("./serverfiles", "the game install"),
                  ("x/../serverfiles", "the game install"),
                  ("a/b/../../.ssh", "the host's SSH keys"),
                  ("./linuxgsm.sh", "the LinuxGSM launcher"),
                  ("./%s" % _SELF, "the server's own script")):
    check("file guard: %r cannot sneak past and take %s" % (_p, _what),
          sm._is_protected_path(_p, _SELF) is True)
# ...and ordinary content is still deletable, or the file manager is useless.
for _p in ("addons/mymap.bsp", "./addons/mymap.bsp", "cfg/server.cfg", "logs", "lgsm2",
           "serverfiles-old", "my lgsm notes.txt"):
    check("file guard: ordinary path %r stays deletable" % _p,
          sm._is_protected_path(_p, _SELF) is False)

# End-to-end through delete_path itself: the guard is worth nothing if the caller skips it, so
# assert no shell command is issued at all for a protected path.
_sent_rm = []
_orig_rc2 = sm.run_command
try:
    sm.run_command = lambda server, cmd, timeout=30, sudo=None: (_sent_rm.append(cmd), ("__OK__", "", 0))[1]
    _ok, _msg = sm.delete_path(object(), _SELF, "./lgsm", selfname=_SELF)
    check("file guard: delete_path refuses './lgsm' and runs NOTHING",
          _ok is False and not _sent_rm, "ran: %s" % _sent_rm[:1])
    check("file guard: the refusal explains itself", "protected" in (_msg or "").lower(), _msg)
    _sent_rm.clear()
    _ok2, _ = sm.delete_path(object(), _SELF, "x/../serverfiles", selfname=_SELF)
    check("file guard: delete_path refuses a traversal onto serverfiles",
          _ok2 is False and not _sent_rm, "ran: %s" % _sent_rm[:1])
    _sent_rm.clear()
    _ok3, _ = sm.delete_path(object(), _SELF, "addons/junk.txt", selfname=_SELF)
    check("file guard: a real file still gets deleted, at its resolved path",
          _ok3 is True and len(_sent_rm) == 1
          and "/home/%s/addons/junk.txt" % _SELF in _sent_rm[0], "ran: %s" % _sent_rm[:1])
finally:
    sm.run_command = _orig_rc2

# ── The renderer's one guarantee: no control byte reaches the page ────────────────────────────
# Console text carries player names and chat, so these bytes are AUTHORED, not just accidental.
# A sequence that never completes matched none of the three grammars and used to survive.
import terminal as _term
for _src in ("player \x1b", "chat: \x1b\t hi", "x\x1b\x00y", "\x1b[38;5;", "\x1b\x9b"):
    check("terminal: an incomplete escape %r leaves no ESC behind" % _src,
          "\x1b" not in _term.render(_src), repr(_term.render(_src)))
for _src, _want in (("\x1b[32mgreen\x1b[0m", "green"), ("a\x1b[Kb", "ab"), ("x\x1b>y", "xy"),
                    ("\x1b]0;title\x07hi", "hi"), ("ssa\b\b\bsay hi", "say hi"),
                    ("abcdef\rXY", "XYcdef"), ("done\r\nnext", "done\nnext")):
    eq("terminal: %r still renders as a terminal would" % _src, _term.render(_src), _want)

# ── File manager: the path resolver every read/write/upload/browse goes through ────────────────
# _is_protected_path stops you deleting the game install; _safe_abspath is the one that stops you
# leaving the game user's home at all, and it guards four more operations than delete does.
_HOME = "/home/csgoserver"
for _p in ("../etc/passwd", "..", "a/../../etc", "../../root/.ssh/id_rsa", "../csgoserver2/secrets",
           "cfg/../../../etc/shadow"):
    eq("path resolver: %r cannot escape the home dir" % _p,
       sm._safe_abspath("csgoserver", _p), None)
# A leading slash is treated as home-relative, not as the filesystem root: "/etc/passwd" must land
# inside the home, never at the real /etc/passwd.
eq("path resolver: an absolute-looking path is clamped into the home dir",
   sm._safe_abspath("csgoserver", "/etc/passwd"), _HOME + "/etc/passwd")
for _p, _want in (("cfg/server.cfg", _HOME + "/cfg/server.cfg"),
                  ("./cfg/server.cfg", _HOME + "/cfg/server.cfg"),
                  ("a//b", _HOME + "/a/b"),
                  ("cfg/./x/../y", _HOME + "/cfg/y"),
                  ("", _HOME)):
    eq("path resolver: %r resolves under the home dir" % _p, sm._safe_abspath("csgoserver", _p), _want)
# Non-str input must not crash the file manager.
for _junk in (None, 0, 12, [], {}):
    _r = sm._safe_abspath("csgoserver", _junk)
    check("path resolver: %r is handled, not raised on" % (_junk,),
          _r is None or _r.startswith(_HOME), repr(_r))

# ── Never echo an exception's text to the browser ─────────────────────────────────────────────
# models.py states the rule ("returning str(exc) to a client is how raw internals leak into API
# responses (CodeQL py/stack-trace-exposure), and this codebase's rule is never to do it"), and
# three flash() calls were doing exactly that. The audit log is where the detail belongs.
import re as _re_fl
_app_src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py"),
                encoding="utf-8").read()
_leaky = []
for _m in _re_fl.finditer(r"flash\(\s*f?[\"'][^\"']*\{\s*(e|exc|err|ex)\b[^}]*\}", _app_src):
    _leaky.append("app.py:%d" % (_app_src[:_m.start()].count("\n") + 1))
check("no route flashes an exception's text to the browser (py/stack-trace-exposure)",
      not _leaky, ", ".join(_leaky))

# ── Alert delivery: Discord ────────────────────────────────────────────────────────────────────
# send_discord had never been executed by a test. It is the path a "server went offline" alert
# takes, and a broken one fails the same way as no alert at all — silence. The SSRF barrier around
# it matters too: the URL is rebuilt onto a constant host from regex-captured id/token, so no
# admin-supplied string can steer the request. Both properties are asserted here with the socket
# layer replaced, so nothing leaves the machine.
_sent = []


def _fake_post(url, data, headers):
    _sent.append((url, json.loads(data.decode()), headers))
    return True, "sent"


_sv_post = N._post
try:
    N._post = _fake_post
    _WH = "https://discord.com/api/webhooks/12345/TESTONLY-not-a-real-webhook"
    _ok, _detail = N.send_discord(_WH, "codserver went offline unexpectedly.")
    check("discord: a valid webhook sends", _ok is True and _detail == "", repr(_detail))
    _url, _body, _hdr = _sent[-1]
    check("discord: the request goes to discord.com and nowhere else",
          _url.startswith("https://discord.com/api/webhooks/"), _url)
    check("discord: the message is the payload's content", _body.get("content", "").startswith("codserver went offline"))
    check("discord: it is sent as JSON", _hdr.get("Content-Type") == "application/json")

    # 1900 chars: Discord rejects over 2000, and a rejected alert is a missed alert.
    _sent.clear()
    N.send_discord(_WH, "x" * 5000)
    check("discord: an over-long message is truncated rather than rejected",
          len(_sent[-1][1]["content"]) == 1900, len(_sent[-1][1]["content"]))

    # Anything that is not a real discord webhook must not even reach _post.
    for _bad in ("https://evil.example/api/webhooks/1/x", "http://discord.com/api/webhooks/1/x",
                 "https://discord.com.evil.example/api/webhooks/1/x", "not a url", "", None,
                 "https://discord.com/api/webhooks/abc/xyz"):
        _sent.clear()
        _ok2, _d2 = N.send_discord(_bad, "hi")
        check("discord: %r is refused before any request" % (str(_bad)[:34],),
              _ok2 is False and not _sent, "sent=%s detail=%r" % (len(_sent), _d2))

    # The failure reasons must be distinguishable — "can't reach Discord" and "Discord said no" are
    # different problems for whoever is debugging why an alert never arrived.
    N._post = lambda u, d, h: (False, "unreachable")
    _ok3, _d3 = N.send_discord(_WH, "hi")
    check("discord: an unreachable host says so", _ok3 is False and "couldn't reach" in _d3, _d3)
    N._post = lambda u, d, h: (False, "rejected")
    _ok4, _d4 = N.send_discord(_WH, "hi")
    check("discord: a rejected webhook says so instead", _ok4 is False and "rejected it" in _d4, _d4)
finally:
    N._post = _sv_post

# The SSRF barrier itself: _post refuses anything outside the provider allow-list, before opening
# a socket. Passing a non-allow-listed URL must return 'blocked', not attempt a connection.
_blocked_ok, _blocked_reason = N._post("https://169.254.169.254/latest/meta-data/", b"{}", {})
check("alerts: _post blocks a URL outside the provider allow-list (SSRF barrier)",
      _blocked_ok is False and _blocked_reason == "blocked", _blocked_reason)

# ── Saving notification settings must not destroy the secrets ─────────────────────────────────
# The settings form never round-trips a real token back to the server — it posts None to mean
# "leave it alone". If save_settings took that literally it would wipe the bot token every time
# anyone touched an unrelated checkbox, and alerts would stop with nothing on screen to say why.
# update_config is stubbed throughout, so the real data/config.json is never written.
_saved_cfg = {}
_sv_cfgfn, _sv_update = N._cfg, N.update_config
try:
    N.update_config = lambda fn: fn(_saved_cfg)
    _existing_tok = N.encrypt_secret("12345:TESTONLYnotarealtoken00")
    _existing_wh = N.encrypt_secret("https://discord.com/api/webhooks/1/x")
    N._cfg = lambda: {"telegram": {"token": _existing_tok, "chat_id": "42"},
                      "discord": {"webhook": _existing_wh}}
    N.save_settings(telegram={"enabled": True, "chat_id": "42", "token": None},
                    discord={"enabled": True, "webhook": None}, events={})
    _n = _saved_cfg["notifications"]
    check("notify save: a None token KEEPS the stored one (the form never sends it back)",
          _n["telegram"]["token"] == _existing_tok)
    check("notify save: a None webhook keeps the stored one too",
          _n["discord"]["webhook"] == _existing_wh)

    _saved_cfg.clear()
    N.save_settings(telegram={"enabled": True, "chat_id": "42", "token": "67890:TESTONLYreplacementvalue"},
                    discord={"enabled": False, "webhook": ""}, events={})
    _n = _saved_cfg["notifications"]
    check("notify save: a new token replaces it", _n["telegram"]["token"] != _existing_tok)
    check("notify save: and is stored ENCRYPTED, not in the clear",
          "67890:TESTONLYreplacementvalue" not in _n["telegram"]["token"]
          and N.decrypt_secret(_n["telegram"]["token"]) == "67890:TESTONLYreplacementvalue")

    # Thresholds are clamped, and junk must not overwrite a good value.
    _saved_cfg.clear()
    _k = sorted(N._DEFAULT_THRESHOLDS)[0]
    _lo, _hi = N._THRESHOLD_BOUNDS[_k]
    N.save_settings(telegram={}, discord={}, events={}, thresholds={_k: _hi + 10_000})
    check("notify save: an out-of-range threshold is clamped to its bound",
          _saved_cfg["notifications"]["thresholds"][_k] == _hi,
          "%s -> %s" % (_k, _saved_cfg["notifications"]["thresholds"][_k]))
    _saved_cfg.clear()
    N.save_settings(telegram={}, discord={}, events={}, thresholds={_k: "not a number"})
    check("notify save: junk in a threshold is ignored, not written",
          isinstance(_saved_cfg["notifications"]["thresholds"][_k], int))
finally:
    N._cfg, N.update_config = _sv_cfgfn, _sv_update

# ── The Telegram poller ────────────────────────────────────────────────────────────────────────
check("telegram poll: a malformed token returns None without building a URL",
      N.telegram_get_updates("not-a-token") is None)
check("telegram poll: so does an empty one", N.telegram_get_updates("") is None)

# ── "Send test" must explain itself rather than fail silently ─────────────────────────────────
_sv_cfg2 = N._cfg
try:
    N._cfg = lambda: {}
    for _kind, _kw, _want in (("telegram", {}, "bot token"),
                              ("telegram", {"token": "nope"}, "expected format"),
                              ("telegram", {"token": "12345:TESTONLYnotarealtoken00"}, "chat ID"),
                              ("discord", {}, "webhook URL"),
                              ("discord", {"webhook": "https://evil.example/x"}, "Discord webhook URL")):
        _ok, _msg = N.test_send(_kind, **_kw)
        check("test send: %s with %s explains what is missing" % (_kind, list(_kw) or "nothing"),
              _ok is False and _want.lower() in _msg.lower(), _msg[:70])
finally:
    N._cfg = _sv_cfg2

# ── Tailscale address recognition ──────────────────────────────────────────────────────────────
# is_tailscale_ip decides whether the panel treats a host as being on the tailnet, which changes
# how it connects and what it exempts from fail2ban/UFW. A false positive would exempt a PUBLIC
# address from the security rules, so the near-misses matter as much as the hits.
import tailscale_integration as TS

for _h in ("100.64.0.1", "100.115.92.7", "fd7a:115c:a1e0::1",
           "ns106051.taile87e07.ts.net", "box.tail1234.ts.net", "host.taile87e07.example"):
    check("tailnet: %r is recognised" % _h, TS.is_tailscale_ip(_h) is True)
for _h in ("10.0.0.1", "192.168.1.5", "1.100.0.1", "203.0.113.9", "example.ts.net.evil.com",
           "fd7b:115c::1", "", None, "100abc.example.com"):
    check("tailnet: %r is NOT taken for a tailnet address" % (_h,), TS.is_tailscale_ip(_h) is False)

# get_magic_url: the port is omitted for the standard ones and appended otherwise, and there is no
# URL at all when the node has no MagicDNS name (rather than a broken "https://None").
_sv_info = TS.get_tailscale_info
try:
    class _Info(object):
        def __init__(self, dns): self.dns_name, self.tailscale_ips, self.peers = dns, [], []
    TS.get_tailscale_info = lambda *a, **k: _Info("box.taile87e07.ts.net")
    eq("magic url: no port for https", TS.get_magic_url(), "https://box.taile87e07.ts.net")
    eq("magic url: 443 is left off", TS.get_magic_url(443), "https://box.taile87e07.ts.net")
    eq("magic url: 80 is left off too", TS.get_magic_url(80), "https://box.taile87e07.ts.net")
    eq("magic url: any other port is appended", TS.get_magic_url(5000),
       "https://box.taile87e07.ts.net:5000")
    eq("magic url: the protocol is honoured", TS.get_magic_url(8080, "http"),
       "http://box.taile87e07.ts.net:8080")
    TS.get_tailscale_info = lambda *a, **k: _Info("")
    eq("magic url: no MagicDNS name means no URL, not a broken one", TS.get_magic_url(), None)
finally:
    TS.get_tailscale_info = _sv_info

check("tailnet: the panel can name the OS user it runs as", bool(TS._current_os_user()))

# ── Test fixtures must not be shaped like real credentials ────────────────────────────────────
# A synthetic Telegram token written in the EXACT real shape (9 digits : 35 chars) tripped GitHub
# secret scanning and opened an alert against this repo. A false positive there is not harmless:
# it trains whoever reads that dashboard to wave the next one through. The panel's own patterns
# are far looser than the real formats, so a fixture can stay valid AND be obviously fake.
import re as _re_fx
_fixture_shapes = [
    ("Telegram bot token", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    ("Discord webhook", r"https://discord\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_-]{60,}"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
]
_own = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "unit_test.py"),
            encoding="utf-8").read()
for _label, _pat in _fixture_shapes:
    _hits = _re_fx.findall(_pat, _own)
    check("fixtures: no test value is shaped like a real %s" % _label, not _hits,
          "%s" % (_hits[:1],))

# ── Supported-release claim vs what CI actually proves ──────────────────────────────────────────
# The README tells people which Ubuntu releases the panel runs on; the CI matrix is the only thing
# that proves it. These drift apart silently — a release added to one and not the other is
# invisible until somebody installs onto it and finds out. Assert the claim and the proof agree.
# Parsed with regex rather than PyYAML so this gate needs no dependency CI doesn't already install.
_repo = _pl.Path(__file__).resolve().parent.parent
_ci_yml = (_repo / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
_readme = (_repo / "README.md").read_text(encoding="utf-8")
_ci_pairs = set(zip(
    [m for m in _re_fx.findall(r"- os: ubuntu-([0-9]{2}\.[0-9]{2})", _ci_yml)],
    [m for m in _re_fx.findall(r"\n\s+python: \"([0-9]+\.[0-9]+)\"", _ci_yml)],
))
_ci_releases = {r for r, _ in _ci_pairs}
_readme_line = next((ln for ln in _readme.splitlines() if "LTS** for the panel" in ln), "")
_readme_releases = set(_re_fx.findall(r"([0-9]{2}\.[0-9]{2})", _readme_line))
check("supported releases: CI matrix has at least one entry", bool(_ci_releases), str(_ci_pairs))
eq("supported releases: README lists exactly what CI tests",
   sorted(_readme_releases), sorted(_ci_releases))
# Each release must be paired with the Python IT ships — testing 26.04 on 3.12 would prove nothing
# about the interpreter people will actually run the panel under.
_EXPECTED_PY = {"22.04": "3.10", "24.04": "3.12", "26.04": "3.14"}
_wrong = sorted("%s->py%s (ships %s)" % (r, py, _EXPECTED_PY[r])
                for r, py in _ci_pairs if r in _EXPECTED_PY and _EXPECTED_PY[r] != py)
check("supported releases: each is tested on the Python that release ships", not _wrong, str(_wrong))


# A chat-bot command can stop a game server or update the panel. Every one used to be recorded
# with actor=None — i.e. "system" — so the audit log showed the effect and nothing about the
# cause. The origin string is what makes a bot-initiated action attributable.
from app import _bot_origin
eq("bot origin: telegram sender by username", _bot_origin("telegram", {"username": "fred", "id": 7}), "telegram:fred")
eq("bot origin: falls back to the numeric id", _bot_origin("telegram", {"id": 4242}), "telegram:4242")
eq("bot origin: discord is labelled as discord", _bot_origin("discord", {"username": "ann"}), "discord:ann")
eq("bot origin: an absent sender is still recorded, not blank",
   _bot_origin("telegram", None), "telegram:unknown")
check("bot origin: capped so a hostile display name can't flood the audit column",
      len(_bot_origin("discord", {"username": "x" * 500})) <= 64)


# ── API-token brute-force throttle ──────────────────────────────────────────────────────────────
# /login has been throttled for years; the bearer path — the panel's OTHER way in — had nothing.
import auth as _authmod
_authmod._TOKEN_FAILS.clear()
for _i in range(_authmod.TOKEN_MAX_FAILS - 1):
    _authmod._token_auth_record("10.0.0.9", ok=False)
check("token throttle: under the limit an IP is still allowed to try",
      not _authmod._token_auth_blocked("10.0.0.9"))
_authmod._token_auth_record("10.0.0.9", ok=False)
check("token throttle: the limit blocks further attempts",
      _authmod._token_auth_blocked("10.0.0.9"))
check("token throttle: a DIFFERENT IP is unaffected",
      not _authmod._token_auth_blocked("10.0.0.10"))
# A success must clear the counter, or one bad script would lock out the good token behind it.
_authmod._token_auth_record("10.0.0.9", ok=True)
check("token throttle: a successful auth clears the counter",
      not _authmod._token_auth_blocked("10.0.0.9"))
# Entries must age out, or the map grows one row per IP that ever mistyped a token.
_authmod._TOKEN_FAILS["10.0.0.11"] = [_time.time() - (_authmod.TOKEN_WINDOW + 5)] * 50
_authmod._token_auth_blocked("10.0.0.12")          # any call prunes
check("token throttle: stale IPs are pruned, so the map cannot grow forever",
      "10.0.0.11" not in _authmod._TOKEN_FAILS, str(list(_authmod._TOKEN_FAILS))[:60])
_authmod._TOKEN_FAILS.clear()


# ── Deprecations the panel must be able to hear ────────────────────────────────────────────────
# app.py used to open with `filterwarnings("ignore", category=DeprecationWarning)` — no module, no
# message, never lifted. Two consequences, both proven before this was changed:
#
#   1. It did NOT silence what its comment claimed. EventletDeprecationWarning subclasses Warning,
#      not DeprecationWarning, so eventlet's banner printed on every single start regardless.
#   2. It DID silence everything else, and it won the race against the operator: running the panel
#      under `-W always::DeprecationWarning` heard nothing, because a filterwarnings() call inserts
#      at the FRONT of the filter list and so overrides -W and PYTHONWARNINGS.
#
# What was hidden: 22 calls to datetime.utcnow(), deprecated in 3.12 and scheduled for removal —
# exactly the class of warning that predicts the next Python breaking the panel.
import re as _re
import shutil as _shutil
import subprocess as _sp
import tempfile as _tempfile
import time as _time
import clock as _clock
from datetime import datetime as _dtm, timezone as _tz

_n = _clock.utcnow()
check("clock.utcnow() is naive, so it can go straight into a db.DateTime column",
      _n.tzinfo is None, repr(_n.tzinfo))
check("clock.utcnow() still reads UTC, like datetime.utcnow() did",
      abs((_dtm.now(_tz.utc).replace(tzinfo=None) - _n).total_seconds()) < 5)
_a = _clock.aware_utcnow()
check("clock.aware_utcnow() is timezone-aware, for libraries that require it",
      _a.tzinfo is not None and _a.utcoffset().total_seconds() == 0, repr(_a.tzinfo))

# Source gate: the deprecated spellings must not come back. A single `datetime.utcnow()` reintroduced
# in a later PR would be invisible again the day CPython removes it.
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Split so these patterns do not match their own source line — this file is inside the walk.
_BAD_NOW = r"\.utc" + r"now\s*\("
_BAD_TS = r"\.utc" + r"fromtimestamp\s*\("
_offenders = []
for _dirpath, _dirnames, _files in os.walk(_root):
    _dirnames[:] = [d for d in _dirnames
                    if d not in {".git", ".venv", "venv", "__pycache__", "node_modules", "data"}]
    for _f in _files:
        if not _f.endswith(".py") or _f == "clock.py":
            continue
        _fp = os.path.join(_dirpath, _f)
        for _i, _line in enumerate(open(_fp, encoding="utf-8", errors="replace"), 1):
            _code = _line.split("#", 1)[0]          # a comment may legitimately name the old spelling
            if "clock" in _code:                    # clock.utcnow() is the replacement, not the target
                continue
            # The deprecated spellings are attribute access on datetime: datetime.utcnow(),
            # _dt.utcnow(), datetime.datetime.utcfromtimestamp(). A bare utcnow() is clock's.
            if _re.search(_BAD_NOW, _code) or _re.search(_BAD_TS, _code):
                _offenders.append("%s:%d" % (os.path.relpath(_fp, _root), _i))
check("no module calls the datetime UTC helpers that are scheduled for removal",
      not _offenders, ", ".join(_offenders[:5]))

# Source gate: no unscoped DeprecationWarning suppression anywhere. `module=` or `message=` is fine;
# a bare category filter silences the whole process.
_blanket = []
for _f in ("app.py", "auth.py", "models.py", "ssh_manager.py", "system_ops.py", "notifications.py"):
    for _i, _line in enumerate(open(os.path.join(_root, _f), encoding="utf-8"), 1):
        if "filterwarnings" in _line and "DeprecationWarning" in _line \
                and "module=" not in _line and "message=" not in _line and not _line.lstrip().startswith("#"):
            _blanket.append("%s:%d" % (_f, _i))
check("no module installs a process-wide DeprecationWarning filter",
      not _blanket, ", ".join(_blanket))

# Behavioural proof, not just a grep: with the operator asking for DeprecationWarnings on the command
# line, importing app must leave them audible. This is the check that actually failed before the fix.
_probe = (
    "import sys, warnings; sys.path.insert(0, %r);"
    "import app;"
    "heard=[];"
    "warnings.showwarning=lambda m,c,f,l,file=None,line=None: heard.append(c.__name__);"
    "warnings.warn('probe', DeprecationWarning);"
    "print('HEARD' if heard else 'DEAF')" % _root
)
try:
    _out = _sp.run([sys.executable, "-W", "always::DeprecationWarning", "-c", _probe],
                   capture_output=True, text=True, timeout=120, cwd=_root)
    _heard = "HEARD" in _out.stdout
    _detail = (_out.stdout.strip()[-60:] + " " + _out.stderr.strip()[-120:])
except Exception as _e:            # a sandbox that forbids subprocess shouldn't fail the suite
    _heard, _detail = True, "skipped: %s" % _e
check("importing app leaves -W always::DeprecationWarning working", _heard, _detail)

# eventlet's own banner IS silenced now — by message, since it is not a DeprecationWarning at all.
_quiet = _sp.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); import app" % _root],
                 capture_output=True, text=True, timeout=120, cwd=_root)
check("eventlet's deprecation banner no longer prints on every start",
      "Eventlet is deprecated" not in _quiet.stderr, _quiet.stderr.strip()[:120])

# ── The privileged helper: verbs instead of shell strings ──────────────────────────────────────
# The panel escalates local work as `sudo bash -c '<command>'`, and a sudoers rule permitting
# /bin/bash is exactly NOPASSWD:ALL — so the grant cannot be narrowed while a shell string crosses
# the boundary. privileged.py names each operation as a verb with separated arguments;
# tools/panel-helper is the root-owned end that re-validates them and execs a fixed argv.
import importlib.machinery as _machinery
import importlib.util as _ilu
import privileged as _priv

_helper_path = os.path.join(_root, "tools", "panel-helper")
_spec = _ilu.spec_from_loader("panel_helper", _machinery.SourceFileLoader("panel_helper", _helper_path))
_helper = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_helper)

# Sample arguments per verb. Every verb must appear here — a new verb with no sample is a gap in
# the parity check below, so the test fails rather than silently skipping it.
_VERB_SAMPLES = {
    "ufw-status": ["numbered"],
    "ufw-enable": [],
    "ufw-default": ["deny", "incoming"],
    "ufw-allow-port": ["27015", "Game"],
    "ufw-allow-proto-port": ["tcp", "27015", "Game"],
    "ufw-limit-port": ["22/tcp"],
    "ufw-allow-iface": ["tailscale0"],
    "ufw-delete-allow-port": ["22/tcp"],
    "ufw-delete-allow-proto-port": ["udp", "27015"],
    "ufw-delete-limit-port": ["22/tcp"],
    "ufw-delete-allow-app": ["OpenSSH"],
    "ufw-deny-ip": ["203.0.113.5", "panel-autoblock"],
    "ufw-delete-deny-ip": ["203.0.113.5"],
    "ufw-delete-num": ["3"],
    "f2b-status": [],
    "f2b-status-jail": ["sshd"],
    "f2b-unban": ["sshd", "203.0.113.5"],
    "f2b-reload": [],
    "service-restart": ["ssh"],
    "panel-restart": ["2"],
    "tailscale-set-operator": ["ubuntu"],
    "tailscale-serve": ["serve", "modern", "/", "http", "5000"],
    "service-reload": ["fail2ban"],
    "service-enable-now": ["fail2ban"],
    "service-disable-now": ["cups"],
    "apt-update": [],
    "apt-full-upgrade": ["phased"],
    "apt-upgrade": [],
    "apt-autoremove": [],
    "apt-install": ["curl", "lib32gcc-s1", "libsdl2-2.0-0:i386"],
    "apt-add-repo": ["universe"],
    "dpkg-add-arch": ["i386"],
    "apt-any-running": [],
    "apt-upgrade-running": [],
    "dpkg-lock-held": [],
    "reboot": [],
    "journal": ["ssh", "400"],
    "log-tail": ["fail2ban", "4000"],
    "os-update-log": [],
    "crontab-list": ["codserver"],
    "user-create": ["codserver"],
    "user-lock-password": ["codserver"],
    "user-delete": ["codserver"],
    "user-delete-force": ["codserver"],
    "user-kill-processes": ["codserver"],
    "user-remove-home": ["codserver"],
    "write-file": ["fail2ban-jail-local"],
    "sysctl-reload": ["tailscale"],
    "sshd-backup-dropin": [],
    "sshd-restore-dropin": [],
    "sshd-discard-backup": [],
    "sshd-validate": [],
    "listening-sockets": [],
    "f2b-set-sshd-ports": ["2222,22"],
    "reboot-delayed": [],
    "pro-status": [],
    "pro-attach": ["A1b2C3d4E5f6G7h8"],
    "pro-service": ["enable", "esm-infra"],
    "pro-detach": [],
    "renice-users": ["-1", "codserver"],
    "set-timezone": ["America/Chicago"],
    "sshd-effective-config": [],
    "disk-free": ["/home"],
    "content-dir-create": ["gmodcontent"],
    "content-game-present": ["gmodcontent", "cstrike"],
    "content-script-present": ["gmodcontent", "cssserver"],
    "content-game-remove": ["gmodcontent", "cstrike", "cssserver"],
    "content-cron-write": ["gmodcontent"],
    "content-cron-remove": ["gmodcontent"],
    "content-grant-read": ["gmodcontent", "gmodcontent", "gmodserver", "cstrike"],
    "gmod-mount-read": ["gmodserver"],
    "f2b-log-lines": ["2026-09-02"],
    "sshd-set-directive": ["ClientAliveInterval", "300"],
    "create-swapfile": [],
    "npm-install-global": ["gamedig"],
    "journal-cron": [],
    "tailscale-up-key": ["tskey-auth-abc123def", "yes", "10.0.0.0/24", "tag:server"],
    "tailscale-up-login": ["yes", "-"],
    "os-update-run": [],
    "panel-db-repair": [],
    "panel-restore": [],
    "panel-self-update": ["-", "-"],
    "tailscale-install": [],
    "game-backup-read": ["ubuntu", "csgoserver-2026-01-01.tar.gz"],
    "lgsm-discover": [],
    "content-scan": ["cstrike", "hl2"],
}
check("privileged: every verb has a sample (new verbs cannot skip the parity check)",
      set(_VERB_SAMPLES) == set(_priv.verbs()),
      "panel-only=%s helper-only=%s" % (sorted(set(_priv.verbs()) - set(_VERB_SAMPLES)),
                                        sorted(set(_VERB_SAMPLES) - set(_priv.verbs()))))
check("privileged: the helper knows exactly the same verbs as the panel",
      sorted(_helper.VERBS) == _priv.verbs(),
      "helper=%s panel=%s" % (sorted(_helper.VERBS)[:3], _priv.verbs()[:3]))

# THE anti-drift gate. The helper deliberately keeps its own copy of the table — it must not import
# panel code, because root running panel-writable code is the thing this is trying to prevent. The
# copies are only safe while something checks they agree.
_drift = []
for _v, _a in _VERB_SAMPLES.items():
    if _v not in _helper.VERBS or _v not in _priv.verbs():
        continue
    _hv = _helper.VERBS[_v][1](_helper.validate(_v, _a))
    _pv = _priv.tool_argv(_v, _a)
    if _hv != _pv:
        _drift.append("%s: helper=%r panel=%r" % (_v, _hv, _pv))
check("privileged: helper and panel build an identical argv for every verb",
      not _drift, "; ".join(_drift[:2]))

# The helper can only ever run tools it names. bash is the whole point: if it resolved, the boundary
# would be decorative.
check("helper: resolves ufw", _helper.resolve("ufw").endswith("/ufw") if os.path.exists("/usr/sbin/ufw") else True)
check("helper: knows exactly the tools its verbs need, and no more",
      sorted(_helper.TOOLS) == ["add-apt-repository", "apt-get", "bash_installer", "crontab",
                                "curl", "df", "dpkg",
                                "fail2ban-client", "fallocate", "fuser", "journalctl", "mkswap",
                                "npm", "passwd", "pgrep", "pkill", "pro", "reboot", "renice", "rm",
                                "sh_installer", "ss", "sshd", "swapon", "sysctl",
                                "systemctl", "systemd-run",
                                "tail", "tailscale", "timedatectl", "ufw", "useradd", "userdel",
                                "usermod"],
      sorted(_helper.TOOLS))
# bash_installer exists so the self-update can run ONE fixed root-owned file. The general shell
# must stay unresolvable under its own name, or any future verb could build ["bash", "-c", ...].
check("helper: bash_installer points at a real shell, and only INSTALLER_PATH uses it",
      _helper.TOOLS["bash_installer"] == ("/bin/bash", "/usr/bin/bash"))
for _prog in ("bash", "sh", "python3", "env"):
    check("helper: refuses to resolve %s" % _prog, _ufw_raises_fnf(_helper.resolve, _prog))

# Validators. Each of these reached a root shell as text before; now they are rejected outright.
_BAD = {
    "ufw-delete-deny-ip": ["1.2.3.4; rm -rf /", "$(id)", "any", "", "1.2.3.4 -x", "0"],
    "ufw-limit-port": ["22; reboot", "0", "65536", "22/sctp", "-1", "$(id)"],
    "ufw-allow-iface": ["eth0; id", "../../etc", "a" * 16, "$(id)"],
    "ufw-delete-allow-app": ["OpenSSH; id", "Nginx", "openssh"],
    "ufw-default": ["allow; id", "drop"],
    "ufw-delete-num": ["0", "1; id", "-1", "abc"],
    # The unit list is exhaustive on purpose: the panel may restart these six services and nothing
    # else, so a real service name it was never meant to touch is refused like an injection is.
    "service-restart": ["nginx", "docker", "ssh; id", "ssh.service", ""],
    # The delay is the ONLY caller input to a verb that restarts the panel itself.
    "panel-restart": ["0", "301", "-1", "2; reboot", "", "abc", "1e3"],
    # These two are exported into a ROOT-run installer's environment.
    "panel-self-update": ["--upload-pack=x", "main; id", "a/../b", "HEAD~1", "'"],
    # The operator is a Linux user name; anything shaped like a flag or a shell fragment is out.
    "tailscale-set-operator": ["root; id", "--operator=x", "", "a" * 40, "has space"],
    "f2b-status-jail": ["sshd; id", "$(id)", "a" * 65, ""],
    # Package names reach `apt-get install` as separate argv entries, but a name is still the one
    # place an attacker-supplied string gets to be a whole argument — so it is charset-checked.
    "apt-install": ["curl; id", "$(id)", "--reinstall", "-o", "Curl", "pkg name", ""],
    "dpkg-add-arch": ["amd64", "i386; id", ""],
    "apt-add-repo": ["ppa:someone/ppa", "universe; id", "multiverse"],
    "apt-full-upgrade": ["phased; id", "everything", ""],
    # The log verbs take a SOURCE NAME, never a path or a unit — so a traversal is not rejected by
    # a filter, it is simply not expressible.
    "log-tail": ["/etc/shadow", "../../etc/shadow", "syslog", "auth; id", ""],
    "journal": ["nginx", "ssh; id", "linuxgsm-panel", ""],
    # user-remove-home runs `rm -rf` as root. These are the names that must never become a path.
    "user-remove-home": ["..", ".", "", "-rf", "/home/x", "root; rm -rf /", "a" * 33, "1abc"],
    "user-create": ["-o root", "a b", "$(id)", ""],
    # write-file takes a destination NAME. A path is not "escaped" here, it is not accepted.
    "write-file": ["/etc/shadow", "/etc/passwd", "../../etc/shadow", "fail2ban-jail-local; id", ""],
    "sysctl-reload": ["../../etc", "tailscale; id", ""],
    "f2b-set-sshd-ports": ["22; id", "0", "99999", "a,b", "", "1,2,3,4,5,6,7,8,9,10,11"],
    "set-timezone": ["../../etc/passwd", "UTC; id", "$(id)", "", "A" * 40],
    "disk-free": ["relative", "/home/../etc", "/home; id", "", "/home/$(id)"],
    "pro-attach": ["short", "tok en", "tok;id", ""],
    "renice-users": ["-99", "20", "abc", ""],
}
_leaked = []
for _v, _bads in _BAD.items():
    _nargs = len(_VERB_SAMPLES[_v])
    for _b in _bads:
        _args = [_b] + ["x"] * (_nargs - 1) if _nargs else [_b]
        try:
            _priv.check_args(_v, _args[:_nargs] if _nargs else [])
            _leaked.append("%s <- %r" % (_v, _b))
        except _priv.VerbError:
            pass
check("privileged: injection and out-of-range arguments are refused, not quoted",
      not _leaked, "; ".join(_leaked[:3]))

# _BAD above only ever puts the bad value in argument ONE, which silently leaves later arguments
# untested: widening PRO_SERVICES to accept any string passed the whole suite, because
# pro-service's first argument is the action and its own _choice rejected the probe first. These
# are full argument vectors, so a validator in any position is actually exercised.
_BAD_VECTORS = [
    ("pro-service", ["enable", "nginx"]),
    ("pro-service", ["enable", "esm-infra; id"]),
    ("pro-service", ["enable", ""]),
    ("pro-service", ["restart", "esm-infra"]),
    ("renice-users", ["-1", "root; id"]),
    ("renice-users", ["-1", "-oProxyCommand=x"]),
    ("renice-users", ["-1", "codserver", "bad;user"]),
    ("ufw-allow-port", ["27015", "comment; id"]),
    ("ufw-deny-ip", ["203.0.113.5", "tag$(id)"]),
    ("f2b-unban", ["sshd", "not-an-ip"]),
    ("ufw-allow-proto-port", ["tcp", "22", "a;b"]),
    ("ufw-default", ["allow", "sideways"]),
    ("apt-install", ["curl", "--reinstall"]),
    ("write-file", ["/etc/shadow"]),
    # The backup NAME is argument two, so _BAD above never reaches it — it pads position two
    # with "x". These aim at the validator that actually guards the path segment.
    ("game-backup-read", ["ubuntu", "../../etc/shadow"]),
    ("game-backup-read", ["ubuntu", "a/b.tar.gz"]),
    ("game-backup-read", ["ubuntu", "x.tar.gz; id"]),
    ("game-backup-read", ["ubuntu", "plain.txt"]),
    ("game-backup-read", ["ubuntu", ""]),
    ("panel-self-update", ["-", "main; id"]),
    ("panel-self-update", ["-", "--upload-pack=x"]),
    ("panel-self-update", ["-", "a/../b"]),
    ("panel-self-update", ["nothex", "-"]),
    # The content box: three of these verbs end in `rm -rf` as root, so the identifiers must be
    # refused in every position, not just the first.
    ("content-game-remove", ["gmodcontent", "../../etc", "cssserver"]),
    ("content-game-remove", ["gmodcontent", "cstrike", "../../etc"]),
    ("content-game-remove", ["..", "cstrike", "cssserver"]),
    ("content-game-remove", ["gmodcontent", "", "cssserver"]),
    ("content-game-present", ["gmodcontent", "a;b"]),
    ("content-grant-read", ["gmodcontent", "root; id", "gmodserver", "cstrike"]),
    ("content-grant-read", ["gmodcontent", "gmodcontent", "gmodserver", "../../etc"]),
    ("gmod-mount-read", ["../../etc"]),
    ("content-cron-remove", [".."]),
    ("content-scan", ["../../etc"]),
    ("content-scan", ["a;b"]),
    ("content-scan", [""]),
    ("f2b-log-lines", ["2026-09-02; id"]),
    ("f2b-log-lines", ["$(id)"]),
    ("f2b-log-lines", [""]),
    ("f2b-log-lines", ["/var/log/anything"]),
    # sshd-set-directive is the one verb where an argument constrains another: the panel may set
    # four directives, each only to values from its OWN set. "PermitRootLogin yes" is individually
    # well-formed and must still be refused.
    ("sshd-set-directive", ["Banner", "x"]),
    ("sshd-set-directive", ["PermitRootLogin", "yes"]),
    ("sshd-set-directive", ["ClientAliveInterval", "0"]),
    ("sshd-set-directive", ["PasswordAuthentication", "maybe"]),
    ("sshd-set-directive", ["ClientAliveInterval", "300; id"]),
    ("npm-install-global", ["evil-package"]),
    # tailscale: routes are PARSED as networks and tags must be `tag:name`, so a shell
    # metacharacter in either is refused rather than quoted.
    ("tailscale-up-key", ["tskey-abc123def45", "yes", "1.2.3.0/24; reboot", "-"]),
    ("tailscale-up-key", ["tskey-abc123def45", "yes", "-", "tag:x; rm -rf /"]),
    ("tailscale-up-key", ["tskey; touch /tmp/x", "yes", "-", "-"]),
    ("tailscale-up-key", ["tskey-abc123def45", "maybe", "-", "-"]),
    ("tailscale-up-key", ["short", "yes", "-", "-"]),
    ("tailscale-up-login", ["yes", "notacidr"]),
    ("tailscale-up-login", ["sure", "-"]),
]
_leaked2 = ["%s %r" % (v, a) for v, a in _BAD_VECTORS
            if not _ufw_raises_verb(lambda v=v, a=a: _priv.check_args(v, a))]
check("privileged: a bad argument is refused wherever it sits in the vector, not just first",
      not _leaked2, "; ".join(_leaked2[:3]))

# Arguments stay ARGUMENTS. The local transport never produces a string for a shell to parse, so a
# metacharacter is inert rather than escaped-and-hoped-for.
_argv = _priv.helper_argv("ufw-allow-port", ["27015", "cod server"])
check("privileged: local transport passes argv, with the comment as ONE element",
      "cod server" in _argv and not any(" -c" == x for x in _argv), repr(_argv))
check("privileged: local transport invokes the helper, never a shell",
      _argv[:3] == ["sudo", "-n", _priv.HELPER_PATH] and "bash" not in " ".join(_argv), repr(_argv))

# The remote transport must keep sending what it always sent — a host upgrading to this code should
# not see its firewall commands change shape.
_REMOTE_EXPECTED = {
    ("ufw-status", ("numbered",)): "ufw status numbered 2>&1",
    ("ufw-status", ("plain",)): "ufw status 2>&1",
    ("ufw-enable", ()): "ufw --force enable 2>&1",
    ("ufw-default", ("deny", "incoming")): "ufw default deny incoming 2>&1",
    ("ufw-allow-port", ("27015", "Game")): "ufw allow 27015 comment Game 2>&1",
    ("ufw-allow-proto-port", ("tcp", "27015", "")): "ufw allow proto tcp to any port 27015 2>&1",
    ("ufw-limit-port", ("22/tcp",)): "ufw limit 22/tcp 2>&1",
    ("ufw-allow-iface", ("tailscale0",)): "ufw allow in on tailscale0 2>&1",
    ("ufw-delete-num", ("3",)): "yes | ufw delete 3 2>&1",
    ("ufw-deny-ip", ("203.0.113.5", "panel-autoblock")):
        "ufw insert 1 deny from 203.0.113.5 comment panel-autoblock 2>&1",
    ("f2b-status", ()): "fail2ban-client status 2>&1",
    ("f2b-status-jail", ("sshd",)): "fail2ban-client status sshd 2>&1",
    ("f2b-unban", ("sshd", "203.0.113.5")): "fail2ban-client set sshd unbanip 203.0.113.5 2>&1",
    ("f2b-reload", ()): "fail2ban-client reload 2>&1",
    ("service-restart", ("ssh",)): "systemctl restart ssh 2>&1",
    ("service-enable-now", ("fail2ban",)): "systemctl enable --now fail2ban 2>&1",
    ("service-disable-now", ("cups",)): "systemctl disable --now cups 2>&1",
    ("apt-update", ()): "apt-get update -qq 2>&1",
    ("apt-autoremove", ()): "apt-get autoremove -y 2>&1",
    ("apt-install", ("curl",)):
        "DEBIAN_FRONTEND=noninteractive apt-get install -y curl 2>&1",
    ("apt-install", ("python3", "libsdl2-2.0-0:i386")):
        "DEBIAN_FRONTEND=noninteractive apt-get install -y python3 libsdl2-2.0-0:i386 2>&1",
    ("apt-full-upgrade", ("phased",)):
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
        "-o APT::Get::Always-Include-Phased-Updates=true "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold 2>&1",
    ("apt-full-upgrade", ("standard",)):
        "DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold 2>&1",
    ("dpkg-add-arch", ("i386",)): "dpkg --add-architecture i386 2>&1",
    ("apt-add-repo", ("universe",)): "add-apt-repository -y universe 2>&1",
    ("apt-upgrade-running", ()):
        "pgrep -f 'apt-get (upgrade|dist-upgrade|full-upgrade)' 2>&1",
    ("reboot", ()): "reboot 2>&1",
    ("journal", ("ssh", "400")): "journalctl -u ssh -u sshd --no-pager -n 400 2>&1",
    ("journal", ("fail2ban", "4000")): "journalctl -u fail2ban --no-pager -n 4000 2>&1",
    ("journal", ("panel", "400")): "journalctl -u linuxgsm-panel --no-pager -n 400 2>&1",
    ("log-tail", ("fail2ban", "4000")): "tail -n 4000 /var/log/fail2ban.log 2>&1",
    ("log-tail", ("auth", "200")): "tail -n 200 /var/log/auth.log 2>&1",
    ("os-update-log", ()): "tail -c 20000 /run/panel-os-update.log 2>&1",
    ("journal-cron", ()):
        "journalctl _COMM=cron --since '-14 days' -o short-unix --no-pager 2>&1",
    ("content-game-remove", ("gmodcontent", "cstrike", "cssserver")):
        "rm -rf /home/gmodcontent/serverfiles/cstrike ; rm -rf /home/gmodcontent/cssserver"
        " ; rm -rf /home/gmodcontent/lgsm/config-lgsm/cssserver",
    ("content-game-remove", ("srcds", "hl2", "-")): "rm -rf /home/srcds/serverfiles/hl2",
    ("content-cron-remove", ("gmodcontent",)):
        "rm -f /etc/cron.d/lgsm-gmod-content-gmodcontent",
    ("gmod-mount-read", ("gmodserver",)):
        "cat /home/gmodserver/serverfiles/garrysmod/cfg/mount.cfg 2>/dev/null || true",
    ("crontab-list", ("codserver",)): "crontab -u codserver -l 2>&1",
    ("user-create", ("codserver",)): "useradd -m -s /bin/bash codserver 2>&1",
    ("user-lock-password", ("codserver",)): "passwd -l codserver 2>&1",
    ("user-delete-force", ("codserver",)): "userdel -r -f codserver 2>&1",
    ("user-kill-processes", ("codserver",)): "pkill -9 -u codserver 2>&1",
    ("user-remove-home", ("codserver",)): "rm -rf -- /home/codserver 2>&1",
}
_wrong = []
for (_v, _a), _want in _REMOTE_EXPECTED.items():
    _got = _priv.remote_command(_v, list(_a))
    if _got != _want:
        _wrong.append("%s: %r != %r" % (_v, _got, _want))
check("privileged: the remote transport renders the same commands the SSH path always sent",
      not _wrong, "; ".join(_wrong[:2]))

# A comment with a space must survive shell-quoting on the remote side.
check("privileged: remote rendering quotes a comment containing a space",
      _priv.remote_command("ufw-allow-port", ["27015", "cod server"])
      == "ufw allow 27015 comment 'cod server' 2>&1",
      _priv.remote_command("ufw-allow-port", ["27015", "cod server"]))

# End-to-end through the real script: unknown verbs and wrong arity are refused before anything runs.
_hp = _sp.run([sys.executable, _helper_path, "definitely-not-a-verb"],
              capture_output=True, text=True, timeout=60)
check("helper: an unknown verb exits 2 and runs nothing", _hp.returncode == 2, _hp.stderr.strip()[:80])
_hp = _sp.run([sys.executable, _helper_path, "ufw-status", "numbered", "extra"],
              capture_output=True, text=True, timeout=60)
check("helper: the wrong number of arguments exits 2", _hp.returncode == 2, _hp.stderr.strip()[:80])
_hp = _sp.run([sys.executable, _helper_path, "ufw-deny-ip", "1.2.3.4; id", "tag"],
              capture_output=True, text=True, timeout=60)
check("helper: a rejected argument exits 2", _hp.returncode == 2, _hp.stderr.strip()[:80])
check("helper: the rejected value is NOT echoed back (this runs as root, its stderr reaches the UI)",
      "1.2.3.4; id" not in _hp.stderr, _hp.stderr.strip()[:100])

# apt-install is the one variadic verb: a package LIST, each element validated, with a floor and a
# ceiling on how many. An unbounded list would be a way to make one command arbitrarily large.
check("privileged: apt-install accepts a list of packages",
      _priv.tool_argv("apt-install", ["a", "b-c", "d:i386"])[-3:] == ["a", "b-c", "d:i386"])
check("privileged: apt-install refuses an empty package list",
      _ufw_raises_verb(lambda: _priv.check_args("apt-install", [])))
check("privileged: apt-install refuses an absurdly long package list",
      _ufw_raises_verb(lambda: _priv.check_args("apt-install", ["pkg"] * 65)))
check("privileged: one bad name rejects the whole apt-install list",
      _ufw_raises_verb(lambda: _priv.check_args("apt-install", ["good", "also-good", "bad;name"])))

# The write verb: content goes on stdin and the destination is a name, so neither ever becomes
# part of a command line. The two copies of the table must agree on every path AND every mode — a
# world-writable /etc/fail2ban/jail.local would be a quiet disaster.
check("privileged: the two copies agree on every write target, path and mode",
      _priv.WRITE_TARGETS == _helper.WRITE_TARGETS)
check("privileged: every write target is an absolute path under /etc",
      all(p.startswith("/etc/") and ".." not in p for p, _m in _priv.WRITE_TARGETS.values()),
      str(sorted(p for p, _m in _priv.WRITE_TARGETS.values()))[:120])
check("privileged: no write target is group- or world-writable",
      all(m & 0o022 == 0 for _p, m in _priv.WRITE_TARGETS.values()),
      str({p: oct(m) for p, m in _priv.WRITE_TARGETS.values()})[:120])
# This gate used to assert the sshd drop-in was ABSENT, so that adding it could not happen by
# accident in a batch. It is present now, deliberately, together with the backup / validate /
# restore verbs that make changing it survivable. What is checked has moved accordingly: the
# drop-in may be written only if every step of the rollback sequence exists as a verb.
_SSHD_SEQUENCE = ["sshd-backup-dropin", "sshd-validate", "sshd-restore-dropin",
                  "sshd-discard-backup"]
check("privileged: the sshd drop-in is writable only alongside its whole rollback sequence",
      ("sshd-port-dropin" in _priv.WRITE_TARGETS)
      <= all(v in _priv.verbs() for v in _SSHD_SEQUENCE),
      "missing: %s" % [v for v in _SSHD_SEQUENCE if v not in _priv.verbs()])
check("privileged: the sshd snapshot cannot be read back by sshd (it must not end in .conf)",
      not _priv.SSHD_DROPIN_BAK.endswith(".conf") and _priv.SSHD_DROPIN.endswith(".conf"),
      _priv.SSHD_DROPIN_BAK)
check("privileged: both copies agree on the sshd paths",
      (_priv.SSHD_DROPIN, _priv.SSHD_DROPIN_BAK)
      == (_helper.SSHD_DROPIN, _helper.SSHD_DROPIN_BAK))
check("privileged: both copies agree on fail2ban's jail.local path",
      _priv.F2B_JAIL_LOCAL == _helper.F2B_JAIL_LOCAL)
# The tailscale login log is read by a poll loop running as root. Both copies must name the same
# file, and it must live in /run: in /tmp any local user could pre-create or replace it, and the
# poll would then be reading a file it does not own.
check("privileged: both copies agree on the tailscale login log",
      _priv.TS_UP_LOG == _helper.TS_UP_LOG, "%s / %s" % (_priv.TS_UP_LOG, _helper.TS_UP_LOG))
check("privileged: the tailscale login log is in /run, not /tmp",
      _priv.TS_UP_LOG.startswith("/run/"), _priv.TS_UP_LOG)
# Every time a verb takes over an operation, the module-level constant that used to hold its path
# or its command is left behind with no users — and CodeQL's py/unused-global-variable turns main
# RED for it through the open-alerts gate from #101. That has now happened four times.
#
# The gate that used to be here named two constants explicitly, which is why it caught neither of
# the next two. This finds them by structure instead: every module-level `NAME = …`, checked
# against every Name/Attribute reference across the panel, its tools and its tests.
#
# Assignments whose value is a CALL are skipped, and that carve-out is load-bearing:
# `group_permissions = db.Table("group_permissions", …)` is referenced nowhere by name, but the
# call registers the table in SQLAlchemy's metadata, so create_all() builds it. Deleting it as
# "unused" would drop a table from the schema.
import ast as _ast_scan
# DERIVED, not hardcoded. This list used to name all fifteen modules by hand, which meant a new
# panel module was silently exempt from the gate until someone remembered to add it — and the
# whole point of a structural check is that it covers what actually exists. Splitting app.py up
# creates modules steadily, so the list reads the repo root instead.
_SCAN_MODULES = sorted(
    f for f in os.listdir(_root)
    if f.endswith(".py") and not f.startswith((".", "_")) and f != "setup.py"
)
assert "app.py" in _SCAN_MODULES and "ssh_manager.py" in _SCAN_MODULES, \
    "module discovery is looking at the wrong directory: %s" % _SCAN_MODULES[:5]
# The two lists are kept APART on purpose, and which one the orphan check consults is the whole
# point. _OS_UPDATE_LOG survived this gate all the way onto main and turned the branch red via
# CodeQL alert #352: it was dead production code, but a test asserted it equalled the helper's
# copy, and a test reference used to count as "referenced". A constant that only its own test
# mentions is exactly the thing this gate exists to find, so the orphan check below reads
# production references only. Tests are still parsed — other checks walk _parsed — they just
# no longer vouch for a name's aliveness.
_SCAN_PROD_USERS = _SCAN_MODULES + ["tools/panel-helper", "tools/perf_bench.py",
                                    "tools/lhci_serve.py"]
_SCAN_TEST_USERS = ["tests/unit_test.py", "tests/smoke_test.py", "tests/rbac_test.py",
                    "tests/manage_test.py", "tests/template_actions_test.py"]
_SCAN_USERS = _SCAN_PROD_USERS + _SCAN_TEST_USERS
_referenced = set()
_referenced_prod = set()
_parsed = {}
for _f in _SCAN_USERS:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    _parsed[_f] = _ast_scan.parse(open(_fp, encoding="utf-8").read())
    _here = set()
    for _n in _ast_scan.walk(_parsed[_f]):
        if isinstance(_n, _ast_scan.Name) and isinstance(_n.ctx, _ast_scan.Load):
            _here.add(_n.id)
        elif isinstance(_n, _ast_scan.Attribute):
            _here.add(_n.attr)                     # sm._FOO / _priv.BAR
        elif isinstance(_n, _ast_scan.ImportFrom):
            for _a in _n.names:
                _here.add(_a.name)
    _referenced |= _here
    if _f in _SCAN_PROD_USERS:
        _referenced_prod |= _here
_orphans = []
for _f in _SCAN_MODULES:
    if _f not in _parsed:
        continue
    for _node in _parsed[_f].body:
        if not isinstance(_node, _ast_scan.Assign) or isinstance(_node.value, _ast_scan.Call):
            continue
        for _t in _node.targets:
            if isinstance(_t, _ast_scan.Name) and not _t.id.startswith("__") \
                    and _t.id not in _referenced_prod:
                _orphans.append("%s:%d %s%s" % (
                    _f, _node.lineno, _t.id,
                    " (only its tests mention it)" if _t.id in _referenced else ""))
# ── Census: argv of the form ["sudo", <shell>, ...] ────────────────────────────────────────────
# This is the measure of how far the sudoers grant is from being narrowable. A sudoers rule that
# permits /bin/bash or /bin/sh is EXACTLY equivalent to NOPASSWD:ALL — the caller just runs
# `sudo bash -c '<anything>'` — so every one of these sites has to become a verb before the grant
# can shrink to the helper alone. install.sh's header says the same thing.
#
# A ratchet, like the sudo=True one: it may fall, never rise. Lower the ceiling when you convert
# one; do not raise it to make a new call site pass.
_SHELLS = {"bash", "sh", "/bin/bash", "/bin/sh"}
_sudo_shell = []
for _f in _SCAN_MODULES:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    for _n in _ast_scan.walk(_ast_scan.parse(open(_fp, encoding="utf-8").read())):
        if isinstance(_n, (_ast_scan.List, _ast_scan.Tuple)) and _n.elts:
            _first = _n.elts[0]
            if isinstance(_first, _ast_scan.Constant) and _first.value == "sudo":
                _rest = [_e.value for _e in _n.elts[1:3] if isinstance(_e, _ast_scan.Constant)]
                if any(_r in _SHELLS for _r in _rest):
                    _sudo_shell.append("%s:%d" % (_f, _n.lineno))
_SUDO_SHELL_CEILING = 1   # tailscale_integration.install_tailscale_local — the curl|sh installer
check("escalation census: ['sudo', <shell>] sites <= %d (currently %d) — ratchet, never raise"
      % (_SUDO_SHELL_CEILING, len(_sudo_shell)),
      len(_sudo_shell) <= _SUDO_SHELL_CEILING, "; ".join(sorted(_sudo_shell)))

# ── Census: EVERY direct ["sudo", ...] argv that is not the helper ─────────────────────────────
# This is the number that decides whether /etc/sudoers.d/linuxgsm-panel can shrink to a single
# line permitting only panel-helper. While any of these exist the grant has to stay NOPASSWD:ALL,
# because each one runs something the sudoers file would have to permit separately — and the two
# worst (a shell, and systemd-run, which runs whatever you hand it) cannot be scoped at all.
#
# Ratchet: convert a site to a verb and lower the ceiling. Never raise it.
_direct_sudo = []
for _f in _SCAN_MODULES:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    for _n in _ast_scan.walk(_ast_scan.parse(open(_fp, encoding="utf-8").read())):
        if isinstance(_n, (_ast_scan.List, _ast_scan.Tuple)) and _n.elts:
            _e0 = _n.elts[0]
            if not (isinstance(_e0, _ast_scan.Constant) and _e0.value == "sudo"):
                continue
            # privileged.helper_argv builds ["sudo", "-n", HELPER_PATH, verb, ...] — that IS the
            # boundary, not a bypass of it.
            _second = _n.elts[1] if len(_n.elts) > 1 else None
            if isinstance(_second, _ast_scan.Constant) and _second.value == "-n":
                continue
            _direct_sudo.append("%s:%d" % (_f, _n.lineno))
_DIRECT_SUDO_CEILING = 5   # backup restore, sudo -u cat, self-update, db repair, ts curl|sh installer
check("escalation census: direct ['sudo', ...] sites (not the helper) <= %d (currently %d)"
      % (_DIRECT_SUDO_CEILING, len(_direct_sudo)),
      len(_direct_sudo) <= _DIRECT_SUDO_CEILING, "; ".join(sorted(_direct_sudo)))

# ── panel_state's one rule: mutate in place, never rebind ──────────────────────────────────────
# monitoring.py and app.py both do `from panel_state import _player_counts`, which binds the OBJECT.
# Mutating it (`.clear()`, `[k] = v`) is seen by every importer; REBINDING it (`_player_counts = {}`)
# gives the rebinding module a private copy and strands everyone else on the old one — silently, with
# no error, and the symptom shows up as a monitor that reads stale state. That exact break happened
# while splitting monitoring out: a test reset `_monitor_state` by assignment and the monitor kept
# reading the pre-reset dict. A docstring did not prevent it; this does.
_ps_src = open(os.path.join(_root, "panel_state.py"), encoding="utf-8").read()
# Dunders are module machinery, not shared state: panel_state declares __all__, and so does
# monitoring — without this exclusion the gate reads monitoring's own __all__ as a rebind of
# panel_state's. (It did, the first time.)
_PS_NAMES = {_t.id for _n in _ast_scan.parse(_ps_src).body if isinstance(_n, _ast_scan.Assign)
             for _t in _n.targets
             if isinstance(_t, _ast_scan.Name) and not _t.id.startswith("__")}
_rebinds = []
for _f in ["app.py", "monitoring.py"] + [f for f in _SCAN_TEST_USERS]:
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    for _node in _ast_scan.walk(_ast_scan.parse(open(_fp, encoding="utf-8").read())):
        # `x = ...` and `x, y = ...` rebind; `x.attr = ...` and `x[k] = ...` do not.
        if isinstance(_node, _ast_scan.Assign):
            for _t in _node.targets:
                _flat = _t.elts if isinstance(_t, (_ast_scan.Tuple, _ast_scan.List)) else [_t]
                for _e in _flat:
                    if isinstance(_e, _ast_scan.Name) and _e.id in _PS_NAMES:
                        _rebinds.append("%s:%d %s" % (_f, _e.lineno, _e.id))
                    elif isinstance(_e, _ast_scan.Attribute) and _e.attr in _PS_NAMES:
                        _rebinds.append("%s:%d <mod>.%s" % (_f, _e.lineno, _e.attr))
check("panel_state names are mutated in place, never rebound by an importer",
      not _rebinds, "; ".join(sorted(set(_rebinds))[:5]))

check("no module-level constant is defined and then never referenced by production code",
      not _orphans, "; ".join(_orphans[:4]))
# The remote transport still base64s the content through a shell, so the content must survive
# every byte a config file can legitimately contain.
_tricky = "a'b\"c$d`e\\f\n[DEFAULT]\nignoreip = 10.0.0.1/8\n"
import base64 as _b64t
_rc = _priv.remote_write_command("fail2ban-panel-whitelist", _tricky)
check("privileged: remote write round-trips content containing shell metacharacters",
      _b64t.b64decode(_rc.split()[1]).decode() == _tricky)
check("privileged: remote write targets the table's path, not a caller's",
      "/etc/fail2ban/jail.d/zz-panel-whitelist.local" in _rc)

# The content box shares nothing until access is granted. The shell form created serverfiles with
# `install -m 750`, so the group bits existed from the moment the directory did, whether or not any
# GMod user had been granted anything. Creation is private now and the grant is what opens it.
import getpass as _gp2
import grp as _grp2
import pwd as _pwd2
import stat as _st2
try:
    _me2 = _gp2.getuser()
    _mygrp2 = _grp2.getgrgid(_pwd2.getpwnam(_me2).pw_gid).gr_name
    _cbox = _tempfile.mkdtemp(prefix="panel-content-")
    # A fresh copy of the helper module, so redirecting its home root cannot leak into any other
    # test — _sandboxed_helper() is defined further down, after the sshd block.
    _spec_c = _ilu.spec_from_loader("ph_content",
                                    _machinery.SourceFileLoader("ph_content", _helper_path))
    _hc = _ilu.module_from_spec(_spec_c)
    _spec_c.loader.exec_module(_hc)
    _hc.HOME_ROOT = _cbox
    _hc.home_of = lambda u, _r=_cbox: _r + "/" + _hc.v_username(u)
    os.makedirs(_cbox + "/" + _me2, exist_ok=True)
    _hc.do_content_dir_create([_me2], None)
    _sf = _cbox + "/" + _me2 + "/serverfiles"
    check("content box: serverfiles is created PRIVATE, not group-readable",
          _st2.S_IMODE(os.stat(_sf).st_mode) == 0o700,
          oct(_st2.S_IMODE(os.stat(_sf).st_mode)))
    os.makedirs(_sf + "/cstrike/sub", exist_ok=True)
    open(_sf + "/cstrike/plain", "w").write("x")
    os.chmod(_sf + "/cstrike/plain", 0o600)
    _hc.do_content_grant_read([_me2, _mygrp2, _me2, "cstrike"], None)
    check("content box: the grant makes serverfiles traversable by the group",
          _st2.S_IMODE(os.stat(_sf).st_mode) & _st2.S_IXGRP,
          oct(_st2.S_IMODE(os.stat(_sf).st_mode)))
    _pm = _st2.S_IMODE(os.stat(_sf + "/cstrike/plain").st_mode)
    check("content box: g+rX gives a plain file g+r and NOT g+x",
          (_pm & _st2.S_IRGRP) and not (_pm & _st2.S_IXGRP), oct(_pm))
    _dm = _st2.S_IMODE(os.stat(_sf + "/cstrike/sub").st_mode)
    check("content box: g+rX gives a directory both bits, because it was already u+x",
          (_dm & _st2.S_IRGRP) and (_dm & _st2.S_IXGRP), oct(_dm))
    _shutil.rmtree(_cbox, ignore_errors=True)
except (KeyError, OSError) as _e:
    check("content box: grant semantics exercised", True, "skipped: %s" % _e)

# content_path() is the second line of defence and the vector tests above never reach it: they go
# through check_args, whose per-verb validators reject a bad identifier first. So it is exercised
# DIRECTLY here — mutation showed that removing its validation left the whole suite green.
eq("content_path builds the expected path",
   _priv.content_path("gmodcontent", "serverfiles", "cstrike"),
   "/home/gmodcontent/serverfiles/cstrike")
check("content_path agrees between the panel and the helper",
      _priv.content_path("gmodcontent", "serverfiles", "cstrike")
      == _helper.content_path("gmodcontent", "serverfiles", "cstrike"))
for _bad in (("gmodcontent", "../../etc"), ("gmodcontent", ".."), ("gmodcontent", ""),
             ("gmodcontent", "a;b"), ("gmodcontent", "/etc"), ("..", "serverfiles"),
             ("gmodcontent", "serverfiles", "../.."), ("", "serverfiles")):
    check("content_path refuses %r" % (_bad,),
          _ufw_raises_verb(lambda b=_bad: _priv.content_path(*b)))

# The helper's own group check: content-grant-read adds a user to a GROUP, and the group named by
# the caller must actually be the content user's. Mutation showed this was untested — the suite
# exercises argv building, not the action bodies.
import getpass as _getpass
import grp as _grp
import pwd as _pwd
try:
    _me = _getpass.getuser()
    _my_group = _grp.getgrgid(_pwd.getpwnam(_me).pw_gid).gr_name
    check("content-grant-read refuses a group that is not the content user's",
          _helper.do_content_grant_read([_me, "root" if _my_group != "root" else "daemon",
                                         _me], None) == 2)
except (KeyError, OSError) as _e:
    check("content-grant-read group check exercised", True, "skipped: %s" % _e)

# home_of() is the only place a path is built from a name, and it feeds an `rm -rf` running as
# root. Both copies must agree, and neither may ever produce /home itself or escape it.
eq("home_of builds the obvious path", _priv.home_of("codserver"), "/home/codserver")
check("home_of agrees between the panel and the helper",
      _priv.home_of("codserver") == _helper.home_of("codserver"))
for _bad in ("..", ".", "", "/", "../root", "x/../.."):
    check("home_of refuses %r" % _bad, _ufw_raises_verb(lambda b=_bad: _priv.home_of(b)))

# The line count is bounded at both ends: 0 is not a count, and an unbounded one would let a caller
# ask for the entire journal through a root command.
for _n in ("0", "99999", "5; id", "-1", ""):
    check("privileged: journal refuses line count %r" % _n,
          _ufw_raises_verb(lambda n=_n: _priv.check_args("journal", ["ssh", n])))
check("privileged: the panel's OS-update log path is the one the helper reads",
      _priv.OS_UPDATE_LOG == _helper.OS_UPDATE_LOG,
      "%s / %s" % (_priv.OS_UPDATE_LOG, _helper.OS_UPDATE_LOG))
# ssh_manager deliberately has NO copy of this path: the helper both writes the log and reads it
# back through the os-update-log verb, so a third alias could only ever drift. Assert its absence,
# or the next person "restoring symmetry" reintroduces the dead global this test used to check.
check("privileged: ssh_manager keeps no copy of the OS-update log path",
      not hasattr(sm, "_OS_UPDATE_LOG"))
check("privileged: the two copies agree on every log path and journal unit",
      _priv.LOG_FILES == _helper.LOG_FILES and _priv.JOURNAL_UNITS == _helper.JOURNAL_UNITS)

# `| tail -n` became Python.
eq("_last_lines keeps the tail", sm._last_lines("a\nb\nc\nd", 2), "c\nd")
eq("_last_lines is fine with fewer lines than asked", sm._last_lines("a", 5), "a")
eq("_last_lines handles empty output", sm._last_lines("", 3), "")
eq("_last_lines handles None", sm._last_lines(None, 3), "")

# ufw status parsing that used to be a `grep` running under root.
check("ufw: _ufw_is_active reads the Status line", sm._ufw_is_active("Status: active") is True)
check("ufw: _ufw_is_active is false for inactive", sm._ufw_is_active("Status: inactive") is False)
check("ufw: _ufw_is_active is false for empty output", sm._ufw_is_active("") is False)
check("ufw: _ufw_is_active is not fooled by the word active elsewhere",
      sm._ufw_is_active("To    Action\n22    ALLOW  # keep this rule active") is False)

# ── The sshd port change, exercised for real ──────────────────────────────────────────────────
# This is the one privileged sequence whose failure mode is "the operator cannot reach the machine
# any more", so it is tested against a sandboxed filesystem rather than by asserting the argv. The
# property that matters is the ROLLBACK: whatever the host looked like before, a failed change puts
# it back exactly.
_sandbox = _tempfile.mkdtemp(prefix="panel-sshd-")
os.makedirs(os.path.join(_sandbox, "etc/ssh/sshd_config.d"))
os.makedirs(os.path.join(_sandbox, "etc/fail2ban"))


def _sandboxed_helper():
    """The helper module, with every path it writes redirected under a temp dir."""
    _spec = _ilu.spec_from_loader("ph_sandbox",
                                  _machinery.SourceFileLoader("ph_sandbox", _helper_path))
    _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m)
    _m.SSHD_DROPIN = _sandbox + _m.SSHD_DROPIN
    _m.SSHD_DROPIN_BAK = _m.SSHD_DROPIN + ".bak"
    _m.WRITE_TARGETS = dict(_m.WRITE_TARGETS,
                            **{"sshd-port-dropin": (_m.SSHD_DROPIN, 0o644)})
    _m.F2B_JAIL_LOCAL = os.path.join(_sandbox, "etc/fail2ban/jail.local")
    return _m


_h = _sandboxed_helper()

# (a) No drop-in before -> a failed change must leave no drop-in. Getting this wrong leaves an
#     empty file that sshd reads, which is how a "rollback" locks someone out.
_h.do_sshd_backup([], None)
check("sshd: backing up a host with no drop-in creates no snapshot",
      not os.path.exists(_h.SSHD_DROPIN_BAK))
_h.do_write_file(["sshd-port-dropin"], "Port 2222\nPort 22\n")
_h.do_sshd_restore([], None)
check("sshd: rolling back a host that had no drop-in removes the file entirely",
      not os.path.exists(_h.SSHD_DROPIN))

# (b) An existing drop-in must come back byte-identical, comments and all.
_ORIGINAL = "# the operator's own file\nPort 22\nListenAddress 10.0.0.1:22\n"
open(_h.SSHD_DROPIN, "w").write(_ORIGINAL)
_h.do_sshd_backup([], None)
_h.do_write_file(["sshd-port-dropin"], "Port 2222\nPort 22\n")
check("sshd: the new drop-in is what got written",
      open(_h.SSHD_DROPIN).read() == "Port 2222\nPort 22\n")
_h.do_sshd_restore([], None)
check("sshd: rolling back restores the previous drop-in byte for byte",
      open(_h.SSHD_DROPIN).read() == _ORIGINAL)
check("sshd: and the snapshot is consumed, not left lying in sshd_config.d",
      not os.path.exists(_h.SSHD_DROPIN_BAK))

# A rollback that changes permissions is not a rollback. There was a chmod 0o644 on the restore
# path, which both widened the file and threw away whatever mode the operator had set.
import stat as _stat
os.chmod(_h.SSHD_DROPIN, 0o600)
_hardened = open(_h.SSHD_DROPIN).read()
_h.do_sshd_backup([], None)
_h.do_write_file(["sshd-port-dropin"], "Port 2222\n")
_h.do_sshd_restore([], None)
check("sshd: rolling back restores the file's MODE, not just its content",
      _stat.S_IMODE(os.stat(_h.SSHD_DROPIN).st_mode) == 0o600
      and open(_h.SSHD_DROPIN).read() == _hardened,
      oct(_stat.S_IMODE(os.stat(_h.SSHD_DROPIN).st_mode)))

# (c) Discarding the snapshot on success is idempotent — the success path runs it once, but a
#     retry must not turn into an error.
_h.do_sshd_backup([], None)
_h.do_sshd_discard_backup([], None)
_h.do_sshd_discard_backup([], None)
check("sshd: discarding the snapshot twice is not an error",
      not os.path.exists(_h.SSHD_DROPIN_BAK))

# (d) The fail2ban jail edit must touch ONLY the [sshd] section. The sed range it replaces
#     (/^\[sshd\]/,/^\[/) was doing the same job with a regex running as root.
_jail = _h.F2B_JAIL_LOCAL
open(_jail, "w").write("[DEFAULT]\nbantime = 1h\nport = 9999\n\n"
                       "[sshd]\nenabled = true\nport = 22\nmaxretry = 5\n\n"
                       "[nginx]\nport = 80\n")
_h.do_f2b_sshd_ports(["2222,22"], None)
_jail_after = open(_jail).read()
check("f2b: the [sshd] jail gets the new port list",
      "port = 2222,22" in _jail_after.split("[sshd]")[1])
check("f2b: [DEFAULT]'s port is left alone",
      "port = 9999" in _jail_after.split("[sshd]")[0])
check("f2b: another jail's port is left alone", "port = 80" in _jail_after)
os.chmod(_jail, 0o640)
_h.do_f2b_sshd_ports(["22"], None)
check("f2b: editing jail.local keeps the mode it already had",
      _stat.S_IMODE(os.stat(_jail).st_mode) == 0o640,
      oct(_stat.S_IMODE(os.stat(_jail).st_mode)))
check("f2b: a host with no jail.local is a no-op, not a failure",
      _h.do_f2b_sshd_ports(["22"], None) == 0)

# (e) The deferred reboot must RETURN IMMEDIATELY and fire later — that is the whole reason it was
#     a backgrounded subshell. Run in a subprocess against a fake reboot binary, so this can be
#     asserted without the suite rebooting the machine it is running on.
_fake_reboot = os.path.join(_sandbox, "fake-reboot")
_marker = os.path.join(_sandbox, "fired")
open(_fake_reboot, "w").write("#!/bin/sh\necho fired > %s\n" % _marker)
os.chmod(_fake_reboot, 0o755)
_probe = (
    "import importlib.util as u, importlib.machinery as m, time, sys;"
    "s=u.spec_from_loader('p', m.SourceFileLoader('p', %r));"
    "mod=u.module_from_spec(s); s.loader.exec_module(mod);"
    "mod.resolve=lambda p: %r; mod.REBOOT_DELAY_SECONDS=1;"
    "t=time.time(); mod.do_reboot_delayed([], None);"
    "print('ELAPSED=%%.2f' %% (time.time()-t))" % (_helper_path, _fake_reboot)
)
try:
    _r = _sp.run([sys.executable, "-c", _probe], capture_output=True, text=True, timeout=60)
    _parts = _r.stdout.strip().rsplit("ELAPSED=", 1)
    _elapsed = float(_parts[1]) if len(_parts) == 2 else 9.0   # no marker -> treat as a failure
    check("reboot: the call returns at once instead of blocking for the delay",
          _elapsed < 0.5, _r.stdout.strip() + _r.stderr.strip()[:80])
    check("reboot: nothing has fired yet when it returns", not os.path.exists(_marker))
    _t_end = _time.time() + 8
    while not os.path.exists(_marker) and _time.time() < _t_end:
        _time.sleep(0.2)
    check("reboot: the detached child fires after the delay", os.path.exists(_marker))
except Exception as _e:                     # a sandbox that forbids fork should not fail the suite
    check("reboot: deferred-reboot probe ran", True, "skipped: %s" % _e)

_shutil.rmtree(_sandbox, ignore_errors=True)


# ── The three transports, including the one every existing install is actually on ──────────────
# run_privileged() has three paths and until now the suite exercised none of them. That matters
# most for the middle one: a host only gains the helper when install.sh is next run as ROOT, and
# the panel cannot place a root-owned file outside its own checkout — so every already-deployed
# install is running the fallback right now. If it were wrong, the firewall, fail2ban, apt and user
# management would all be broken on exactly the hosts that upgraded.
_T_LOCAL = NS(is_local=True, auth_method="local", sudo_enabled=True, linuxgsm_user="")
_T_REMOTE = NS(is_local=False, auth_method="key", sudo_enabled=True, linuxgsm_user="", host="h")
_T_SAMPLE = [
    ("ufw-allow-port", ["27015", "codserver"], "ufw allow 27015 comment codserver 2>&1"),
    ("f2b-unban", ["sshd", "203.0.113.5"], "fail2ban-client set sshd unbanip 203.0.113.5 2>&1"),
    ("service-restart", ["fail2ban"], "systemctl restart fail2ban 2>&1"),
    ("apt-install", ["curl"], "DEBIAN_FRONTEND=noninteractive apt-get install -y curl 2>&1"),
    ("journal", ["ssh", "400"], "journalctl -u ssh -u sshd --no-pager -n 400 2>&1"),
    ("user-remove-home", ["codserver"], "rm -rf -- /home/codserver 2>&1"),
]

_orig_rl, _orig_rc2, _orig_argv = sm._run_local, sm.run_command, sm._exec_local_argv
_orig_helper_state = dict(sm._HELPER_STATE)
try:
    # (a) local, helper NOT installed -> the pre-helper shell string, unchanged.
    _seen = []
    sm._run_local = lambda cmd, timeout=30, sudo=False: (_seen.append((cmd, sudo)), ("", "", 0))[1]
    sm._HELPER_STATE["present"] = False
    for _v, _a, _want in _T_SAMPLE:
        sm.run_privileged(_T_LOCAL, _v, _a, timeout=5)
    check("transport: with no helper installed, the local path runs the pre-helper command",
          [c for c, _s in _seen] == [w for _v, _a, w in _T_SAMPLE],
          str([c for c, _s in _seen][:2]))
    check("transport: and it still escalates (sudo=True), or nothing privileged would work",
          all(_s is True for _c, _s in _seen))

    # (b) local, helper installed -> argv through the helper, and no shell anywhere.
    _argvs = []
    sm._exec_local_argv = lambda argv, timeout=30, stdin_text=None: (
        _argvs.append(argv), ("", "", 0))[1]
    sm._HELPER_STATE["present"] = True
    for _v, _a, _w in _T_SAMPLE:
        sm.run_privileged(_T_LOCAL, _v, _a, timeout=5)
    check("transport: with the helper installed, the local path invokes it with argv",
          all(a[:3] == ["sudo", "-n", _priv.HELPER_PATH] for a in _argvs), str(_argvs[:1]))
    check("transport: the helper path never builds a shell command",
          not any("bash" in x or "2>&1" in x for a in _argvs for x in a), str(_argvs[:1]))
    check("transport: the verb and its arguments arrive as separate argv elements",
          _argvs[0][3:] == ["ufw-allow-port", "27015", "codserver"], str(_argvs[0]))

    # (c) remote -> the shell string over SSH, whatever the local helper situation is.
    _rem = []
    sm.run_command = lambda s_, c, **k: (_rem.append((c, k.get("sudo"))), ("", "", 0))[1]
    for _v, _a, _w in _T_SAMPLE:
        sm.run_privileged(_T_REMOTE, _v, _a, timeout=5)
    check("transport: a remote host gets the same command it always got",
          [c for c, _s in _rem] == [w for _v, _a, w in _T_SAMPLE], str([c for c, _s in _rem][:2]))
    check("transport: the local helper being present does not change what a remote receives",
          all(_s is True for _c, _s in _rem))
finally:
    sm._run_local, sm.run_command, sm._exec_local_argv = _orig_rl, _orig_rc2, _orig_argv
    sm._HELPER_STATE.clear()
    sm._HELPER_STATE.update(_orig_helper_state)


# ── the REMOTE fail2ban top-IPs report ────────────────────────────────────────────────────────
# The remote twin of system_ops.fail2ban_top_ips. #118 converted the local one; this copy still
# carried the five-stage root pipeline, which is how two copies of one behaviour drift. It shares
# the tally now — and a mutation that skipped the tally entirely left the suite green until this
# test existed, because nothing exercised the remote path end to end.
_orig_rt_rp, _orig_rt_ov = sm.run_privileged, sm.remote_fail2ban_overview
try:
    _RAW = "\n".join([
        "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5",
        "2026-09-03 10:00:01 x [sshd] Found 203.0.113.5",
        "2026-09-03 10:00:02 x [sshd] Ban 203.0.113.5",
        "2026-09-03 10:00:03 x [sshd] Found 198.51.100.9",
    ])
    _rt_args = []
    sm.run_privileged = lambda s_, v, a=(), **k: (_rt_args.append((v, list(a))), (_RAW, "", 0))[1]
    sm.remote_fail2ban_overview = lambda s_: {"jails": [{"banned_ips": ["203.0.113.5"]}]}
    _rt = sm.remote_fail2ban_top_ips(object(), limit=20, days=7)
    _rt_by = {r["ip"]: r for r in _rt}
    check("remote top-IPs: the raw log lines are tallied, not passed through",
          "203.0.113.5" in _rt_by and _rt_by["203.0.113.5"]["attempts"] == 2
          and _rt_by["203.0.113.5"]["bans"] == 1, str(_rt))
    check("remote top-IPs: a second IP is counted separately",
          _rt_by.get("198.51.100.9", {}).get("attempts") == 1, str(_rt))
    check("remote top-IPs: currently-banned IPs are marked from the jail overview",
          _rt_by["203.0.113.5"]["banned_now"] is True
          and _rt_by["198.51.100.9"]["banned_now"] is False, str(_rt))
    check("remote top-IPs: the verb is asked for the log lines, with a bare date as its cutoff",
          _rt_args and _rt_args[0][0] == "f2b-log-lines"
          and _re.fullmatch(r"\d{4}-\d{2}-\d{2}", _rt_args[0][1][0]) is not None,
          str(_rt_args[:1]))
    check("remote top-IPs: that cutoff is one privileged.py would accept",
          _priv.check_args("f2b-log-lines", _rt_args[0][1]) == _rt_args[0][1], str(_rt_args[:1]))
finally:
    sm.run_privileged, sm.remote_fail2ban_overview = _orig_rt_rp, _orig_rt_ov


# ── the content scan ──────────────────────────────────────────────────────────────────────────
# Was a shell loop over /home that built its inner list by interpolating the game keys, running as
# root. Read-only, but still a composed root command. Exercised against a sandboxed /home holding
# a user with two of the wanted games, one with none of them, one with no serverfiles at all, and
# one whose NAME is not something the panel would ever pass to a verb.
try:
    _scanroot = _tempfile.mkdtemp(prefix="panel-scan-")
    for _d in ("srcds/serverfiles/cstrike", "srcds/serverfiles/hl2",
               "gmodserver/serverfiles/tf2", "nothing", "bad;name/serverfiles/cstrike"):
        os.makedirs(os.path.join(_scanroot, _d), exist_ok=True)
    _spec_s = _ilu.spec_from_loader("ph_scan", _machinery.SourceFileLoader("ph_scan", _helper_path))
    _hs = _ilu.module_from_spec(_spec_s)
    _spec_s.loader.exec_module(_hs)
    _hs.HOME_ROOT = _scanroot
    _hs.home_of = lambda u, _r=_scanroot: _r + "/" + _hs.v_username(u)
    import io as _io_s
    _sbuf = _io_s.StringIO()
    _ssave = sys.stdout
    sys.stdout = _sbuf
    try:
        _hs.do_content_scan(["cstrike", "hl2"], None)
    finally:
        sys.stdout = _ssave
    _hits = sorted(ln for ln in _sbuf.getvalue().splitlines() if ln)
    eq("content scan: reports every wanted game a user actually has",
       _hits, ["HIT|srcds|cstrike", "HIT|srcds|hl2"])
    check("content scan: a user with serverfiles but none of the wanted games is not reported",
          not any("gmodserver" in h for h in _hits), str(_hits))
    check("content scan: a user with no serverfiles at all is not reported",
          not any("nothing" in h for h in _hits), str(_hits))
    check("content scan: a /home entry whose NAME the panel would never use is skipped",
          not any("bad" in h for h in _hits), str(_hits))
    _shutil.rmtree(_scanroot, ignore_errors=True)
except OSError as _e:
    check("content scan exercised", True, "skipped: %s" % _e)


# ── the detached OS-update runner ─────────────────────────────────────────────────────────────
# Was `setsid bash -c '<seven statements>' </dev/null >/dev/null 2>&1 &`. Exercised for real
# against a sandboxed log and a FAKE apt-get, so the suite cannot upgrade the machine it runs on.
#
# Run in a SUBPROCESS, and that is not tidiness. do_os_update_run ends its grandchild with
# os._exit(): if the fork ever goes missing, that _exit runs in the CALLER's process — which, in
# process, means this suite terminates mid-run with status 0. No failures printed, no summary, a
# green exit code. A mutation that removed the fork did exactly that and "passed". Out of process,
# the same mutation shows up as missing output and a wrong elapsed time.
_ho_done_marker = _helper.OS_UPDATE_DONE
_osu = None
try:
    _osu = _tempfile.mkdtemp(prefix="panel-osupd-")
except OSError as _e:
    check("os update: detached runner exercised", True, "skipped: %s" % _e)
if _osu:
    _fake_apt = os.path.join(_osu, "fake-apt")
    open(_fake_apt, "w").write("#!/bin/sh\necho \"fake apt: $*\"\n"
                               "case \"$*\" in *full-upgrade*) exit 7 ;; esac\nexit 0\n")
    os.chmod(_fake_apt, 0o755)
    _oslog = os.path.join(_osu, "os-update.log")
    _osprobe = (
        "import importlib.util as u, importlib.machinery as m, time, sys;"
        "s=u.spec_from_loader('p', m.SourceFileLoader('p', %r));"
        "mod=u.module_from_spec(s); s.loader.exec_module(mod);"
        "mod.OS_UPDATE_LOG=%r; mod.resolve=lambda p, f=%r: f;"
        "t=time.time(); mod.do_os_update_run([], None);"
        "sys.stderr.write('ELAPSED=%%.2f' %% (time.time()-t))"
        % (_helper_path, _oslog, _fake_apt)
    )
    _osr = _sp.run([sys.executable, "-c", _osprobe], capture_output=True, text=True, timeout=90)
    _osparts = _osr.stderr.rsplit("ELAPSED=", 1)
    _oselapsed = float(_osparts[1]) if len(_osparts) == 2 else 99.0
    check("os update: the call returns at once — the UI polls the log, it does not wait",
          _oselapsed < 1.0, "%.2f (stderr=%r)" % (_oselapsed, _osr.stderr[-60:]))
    check("os update: it reports that the job launched, and RETURNS to its caller",
          _priv.OS_UPDATE_STARTED in _osr.stdout and len(_osparts) == 2,
          "stdout=%r stderr=%r" % (_osr.stdout[-40:], _osr.stderr[-40:]))
    _osdeadline = _time.time() + 15
    _olog = ""
    while _time.time() < _osdeadline:
        try:
            _olog = open(_oslog).read()
            if _ho_done_marker in _olog:
                break
        except OSError:
            pass
        _time.sleep(0.2)
    check("os update: the log opens with a dated header", _olog.startswith("=== OS update started"),
          _olog[:60])
    check("os update: apt update, full-upgrade and autoremove all ran",
          "fake apt: update" in _olog and "full-upgrade" in _olog and "autoremove" in _olog, _olog)
    check("os update: phased updates are included, so a re-check actually reaches zero",
          "Always-Include-Phased-Updates=true" in _olog, _olog)
    check("os update: a config file the operator edited is kept",
          "--force-confold" in _olog and "--force-confdef" in _olog, _olog)
    check("os update: the sentinel carries the REAL exit code, not a fixed one",
          (_ho_done_marker + "7") in _olog, _olog[-80:])
    check("os update: the writer and the reader agree on the sentinel",
          _helper.OS_UPDATE_DONE == _priv.OS_UPDATE_DONE == sm._OS_UPDATE_DONE)

    # A job that dies before writing its own sentinel must still write one. Without it the UI's
    # popup polls forever, which looks exactly like "the update is taking a long time". Provoked
    # by making apt unresolvable, so the run fails at its first step.
    _osfail = os.path.join(_osu, "failed.log")
    _osfprobe = (
        "import importlib.util as u, importlib.machinery as m;"
        "s=u.spec_from_loader('p', m.SourceFileLoader('p', %r));"
        "mod=u.module_from_spec(s); s.loader.exec_module(mod);"
        "mod.OS_UPDATE_LOG=%r;"
        "mod.resolve=lambda p: (_ for _ in ()).throw(FileNotFoundError('apt-get'));"
        "mod.do_os_update_run([], None)" % (_helper_path, _osfail)
    )
    _osfr = _sp.run([sys.executable, "-c", _osfprobe], capture_output=True, text=True, timeout=60)
    check("os update: a job that cannot start still reports STARTED to its caller",
          _priv.OS_UPDATE_STARTED in _osfr.stdout, repr(_osfr.stdout))
    _osfdeadline = _time.time() + 10
    _osftxt = ""
    while _time.time() < _osfdeadline:
        try:
            _osftxt = open(_osfail).read()
            if _ho_done_marker in _osftxt:
                break
        except OSError:
            pass
        _time.sleep(0.2)
    check("os update: and it writes a FAILURE sentinel, so the popup stops waiting",
          (_ho_done_marker + "-1") in _osftxt, repr(_osftxt))
    _shutil.rmtree(_osu, ignore_errors=True)


# ── cron run times, read from cron's own journal ──────────────────────────────────────────────
# Was `journalctl _COMM=cron … | grep -F '(<user>) CMD ' | tail -n 800` — the user name went into a
# grep pattern running as root. The verb reads the window; the filtering is Python. The per-user
# filter is the part that matters: without it one game user's cron history is attributed to
# another, and a mutation that dropped it left the suite green until this test existed.
_CRON_JOURNAL = "\n".join([
    "1788000000 host CRON[1]: (codserver) CMD (/home/codserver/codserver monitor)",
    "1788000060 host CRON[2]: (gmodserver) CMD (/home/gmodserver/gmodserver update)",
    "1788000120 host CRON[3]: (codserver) CMD (/home/codserver/codserver update-lgsm)",
    "1788000180 host CRON[4]: (codserver) CMD (/home/codserver/codserver monitor)",
    "not-an-epoch host CRON[5]: (codserver) CMD (/home/codserver/codserver bogus)",
])
_orig_cron_rp = sm.run_privileged
try:
    sm.run_privileged = lambda s_, v, a=(), **k: (_CRON_JOURNAL, "", 0)
    _times = sm._read_cron_run_times(object(), "codserver")
    check("cron times: only THIS user's lines are counted",
          "/home/gmodserver/gmodserver update" not in _times, str(sorted(_times)))
    check("cron times: this user's commands are all present",
          "/home/codserver/codserver monitor" in _times
          and "/home/codserver/codserver update-lgsm" in _times, str(sorted(_times)))
    check("cron times: a repeated command keeps the LATEST run",
          _times.get("/home/codserver/codserver monitor") == 1788000180,
          str(_times.get("/home/codserver/codserver monitor")))
    check("cron times: a line whose first field is not an epoch is skipped",
          "/home/codserver/codserver bogus" not in _times, str(sorted(_times)))
    sm.run_privileged = lambda s_, v, a=(), **k: ("", "", 0)
    eq("cron times: no journal output is no times",
       sm._read_cron_run_times(object(), "codserver"), {})
finally:
    sm.run_privileged = _orig_cron_rp


# ── sshd hardening, and the swap file's precedence bug ────────────────────────────────────────
# The hardening was four `sed -i 's/^#\?Key.*/Key value/'` substitutions joined with ';' in one
# root shell. Exercised here against a real sshd_config: a commented directive, an already-set one,
# and one that is absent entirely.
try:
    _hdir = _tempfile.mkdtemp(prefix="panel-sshd-cfg-")
    _spec_h2 = _ilu.spec_from_loader("ph_hard", _machinery.SourceFileLoader("ph_hard", _helper_path))
    _hh = _ilu.module_from_spec(_spec_h2)
    _spec_h2.loader.exec_module(_hh)
    _hh.SSHD_CONFIG = os.path.join(_hdir, "sshd_config")
    open(_hh.SSHD_CONFIG, "w").write(
        "# a comment\n#ClientAliveInterval 120\nClientAliveCountMax 9\nPort 22\n")
    os.chmod(_hh.SSHD_CONFIG, 0o600)
    _hh.do_sshd_set_directive(["ClientAliveInterval", "300"], None)
    _hh.do_sshd_set_directive(["ClientAliveCountMax", "2"], None)
    _hh.do_sshd_set_directive(["PermitRootLogin", "prohibit-password"], None)
    _cfg = open(_hh.SSHD_CONFIG).read()
    check("sshd hardening: a COMMENTED directive is replaced, not duplicated",
          "ClientAliveInterval 300" in _cfg and "#ClientAliveInterval" not in _cfg, _cfg)
    check("sshd hardening: an already-set directive is replaced in place",
          "ClientAliveCountMax 2" in _cfg and "ClientAliveCountMax 9" not in _cfg, _cfg)
    check("sshd hardening: a directive that was ABSENT is appended",
          "PermitRootLogin prohibit-password" in _cfg, _cfg)
    check("sshd hardening: unrelated lines are left alone", "Port 22" in _cfg, _cfg)
    check("sshd hardening: the file keeps the mode it had",
          _stat.S_IMODE(os.stat(_hh.SSHD_CONFIG).st_mode) == 0o600)
    _shutil.rmtree(_hdir, ignore_errors=True)
except OSError as _e:
    check("sshd hardening exercised", True, "skipped: %s" % _e)

# The swap shell form had a precedence bug. `a && b && c && grep -q … || echo … >> /etc/fstab`
# parses as `((a && b) && c && grep) || echo`, so the fstab line was appended whenever ANY step
# failed — a host that ran out of space in fallocate still got a swap entry pointing at a file that
# was never formatted. The Python version appends only when the swap is really on and the line is
# absent, so that is what is asserted.
check("swap: the shell form's `a && b || c` appends on ANY failure, not just the grep",
      _sp.run(["bash", "-c", "false && true && grep -q x /dev/null || echo APPENDED"],
              capture_output=True, text=True).stdout.strip() == "APPENDED")
check("swap: the braced form the remote rendering uses does not",
      _sp.run(["bash", "-c", "false && true && { grep -q x /dev/null || echo APPENDED; }"],
              capture_output=True, text=True).stdout.strip() == "")
check("swap: the remote rendering is the braced form",
      "{ grep -q" in _priv.remote_command("create-swapfile", []),
      _priv.remote_command("create-swapfile", []))


# ── the fail2ban top-IPs pipeline ─────────────────────────────────────────────────────────────
# Was five stages — zcat | awk (date filter) | grep | awk (tally) | sort | head — running as root,
# with the cutoff date and the row limit interpolated into it. The verb now does the READ half only
# (fixed glob, gzip handled in Python) and the tally is _tally_f2b_lines. These assert the Python
# reproduces what the awk produced, because "it looks equivalent" is how a rewrite loses a case.
import system_ops as _so_f2b
_F2B_LINES = "\n".join([
    "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5",
    "2026-09-03 10:00:01 x [sshd] Found 203.0.113.5",
    "2026-09-03 10:00:02 x [sshd] Ban 203.0.113.5",
    "2026-09-03 10:00:03 x [linuxgsm-panel] Found 203.0.113.5",
    "2026-09-03 10:00:04 x [sshd] Found 198.51.100.9",
    "2026-09-03 10:00:05 x [sshd] Ban 2001:db8::1",
    "2026-09-03 10:00:06 x [sshd] Unban 203.0.113.5",
])
_tallied = _so_f2b._tally_f2b_lines(_F2B_LINES, 20)
_trows = _so_f2b._parse_top_ips(_tallied, set(), {})
_by_ip = {r["ip"]: r for r in _trows}
check("f2b top-IPs: Found and Ban are counted separately, per IP",
      _by_ip["203.0.113.5"]["attempts"] == 3 and _by_ip["203.0.113.5"]["bans"] == 1, _tallied)
check("f2b top-IPs: an IP seen in two jails lists both, once each",
      _by_ip["203.0.113.5"]["jails"] == ["sshd", "linuxgsm-panel"], str(_by_ip["203.0.113.5"]))
check("f2b top-IPs: an Unban line is not an event", "Unban" not in _tallied)
check("f2b top-IPs: an IPv6 address survives the parse", "2001:db8::1" in _by_ip)
check("f2b top-IPs: ranked by attempts, most first",
      [r["ip"] for r in _trows][0] == "203.0.113.5", str([r["ip"] for r in _trows]))
check("f2b top-IPs: the limit is honoured",
      len(_so_f2b._tally_f2b_lines(_F2B_LINES, 1).splitlines()) == 1)
eq("f2b top-IPs: no input is no rows", _so_f2b._tally_f2b_lines("", 20), "")
eq("f2b top-IPs: lines that are not events are no rows",
   _so_f2b._tally_f2b_lines("nothing to see here\n", 20), "")

# The read half, over a real plain log AND a real gzipped rotation.
try:
    _logdir = _tempfile.mkdtemp(prefix="panel-f2b-")
    open(os.path.join(_logdir, "fail2ban.log"), "w").write(
        "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5\n"
        "2026-09-01 09:00:00 x [sshd] Found 198.51.100.9\n")     # before the cutoff
    import gzip as _gzip_t
    with _gzip_t.open(os.path.join(_logdir, "fail2ban.log.2.gz"), "wt") as _gf:
        _gf.write("2026-09-04 11:00:00 x [sshd] Ban 203.0.113.5\n"
                  "2026-09-03 08:00:00 x [sshd] Unban 203.0.113.5\n")
    _spec_l = _ilu.spec_from_loader("ph_logs", _machinery.SourceFileLoader("ph_logs", _helper_path))
    _hl = _ilu.module_from_spec(_spec_l)
    _spec_l.loader.exec_module(_hl)
    _hl.F2B_LOG_GLOB = os.path.join(_logdir, "fail2ban.log*")
    import io as _io_t
    _buf = _io_t.StringIO()
    _stdout_save = sys.stdout
    sys.stdout = _buf
    try:
        _hl.do_f2b_log_lines(["2026-09-02"], None)
    finally:
        sys.stdout = _stdout_save
    _got = [ln for ln in _buf.getvalue().splitlines() if ln]
    check("f2b log read: the plain log is read", any("Found 203.0.113.5" in ln for ln in _got), str(_got))
    check("f2b log read: a GZIPPED rotation is read too — zcat's job, done in Python",
          any("Ban 203.0.113.5" in ln for ln in _got), str(_got))
    check("f2b log read: a line before the cutoff is dropped",
          not any("198.51.100.9" in ln for ln in _got), str(_got))
    check("f2b log read: a line that is not a Ban/Found is dropped",
          not any("Unban" in ln for ln in _got), str(_got))
    _shutil.rmtree(_logdir, ignore_errors=True)
except OSError as _e:
    check("f2b log read exercised", True, "skipped: %s" % _e)


# ── isdigit() is not "int() will accept this" ─────────────────────────────────────────────────
# Fuzzing found this, in _parse_top_ips: `int(parts[0]) if parts[0].isdigit() else 0` raised
# ValueError on "¹". str.isdigit() is True for Unicode No characters — superscripts — while int()
# only accepts Nd. So the guard passed and the conversion blew up, one line later.
#
# It was never one site. The same `.isdigit()` immediately before `int()` appeared 35 times across
# app, auth, manage, system_ops and ssh_manager, including two reachable from data the panel reads
# off a game server (a queryport from its config, a player count from command output) and two in
# the Flask-Login user loader. isdecimal() is exactly the predicate that was wanted: True iff every
# character is Nd, which is precisely what int() accepts.
check("unicode: isdigit() accepts a superscript, isdecimal() does not — that gap IS the bug",
      "\u00b9".isdigit() and not "\u00b9".isdecimal())
_int_raised = False
try:
    int("\u00b9")
except ValueError:
    _int_raised = True
check("unicode: int() rejects it, so isdecimal() is the guard that matches int()", _int_raised)
check("unicode: isdecimal() still accepts a non-ASCII DECIMAL digit, so nothing legitimate is lost",
      "٥".isdecimal() and int("٥") == 5)

# No module may guard an int() with isdigit() again.
_isdigit_users = []
for _f in ("app.py", "auth.py", "manage.py", "models.py", "system_ops.py", "ssh_manager.py",
           "notifications.py", "backup.py", "db_maintenance.py", "tailscale_integration.py",
           "config.py", "i18n.py", "privileged.py", "clock.py"):
    _fp = os.path.join(_root, _f)
    if not os.path.exists(_fp):
        continue
    for _i, _line in enumerate(open(_fp, encoding="utf-8"), 1):
        if ".isdigit()" in _line.split("#", 1)[0]:
            _isdigit_users.append("%s:%d" % (_f, _i))
check("unicode: no module uses .isdigit() — isdecimal() is the one that matches int()",
      not _isdigit_users, ", ".join(_isdigit_users[:4]))

# The crashing input itself, replayed.
import system_ops as _so_top
_CRASH = "¹\t²\t203.0.113.5\tsshd\n5\t2\t198.51.100.9\tsshd,panel\n"
try:
    _rows = _so_top._parse_top_ips(_CRASH, set(), {})
    check("fail2ban top-IPs: the fuzz crash input parses instead of raising",
          len(_rows) == 2 and _rows[0]["attempts"] == 0 and _rows[1]["attempts"] == 5,
          str(_rows))
except Exception as _e:
    check("fail2ban top-IPs: the fuzz crash input parses instead of raising", False, repr(_e))


# ── The escalation census: a ratchet, and a correction ────────────────────────────────────────
# I reported the conversion's progress for four PRs as "113 sites -> N" while counting only ONE of
# the two ways the panel escalates on its own host. run_command(..., sudo=True) is the obvious one.
# _sudo_sh() is the other: it builds `sudo bash -c '<pipeline>'` itself and then passes sudo=False,
# so it is invisible to a search for sudo=True — and there were 18 of them the whole time.
#
# This counts both, and ratchets: the ceilings below may be lowered as call sites convert, never
# raised. A new escalation written as a shell string fails this test instead of going unnoticed.
import ast as _ast

_ESCALATION_FILES = ["app.py", "auth.py", "ssh_manager.py", "system_ops.py", "notifications.py",
                     "backup.py", "db_maintenance.py", "tailscale_integration.py", "manage.py"]
_CEILING = {"sudo=True": 4, "_sudo_sh": 0}   # measured at the time of writing; lower only

def _is_dispatch(call):
    """True when this escalation is NOT a call site composing a shell string.

    Two shapes qualify. run_privileged() itself takes a `sudo` keyword — passing it explicitly is
    still a VERB call, not a shell string, and counting those overstated the work by one until it
    was noticed. And run_privileged / write_root_file / _run_verb each end in a
    run_command/_run_local/_run with sudo=True, passing a command built by privileged.py.

    run_privileged(), write_root_file() and _run_verb() each end in a run_command/_run_local/_run
    with sudo=True, passing a command built by privileged.py. Counting those as "call sites still
    composing a shell string" overstates the work left by four — the number below is quoted in
    SECURITY.md, so it should mean what it says."""
    if getattr(call.func, "attr", getattr(call.func, "id", "")) in ("run_privileged", "_run_verb"):
        return True                       # a verb call, however it spells its sudo argument
    for _arg in list(call.args) + [k.value for k in call.keywords]:
        for _sub in _ast.walk(_arg):
            if (isinstance(_sub, _ast.Call)
                    and isinstance(_sub.func, _ast.Attribute)
                    and getattr(_sub.func.value, "id", "") == "_priv"
                    and _sub.func.attr in ("remote_command", "remote_write_command",
                                           "remote_content_cron_command")):
                return True
    return False


_census = {"sudo=True": 0, "_sudo_sh": 0}
for _f in _ESCALATION_FILES:
    _tree = _ast.parse(open(os.path.join(_root, _f), encoding="utf-8").read())
    for _n in _ast.walk(_tree):
        if not isinstance(_n, _ast.Call):
            continue
        if getattr(_n.func, "attr", getattr(_n.func, "id", "")) == "_sudo_sh":
            _census["_sudo_sh"] += 1
        for _k in _n.keywords:
            if (_k.arg == "sudo" and isinstance(_k.value, _ast.Constant)
                    and _k.value.value is True and not _is_dispatch(_n)):
                _census["sudo=True"] += 1

# The exclusion above could go over-broad and quietly shrink the number the ratchet guards — a
# _is_dispatch() that returned True for everything would report zero remaining work and still pass.
# So count what it excludes and pin that: there are exactly four transports (run_privileged and
# write_root_file in ssh_manager, twice each for the helper-present and no-helper paths, plus
# _run_verb in system_ops), plus two for write_content_cron, whose destination is per-user and so
# cannot live in WRITE_TARGETS. Raise this only when the verb layer genuinely gains another one.
_excluded = 0
for _f in _ESCALATION_FILES:
    _tree = _ast.parse(open(os.path.join(_root, _f), encoding="utf-8").read())
    for _n in _ast.walk(_tree):
        if not isinstance(_n, _ast.Call):
            continue
        for _k in _n.keywords:
            if (_k.arg == "sudo" and isinstance(_k.value, _ast.Constant)
                    and _k.value.value is True and _is_dispatch(_n)):
                _excluded += 1
check("escalation census: the exclusion covers exactly the 6 known transports",
      _excluded == 6, "excluded %d" % _excluded)

for _kind, _limit in _CEILING.items():
    check("escalation census: %s sites <= %d (currently %d) — ratchet, never raise"
          % (_kind, _limit, _census[_kind]),
          _census[_kind] <= _limit, "found %d" % _census[_kind])

# tailscale-serve is the only verb whose upstream URL is ASSEMBLED on the far side rather than
# handed in. These prove a caller cannot aim Tailscale Serve at anything but loopback on this box —
# which is a guarantee the old `sudo tailscale <args>` form could not make at all.
check("privileged: tailscale-serve builds a loopback upstream, modern grammar",
      _priv.tool_argv("tailscale-serve", ["serve", "modern", "/", "http", "5000"])
      == ["tailscale", "serve", "--bg", "--https=443", "http://127.0.0.1:5000"])
check("privileged: tailscale-serve builds a loopback upstream, legacy grammar",
      _priv.tool_argv("tailscale-serve", ["funnel", "legacy", "/panel", "https+insecure", "8443"])
      == ["tailscale", "funnel", "--bg", "--https", "443", "/panel",
          "https+insecure://127.0.0.1:8443"])
for _bad in (["serve", "modern", "../../etc", "http", "5000"],
             ["serve", "modern", "//evil.example.com", "http", "5000"],
             ["serve", "modern", "/", "ftp", "5000"],
             ["logout", "modern", "/", "http", "5000"],
             ["serve", "modern", "/", "http", "0"],
             ["serve", "sneaky", "/", "http", "5000"]):
    check("privileged: tailscale-serve refuses %r" % (_bad,),
          _ufw_raises_verb(lambda b=_bad: _priv.check_args("tailscale-serve", b)))
# ── The offline DB repair: the path comes from root's config, never from the caller ────────────
# do_panel_db_repair takes ZERO arguments. That is the security property, not a convenience: the
# old form composed `sudo systemd-run ... bash -c "<panel venv python> <panel dir>/db_maintenance.py"`,
# so root ran the panel user's interpreter on the panel user's script out of a checkout that
# `git pull` rewrites. A verb that accepted a path would be the same hole with validation bolted on.
_dbr_conf = _helper.PANEL_CONF
_dbr_dbm = _helper.DBM_PATH
try:
    import tempfile as _tf_dbr
    _dbr_dir = _tf_dbr.mkdtemp()

    # panel.conf parsing: comments, blank lines and stray whitespace are all tolerated.
    _cfgp = os.path.join(_dbr_dir, "panel.conf")
    with open(_cfgp, "w", encoding="utf-8") as _fh:
        _fh.write("# written by install.sh\n\n  db_path = /var/lib/panel/panel.db  \n")
    _helper.PANEL_CONF = _cfgp
    eq("helper: panel.conf parses key=value, ignoring comments and blanks",
       _helper.panel_conf().get("db_path"), "/var/lib/panel/panel.db")

    # A missing conf is an empty dict, not a crash and not a guess.
    _helper.PANEL_CONF = os.path.join(_dbr_dir, "absent.conf")
    eq("helper: a missing panel.conf reads as empty, not a guessed path", _helper.panel_conf(), {})
    check("helper: db-repair refuses to run with no db_path configured",
          _helper.do_panel_db_repair([], None) == 1)

    # A relative path, or one that does not exist, is refused rather than "repaired".
    for _bad in ("relative/panel.db", os.path.join(_dbr_dir, "does-not-exist.db")):
        with open(_cfgp, "w", encoding="utf-8") as _fh:
            _fh.write("db_path=%s\n" % _bad)
        _helper.PANEL_CONF = _cfgp
        check("helper: db-repair refuses db_path %r" % _bad,
              _helper.do_panel_db_repair([], None) == 1)

    # With a real database configured but NO root-owned db_maintenance beside the helper, it must
    # still refuse — running the checkout's copy is precisely what this verb exists to avoid.
    _realdb = os.path.join(_dbr_dir, "panel.db")
    open(_realdb, "wb").close()
    with open(_cfgp, "w", encoding="utf-8") as _fh:
        _fh.write("db_path=%s\n" % _realdb)
    _helper.PANEL_CONF = _cfgp
    _helper.DBM_PATH = os.path.join(_dbr_dir, "not-installed.py")
    check("helper: db-repair refuses when db_maintenance is not installed root-owned",
          _helper.do_panel_db_repair([], None) == 1)
finally:
    _helper.PANEL_CONF = _dbr_conf
    _helper.DBM_PATH = _dbr_dbm

def _module_toplevel_names(path):
    """Every name a module defines or imports at top level, by AST — no importing.

    Importing a panel module to ask `dir()` would boot eventlet, threads and a Flask app; this only
    needs to know what names EXIST, which the syntax tells us."""
    out = set()
    try:
        _t = _ast_scan.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError):
        return out
    for _n in _t.body:
        if isinstance(_n, (_ast_scan.FunctionDef, _ast_scan.AsyncFunctionDef, _ast_scan.ClassDef)):
            out.add(_n.name)
        elif isinstance(_n, _ast_scan.Assign):
            for _t2 in _n.targets:
                if isinstance(_t2, _ast_scan.Name):
                    out.add(_t2.id)
                elif isinstance(_t2, (_ast_scan.Tuple, _ast_scan.List)):
                    for _e in _t2.elts:
                        if isinstance(_e, _ast_scan.Name):
                            out.add(_e.id)
        elif isinstance(_n, _ast_scan.ImportFrom):
            for _a in _n.names:
                out.add(_a.asname or _a.name)
        elif isinstance(_n, _ast_scan.Import):
            for _a in _n.names:
                out.add((_a.asname or _a.name).split(".")[0])
    return out


# ── A stub must land on the module that RESOLVES the name ─────────────────────────────────────
# `mod.name = fake` on a module that has no `name` creates a NEW attribute and returns quietly. If
# the real function lives elsewhere, the stub never takes effect and the harness measures — or
# tests — un-stubbed code while looking like it worked.
#
# This is not hypothetical. Splitting monitoring out of app.py left four stubs in tools/perf_bench.py
# pointing at app's re-exports while _monitor_pass resolved the names in its own namespace; combined
# with a lost setup_complete flag, the benchmark spent every run timing a 199-byte redirect to
# /setup and printing a table that looked entirely plausible.
#
# READS of a missing attribute already fail loudly with AttributeError. Assignments do not, so
# those are what this checks.
_stub_mods = {}
for _f in sorted(os.listdir(_root)):
    if _f.endswith(".py"):
        _stub_mods[_f[:-3]] = _module_toplevel_names(os.path.join(_root, _f))
_stub_bad = []
for _f in sorted(glob.glob(os.path.join(_root, "tests", "*.py"))
                 + glob.glob(os.path.join(_root, "tools", "*.py"))):
    _src = open(_f, encoding="utf-8").read()
    try:
        _tree = _ast_scan.parse(_src)
    except SyntaxError:
        continue
    _alias = {}
    for _n in _ast_scan.walk(_tree):
        if isinstance(_n, _ast_scan.Import):
            for _a in _n.names:
                _base = _a.name.split(".")[0]
                if _base in _stub_mods:
                    _alias[_a.asname or _base] = _base
        elif isinstance(_n, _ast_scan.Assign) and isinstance(_n.value, _ast_scan.Subscript):
            if (getattr(getattr(_n.value, "value", None), "attr", "") == "modules"
                    and isinstance(_n.value.slice, _ast_scan.Constant)
                    and _n.value.slice.value in _stub_mods):
                for _t in _n.targets:
                    if isinstance(_t, _ast_scan.Name):
                        _alias[_t.id] = _n.value.slice.value
    for _n in _ast_scan.walk(_tree):
        if not (isinstance(_n, _ast_scan.Attribute) and isinstance(_n.ctx, _ast_scan.Store)):
            continue
        if not isinstance(_n.value, _ast_scan.Name):
            continue
        _mod = _alias.get(_n.value.id)
        if not _mod or _n.attr.startswith("__"):
            continue
        # nosudo_runner plants _real_subprocess as a MARKER the module is meant not to have; it is
        # read back with getattr(..., None). That is the one legitimate case.
        if _n.attr == "_real_subprocess":
            continue
        if _n.attr not in _stub_mods[_mod]:
            _stub_bad.append("%s:%d %s.%s (%s has no such name)"
                             % (os.path.basename(_f), _n.lineno, _n.value.id, _n.attr, _mod))
check("every stub is installed on a module that actually defines the name",
      not _stub_bad, "; ".join(sorted(set(_stub_bad))[:4]))

# ── The installer must not build a SECOND panel beside an existing one ────────────────────────
# IS_UPDATE asks "is there an app.py and a unit file where I am about to install?" — but where that
# is has already been decided by how the script was invoked. Run as root it looks under the service
# user's home; run as yourself, under yours. Neither sees the other, so `sudo ./install.sh` on a
# host with a working per-user install found nothing, called it a fresh install, and would have
# built a parallel panel: its own user, service, database and port.
_inst_guard = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: looks for an install in the OTHER service model before choosing one",
      "_other_install" in _inst_guard)
check("install.sh: that check runs BEFORE the mode decision, not after",
      _inst_guard.index("_other_install=") < _inst_guard.index('    RUN_AS_ROOT=1'))
check("install.sh: refuses rather than adopting the other install",
      "Refusing to build a parallel install." in _inst_guard)
# The service user's OWN directory must not trip it, or a root install could never update itself.
check("install.sh: skips the service user's own home when scanning for a per-user install",
      '[ "${_u}" = "${SERVICE_USER}" ] && continue' in _inst_guard)
# A stray checkout is not an install; requiring the unit file keeps the check specific.
check("install.sh: requires a user UNIT file, not just an app.py, to call it an install",
      ".config/systemd/user/linuxgsm-panel.service" in _inst_guard)

# ── The sudoers grant itself ──────────────────────────────────────────────────────────────────
# The whole point of the verb table. install.sh writes a NARROW grant when every root-owned piece
# is in place, and the wide one otherwise — because a host that has the new code but has not had
# install.sh re-run as root still falls back to `sudo bash -c '<verb as text>'`, and narrowing
# under it would break every privileged action rather than secure anything.
_inst = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: writes a narrow grant permitting only the helper",
      'NOPASSWD: ${HELPER_DST}" > /etc/sudoers.d/linuxgsm-panel' in _inst)
check("install.sh: the narrow grant is conditional on the root-owned pieces being installed",
      '[ "${HELPER_OK}" -eq 1 ] && [ "${ROOT_TOOLS_OK}" -eq 1 ]' in _inst)
check("install.sh: still validates whichever grant it wrote with visudo",
      "visudo -cf /etc/sudoers.d/linuxgsm-panel" in _inst)
# The narrow grant must not quietly re-admit any of the things that were call sites. Each of these
# runs whatever argv you hand it, so permitting one is permitting everything.
_narrow = _inst[_inst.index('if [ "${HELPER_OK}"'):_inst.index("chmod 440 /etc/sudoers.d")]
for _never in ("systemd-run", "/bin/bash", "/bin/sh", "tailscale", "sudo -u"):
    check("install.sh: the narrow grant does not permit %s" % _never, _never not in _narrow)

# ── The discovery scan, reimplemented in the helper, must speak the parser's dialect ───────────
# discover_linuxgsm_servers used to be a twenty-line shell program run under `sudo bash -c`. It
# needed root for exactly one thing — reading another user's crontab — and everything else was
# ordinary file reading. The helper now does it in Python, so the output contract is the ONLY thing
# holding the two halves together: FOUND|user|instance|port|backups|mods|cronlines|autostart, which
# ssh_manager splits and requires at least 8 fields of.
import tempfile as _tf_disc
_disc_home = _tf_disc.mkdtemp()
_disc_out = []
_sv_home_root, _sv_disc_stdout = _helper.HOME_ROOT, _helper.sys.stdout
try:
    _u = os.path.join(_disc_home, "csgoserver")
    os.makedirs(os.path.join(_u, "lgsm", "config-lgsm", "csgoserver"))
    os.makedirs(os.path.join(_u, "lgsm", "backup"))
    os.makedirs(os.path.join(_u, "lgsm", "mods"))
    with open(os.path.join(_u, "lgsm", "config-lgsm", "csgoserver", "csgoserver.cfg"), "w") as _fh:
        _fh.write("port=27015\n")
    for _b in ("a.tar.gz", "b.tgz", "notes.txt"):
        open(os.path.join(_u, "lgsm", "backup", _b), "w").close()
    with open(os.path.join(_u, "lgsm", "mods", "installed-mods.txt"), "w") as _fh:
        _fh.write("metamod\nsourcemod\n")
    _launcher = os.path.join(_u, "csgoserver")
    open(_launcher, "w").close()
    os.chmod(_launcher, 0o755)

    class _DiscCap:
        def write(self, t):
            _disc_out.append(t)

        def flush(self):
            pass

    _helper.HOME_ROOT = _disc_home
    _helper.sys.stdout = _DiscCap()
    _rc_disc = _helper.do_lgsm_discover([], None)
finally:
    _helper.HOME_ROOT, _helper.sys.stdout = _sv_home_root, _sv_disc_stdout
    import shutil as _sh_disc
    _sh_disc.rmtree(_disc_home, ignore_errors=True)

_disc_line = "".join(_disc_out).strip()
check("helper: lgsm-discover emits a FOUND line for an installed instance",
      _disc_line.startswith("FOUND|"), repr(_disc_line[:120]))
_disc_parts = _disc_line.split("|")
check("helper: lgsm-discover emits the 8 fields ssh_manager splits on",
      len(_disc_parts) >= 8, "%d fields: %r" % (len(_disc_parts), _disc_line[:120]))
if len(_disc_parts) >= 8:
    eq("helper: lgsm-discover reports the user", _disc_parts[1], "csgoserver")
    eq("helper: lgsm-discover reports the instance", _disc_parts[2], "csgoserver")
    eq("helper: lgsm-discover reads the port out of the .cfg", _disc_parts[3], "27015")
    eq("helper: lgsm-discover counts only archive backups, not notes.txt", _disc_parts[4], "2")
    eq("helper: lgsm-discover counts installed mods", _disc_parts[5], "2")

# ── The backup download DROPS privilege; it must never read as root ────────────────────────────
# `sudo -u <user> cat` got one thing exactly right: the read happened as the GAME user, so a
# symlink planted at that path could only reach what that user could already read. Moving it behind
# a root helper is a privilege reduction ONLY if that property survives — read it as root instead
# and a download button becomes "hand me any file on the box".
_gbr = open(os.path.join(_root, "tools", "panel-helper"), encoding="utf-8").read()
_gbr_fn = _gbr[_gbr.index("def do_game_backup_read"):]
_gbr_fn = _gbr_fn[:_gbr_fn.index("\ndef ", 1)]
for _need, _why in (("os.setgroups([])", "supplementary groups are cleared"),
                    ("os.setgid(pw.pw_gid)", "gid is dropped"),
                    ("os.setuid(pw.pw_uid)", "uid is dropped")):
    check("helper: game-backup-read %s" % _why, _need in _gbr_fn, _need)
check("helper: game-backup-read drops the gid BEFORE the uid (the reverse cannot work)",
      _gbr_fn.index("os.setgid(") < _gbr_fn.index("os.setuid("))
check("helper: game-backup-read verifies the drop took before opening anything",
      "os.getuid() != pw.pw_uid" in _gbr_fn
      and _gbr_fn.index("os.getuid() != pw.pw_uid") < _gbr_fn.index("open(path"))
check("helper: game-backup-read opens the file only in the CHILD, after the drop",
      _gbr_fn.index("os.fork()") < _gbr_fn.index("open(path"))

# ── The restore swap: staging location and destinations both come from root's config ──────────
# do_panel_restore takes ZERO arguments for the same reason do_panel_db_repair does, but the stakes
# are higher here: the copy targets are the panel's database AND both encryption keys. A verb that
# accepted a staging path would let a caller name a directory it cannot itself read (say
# /etc/ssl/private) and have root copy the contents somewhere it can.
_rst_conf = _helper.PANEL_CONF
try:
    import tempfile as _tf_rst
    _rst_dir = _tf_rst.mkdtemp()
    _rst_cfg = os.path.join(_rst_dir, "panel.conf")

    _helper.PANEL_CONF = os.path.join(_rst_dir, "absent.conf")
    check("helper: restore refuses with no data_dir configured",
          _helper.do_panel_restore([], None) == 1)

    for _bad in ("relative/data", os.path.join(_rst_dir, "not-a-dir")):
        with open(_rst_cfg, "w", encoding="utf-8") as _fh:
            _fh.write("data_dir=%s\n" % _bad)
        _helper.PANEL_CONF = _rst_cfg
        check("helper: restore refuses data_dir %r" % _bad,
              _helper.do_panel_restore([], None) == 1)

    # A real data_dir but nothing staged must refuse too — otherwise a stray call would stop the
    # panel, copy nothing, and start it again for no reason.
    _real = os.path.join(_rst_dir, "data")
    os.makedirs(_real, exist_ok=True)
    with open(_rst_cfg, "w", encoding="utf-8") as _fh:
        _fh.write("data_dir=%s\n" % _real)
    _helper.PANEL_CONF = _rst_cfg
    check("helper: restore refuses when nothing is staged",
          _helper.do_panel_restore([], None) == 1)
finally:
    _helper.PANEL_CONF = _rst_conf

check("helper: the restore staging directory is a fixed NAME, not a caller argument",
      _helper.RESTORE_STAGE == ".restore-stage"
      and _helper.VERBS["panel-restore"][0] == [])
check("helper: restore copies exactly the four known members",
      _helper.RESTORE_MEMBERS == ("panel.db", "config.json", "secret_key", "cred_key"))

# db_maintenance.repair must work from an explicit path — that is what lets a ROOT-OWNED copy run
# under the system interpreter without importing the panel's config out of the checkout.
check("db_maintenance: repair runs from an explicit path, no config import",
      "argv[2]" in open(os.path.join(_root, "db_maintenance.py"), encoding="utf-8").read())

# ── Every file in data/ that holds DB rows or keys is hardened ───────────────────────────────
# harden_data_permissions() covered the DB, its WAL/SHM pair, the config and both keys — but not
# data/panel.db.backup, the rolling known-good copy models._ensure_db_healthy refreshes on every
# healthy start, nor the panel.db.corrupt-* copies it moves aside. Both hold every password hash
# and every encrypted credential the live database does, and sqlite3.connect / shutil.copy2 create
# them at the process umask (0644 on a stock box). data/ is 0700 so this was defence in depth
# rather than exposure, but it was the one gap in a function whose whole job is not having one.
import tempfile as _tf
import stat as _st
import config as _cfgm
_hd_tmp = _tf.mkdtemp()
_hd_saved = (_cfgm.DATA_DIR, _cfgm.DB_PATH, _cfgm.CONFIG_FILE, _cfgm.SECRET_FILE, _cfgm.CRED_KEY_FILE)
try:
    from pathlib import Path as _P
    _cfgm.DATA_DIR = _P(_hd_tmp)
    _cfgm.DB_PATH = _P(_hd_tmp) / "panel.db"
    _cfgm.CONFIG_FILE = _P(_hd_tmp) / "config.json"
    _cfgm.SECRET_FILE = _P(_hd_tmp) / "secret_key"
    _cfgm.CRED_KEY_FILE = _P(_hd_tmp) / "cred_key"
    _hd_files = ("panel.db", "panel.db-wal", "panel.db-shm", "panel.db.backup",
                 "panel.db.corrupt-1700000000", "config.json", "secret_key", "cred_key")
    for _n in _hd_files:
        _fp = _P(_hd_tmp) / _n
        _fp.write_bytes(b"x")
        os.chmod(_fp, 0o644)
    _cfgm.harden_data_permissions()
    _hd_bad = [_n for _n in _hd_files
               if _st.S_IMODE(os.stat(os.path.join(_hd_tmp, _n)).st_mode) != 0o600]
    check("data perms: every sensitive file in data/ ends up 0600", not _hd_bad,
          "left readable: %s" % _hd_bad)
finally:
    (_cfgm.DATA_DIR, _cfgm.DB_PATH, _cfgm.CONFIG_FILE,
     _cfgm.SECRET_FILE, _cfgm.CRED_KEY_FILE) = _hd_saved
    import shutil as _sh
    _sh.rmtree(_hd_tmp, ignore_errors=True)

# ── The self-signed TLS key is created 0600, never written then chmod'd ──────────────────────
# The old order wrote the unencrypted private key at the process umask and tightened it after,
# leaving a window in which it was world-readable.
import certs as _certs
_ck_tmp = _tf.mkdtemp()
try:
    _ck_cert = os.path.join(_ck_tmp, "ssl", "cert.pem")
    _ck_key = os.path.join(_ck_tmp, "ssl", "key.pem")
    _certs._ensure_self_signed_cert(_ck_cert, _ck_key, "probe.invalid")
    check("tls: the generated private key is 0600",
          _st.S_IMODE(os.stat(_ck_key).st_mode) == 0o600,
          "mode %o" % _st.S_IMODE(os.stat(_ck_key).st_mode))
    check("tls: ...and it is created that way, not chmod'd afterwards",
          "os.open(key_path" in open(os.path.join(_root, "certs.py"), encoding="utf-8").read())
finally:
    _sh.rmtree(_ck_tmp, ignore_errors=True)

# ── The Codacy accepted-errors list is a reviewable list, not a dumping ground ────────────────
# .github/codacy-accepted-errors.json is what stops the "Error-level Codacy issues on main" gate
# failing — so an entry added without a reason is a silent permanent suppression, which is the
# state that gate exists to end. Every entry needs all four fields and a real reason.
_acc_path = os.path.join(_root, ".github", "codacy-accepted-errors.json")
check("codacy: the accepted-errors list exists", os.path.isfile(_acc_path))
if os.path.isfile(_acc_path):
    _acc = json.load(open(_acc_path, encoding="utf-8"))
    _entries = _acc.get("accepted", [])
    _bad = []
    for _e in _entries:
        _missing = [_k for _k in ("filePath", "patternId", "lineText", "reason", "acceptedOn")
                    if not (_e.get(_k) or "").strip()]
        if _missing:
            _bad.append("%s: missing %s" % (_e.get("filePath", "?"), ",".join(_missing)))
        elif len((_e.get("reason") or "").split()) < 12:
            # A one-liner like "false positive" is not a review. Make the bar explicit.
            _bad.append("%s: reason is too short to be a review" % _e.get("filePath"))
    check("codacy: every accepted Error carries a full key and a real reason", not _bad,
          "; ".join(_bad))
    check("codacy: the accepted list is short enough to actually read",
          len(_entries) <= 5, "%d entries — it is meant to shrink" % len(_entries))
    # Keyed on the source LINE, never the line number: a number moves with every edit above it,
    # and one (file, rule) pair covers every hit of that rule in the file — which is how the first
    # draft of this list silently accepted a second, unrelated finding in system_ops.py.
    check("codacy: entries are keyed on the source line, not a line number",
          all("lineNumber" not in _e for _e in _entries) and all("lineText" in _e for _e in _entries))
    _gate = os.path.join(_root, ".github", "scripts", "codacy_open_errors.py")
    check("codacy: the gate script is present and referenced by its workflow",
          os.path.isfile(_gate)
          and "codacy_open_errors.py" in open(
              os.path.join(_root, ".github", "workflows", "codacy-alerts.yml"),
              encoding="utf-8").read())

# ── The docs state numbers that the code owns — pin them ──────────────────────────────────────
# Every one of these was wrong at the time of writing, and none of them could be. SECURITY.md said
# "43 verbs" against 86; the CHANGELOG said 77 in the same release; README advertised 18 alert
# events against 19, and listed `super_admin` as a grantable permission two years after it stopped
# being one. Prose does not enforce itself, so the numbers get gates like everything else.
_sec = open(os.path.join(_root, "SECURITY.md"), encoding="utf-8").read()
_readme = open(os.path.join(_root, "README.md"), encoding="utf-8").read()

check("docs: SECURITY.md states the real verb count",
      "%d verbs" % len(_privmod.verbs()) in _sec,
      "table has %d; SECURITY.md says %s"
      % (len(_privmod.verbs()),
         (re.search(r"(\d+) verbs", _sec) or ["?", "?"])[1]))
check("docs: README states the real number of alert events",
      "%d events" % len(N.EVENTS) in _readme,
      "EVENTS has %d; README says %s"
      % (len(N.EVENTS), (re.search(r"for (\d+) events", _readme) or ["?", "?"])[1]))
# The systemd unit list in SECURITY.md must name every unit the verb table actually accepts.
check("docs: SECURITY.md's systemd unit list matches privileged.UNITS",
      all(("`%s`" % _u) in _sec for _u in _privmod.UNITS),
      "missing from the doc: %s" % [_u for _u in _privmod.UNITS if ("`%s`" % _u) not in _sec])
# super_admin is the is_superadmin FLAG, not a permission. Documenting it as grantable sends an
# operator looking for a tickbox that was deliberately removed.
import auth as _authmod
check("docs: README does not offer super_admin as a grantable permission",
      "| `super_admin` |" not in _readme)
check("docs: ...and it really is not one", "super_admin" not in _authmod.ALL_PERMISSIONS)

# Every fuzz harness must be listed in its README and run by the workflow matrix. The README
# documented 4 of 6 (console and cron were missing), which is how a target quietly stops being
# maintained.
_fuzz_dir = os.path.join(_root, "tests", "fuzz")
_harnesses = sorted(os.path.basename(f)[len("fuzz_"):-len(".py")]
                    for f in glob.glob(os.path.join(_fuzz_dir, "fuzz_*.py")))
_fuzz_readme = open(os.path.join(_fuzz_dir, "README.md"), encoding="utf-8").read()
check("docs: every fuzz harness is listed in tests/fuzz/README.md",
      all(("fuzz_%s.py" % t) in _fuzz_readme for t in _harnesses),
      "missing: %s" % [t for t in _harnesses if ("fuzz_%s.py" % t) not in _fuzz_readme])
_fuzz_wf = open(os.path.join(_root, ".github", "workflows", "fuzz.yml"), encoding="utf-8").read()
_matrix = re.search(r"target:\s*\[([^\]]+)\]", _fuzz_wf)
_matrix_targets = sorted(t.strip() for t in _matrix.group(1).split(",")) if _matrix else []
check("docs: the fuzz workflow matrix runs every harness", _matrix_targets == _harnesses,
      "matrix=%s harnesses=%s" % (_matrix_targets, _harnesses))
# ...and each harness's own module must be in the workflow's path filter, or a change to the code
# it tests does not trigger it. terminal.py (fuzz_console's target) was missing for exactly that
# reason.
for _mod in ("ssh_manager.py", "system_ops.py", "terminal.py"):
    check("docs: the fuzz workflow watches %s" % _mod, ("'%s'" % _mod) in _fuzz_wf)

# ── ufw_allow_tailscale builds a VERB, and does not raise ─────────────────────────────────────
# It read `_run("ufw-allow-iface", [iface], timeout=15)` — _run's signature is
# (cmd, timeout=30, sudo=False, text=True), so the list went in as the positional `timeout` AND
# timeout=15 came in by keyword: TypeError on every single call, 100% of the time. The route
# answered 500, and the two automatic callers in tailscale_integration (after `tailscale up`, and
# during Serve setup) swallow exceptions — so the guard whose whole purpose is "don't let UFW lock
# you out of your own tailnet" had silently not run since the verb conversion.
_uat_calls = []
_uat_saved = (SO._run_verb, SO.detect_tailscale_interface)
try:
    SO.detect_tailscale_interface = lambda: "tailscale0"
    SO._run_verb = lambda verb, args=(), timeout=30, merge_stderr=True: (
        _uat_calls.append((verb, list(args))), ("", "", 0))[1]
    _uat_ok, _uat_msg = SO.ufw_allow_tailscale()
    check("ufw_allow_tailscale: does not raise (it used to TypeError on every call)", _uat_ok is True,
          str(_uat_msg))
    check("ufw_allow_tailscale: goes through the verb table, not a shell string",
          _uat_calls == [("ufw-allow-iface", ["tailscale0"])], str(_uat_calls))
finally:
    SO._run_verb, SO.detect_tailscale_interface = _uat_saved
# ...and the verb it names really exists, so a rename cannot leave it calling a dead one.
check("ufw_allow_tailscale: the verb it calls is in the table",
      "ufw-allow-iface" in _privmod.verbs())

# ── X-Forwarded-Prefix is only believed from a proxy we have reason to trust ──────────────────
# PrefixMiddleware read the header unconditionally, on every request, with the panel able to bind
# 0.0.0.0. SCRIPT_NAME is what every url_for() and every outgoing Location is built from, so any
# client could rewrite the links in its own response — including to a protocol-relative "//host".
# auth.client_ip() has always applied exactly this rule to X-Forwarded-For; this brings the other
# forwarded header in line.
import middleware as _mw
# ...and the middleware must actually CONSULT it — the helper passing on its own proves nothing
# if __call__ still reads the header unconditionally.
_mw_src = open(os.path.join(_root, "middleware.py"), encoding="utf-8").read()
_mw_call = _mw_src[_mw_src.index("def __call__"):]
check("prefix header: __call__ gates the header read on _may_trust_header",
      "_may_trust_header" in _mw_call
      and _mw_call.index("_may_trust_header") < _mw_call.index("if not prefix"))
for _ra, _cfg, _want in (("127.0.0.1", {}, True), ("::1", {}, True),
                         ("203.0.113.7", {}, False), ("10.1.2.3", {}, False),
                         ("", {}, False),
                         ("203.0.113.7", {"trust_proxy": True}, True)):
    check("prefix header: REMOTE_ADDR=%r trust_proxy=%s -> trusted=%s"
          % (_ra, bool(_cfg.get("trust_proxy")), _want),
          _mw.PrefixMiddleware._may_trust_header({"REMOTE_ADDR": _ra}, _cfg) is _want)

# ── The installer refreshes the root-owned helper on an UPDATE, not only a fresh install ──────
# The helper/db_maintenance/panel.conf/installer block used to sit AFTER the update path's
# `exit 0`, so every update — in-panel self-update, the CI auto-deploy, a plain re-run — shipped
# new code against whatever helper first landed on the host. The verb table grows most releases and
# a stale helper answers a new verb with `unknown verb` + rc 2 and no fallback, so the feature
# behind it stopped working with no message anywhere. The grant was never re-evaluated either.
_inst = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: the root-owned tools are installed by a FUNCTION, callable from both paths",
      "install_root_tools() {" in _inst and "write_sudoers_grant() {" in _inst)
_upd = _inst[_inst.index("if [ \"${IS_UPDATE}\" -eq 1 ]; then"):]
_upd_body = _upd[:_upd.index("    # ── Health check FAILED")]
check("install.sh: the UPDATE path refreshes the root-owned helper before restarting the service",
      "install_root_tools" in _upd_body
      and _upd_body.index("install_root_tools") < _upd_body.index('info "[5/6] Starting the service'))
check("install.sh: the UPDATE path also re-evaluates the sudoers grant",
      "write_sudoers_grant" in _upd_body)
check("install.sh: the update path still exits before the fresh-install steps",
      "    exit 0\n" in _upd_body)
# The root-owned installer copy must come from the CHECKOUT: the documented quick install is
# `curl … | bash`, where "$0" is the shell — the old form copied /usr/bin/bash into place.
check("install.sh: the root-owned installer copy is sourced from the checkout, not \"$0\"",
      'INSTALLER_SRC="${PANEL_DIR}/install.sh"' in _inst)

# ── Disabling Tailscale Serve removes the mount it is actually ON ─────────────────────────────
# disableServe() hardcoded mount:'/'. `tailscale serve --remove /` exits 0 on a node whose mapping
# is at /lgsm-panel, so the panel reported success, cleared tailscale_setup_done and
# tailscale_mount, and left Serve running — with PrefixMiddleware then no longer prefixing URLs
# for a panel still served under the prefix.
_ts_tpl = open(os.path.join(_root, "templates", "tailscale.html"), encoding="utf-8").read()
check("tailscale.html: disableServe does not hardcode the mount",
      "action: 'disable', mount: '/'" not in _ts_tpl)
check("tailscale.html: the Disable button carries the configured mount",
      'data-mount="{{ config.tailscale_mount' in _ts_tpl)
check("tailscale.html: the Mount Point field shows the configured mount, not a fixed /",
      "value=\"{{ config.tailscale_mount or '/' }}\"" in _ts_tpl)
# Both serve handlers take the clicked button; enableServe used the implicit global `event`.
check("tailscale.html: enableServe/disableServe receive @self rather than reading global event",
      "var btn = event.target" not in _ts_tpl
      and _ts_tpl.count("""data-args='["@self"]'""") >= 2)

# ── Vendored front-end libraries match their manifest ─────────────────────────────────────────
# static/vendor/ holds ~650KB of third-party browser code: Bootstrap, its icons, Chart.js and the
# Socket.IO client. Nothing was managing any of it — Dependabot reads pip and github-actions, there
# is no package.json, and no scanner looks inside a minified bundle. The result was that Bootstrap's
# JS sat at 5.3.0 while its CSS was 5.3.3 for months with nothing able to notice.
#
# static/vendor/VERSIONS.md is the manifest. This asserts it is true: every listed file exists, and
# the version recorded for it is the version in that file's own banner comment. A bump is then a
# deliberate edit to both, and a silent swap fails the build.
_vendor_dir = os.path.join(_root, "static", "vendor")
_manifest = os.path.join(_vendor_dir, "VERSIONS.md")
check("vendor: the manifest exists", os.path.isfile(_manifest))
if os.path.isfile(_manifest):
    _rows = re.findall(r"^\|\s*([^|]+?)\s*\|\s*([0-9][0-9.]*)\s*\|\s*`([^`]+)`\s*\|",
                       open(_manifest, encoding="utf-8").read(), re.M)
    check("vendor: the manifest lists every vendored library", len(_rows) >= 5,
          "found %d rows" % len(_rows))
    # Every vendored .js/.css must appear in the manifest — a new one cannot be added unlisted.
    _on_disk = set()
    for _dirpath, _dirnames, _filenames in os.walk(_vendor_dir):
        for _fn in _filenames:
            if _fn.endswith((".js", ".css")):
                _on_disk.add(os.path.relpath(os.path.join(_dirpath, _fn), _vendor_dir))
    _listed = {r[2] for r in _rows}
    check("vendor: no vendored file is missing from the manifest",
          not (_on_disk - _listed), "unlisted: %s" % sorted(_on_disk - _listed))
    _bad = []
    for _name, _ver, _rel in _rows:
        _path = os.path.join(_vendor_dir, _rel)
        if not os.path.isfile(_path):
            _bad.append("%s: file missing (%s)" % (_name, _rel))
            continue
        # The banner comment is in the first few hundred bytes of every one of these builds.
        with open(_path, encoding="utf-8", errors="replace") as _fh:
            _head = _fh.read(600)
        if _ver not in _head:
            _found = re.search(r"v?(\d+\.\d+\.\d+)", _head)
            _bad.append("%s: manifest says %s, file says %s"
                        % (_name, _ver, _found.group(1) if _found else "?"))
    check("vendor: every file is the version the manifest records", not _bad, "; ".join(_bad))
    # Bootstrap ships its JS and CSS as one release but they are vendored as two files, so they
    # can drift — and did, 5.3.0 JS against 5.3.3 CSS, for months. They were API-compatible so
    # nothing looked broken, which is exactly why nobody caught it. Require them to agree.
    _js = [r for r in _rows if r[0].strip() == "Bootstrap (JS)"]
    _css = [r for r in _rows if r[0].strip() == "Bootstrap (CSS)"]
    check("vendor: Bootstrap's JS and CSS are the same release",
          _js and _css and _js[0][1] == _css[0][1],
          "JS %s vs CSS %s — they ship together and must be vendored together"
          % (_js[0][1] if _js else "?", _css[0][1] if _css else "?"))

passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if results and passed == len(results) else 1)
