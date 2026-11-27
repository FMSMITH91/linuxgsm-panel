"""The B3 add-on's service interface: what the panel reads from B3 and how it talks to it.

The pinned B3 (addons.B3_COMMIT, its README "Running B3 as a service") gives a program running as the
same account:

- `b3_run.py --check-config -c b3.ini`: "OK: <file>" and exit 0, or one "ERROR: <reason>" line per
  problem (the first is the main one) and exit 230. Settings Apply runs it, in the image that will run,
  on the new files before anything is moved into place (check_sh); a refusal changes and restarts nothing.
- fixed exit codes (b3/exitcodes.py): EXIT_REASONS says each in words on the card. The unit doesn't
  restart on 222 and 230 (addons.CATALOG's "no_restart").
- health.json (mode 0640, rewritten every health_interval seconds, default 60): the card's health
  lines. Older than two intervals while the unit runs means B3 is hung. A read that failed, or a file
  that is not B3's JSON, is no measurement: the card then shows no health line at all, never "healthy"
  and never "not answering".
- the control socket (`control_socket: @conf/b3.sock` in [b3], written only while Panel actions is on):
  /data/b3.sock, 0600, and B3 checks the caller's uid. One JSON line per connection, at most 4096 bytes.
  The panel connects from inside B3's own container (`podman exec`, as the account with keep-id), so the
  host needs no client program; the request travels on stdin, never on a command line (a reason may name
  a player). The panel sends `actor` ("panel:<username>"), which B3 logs and never uses to grant
  anything: who may act is decided by the panel (routes/addons_b3.py).
- a plugin reload without a restart (SIGHUP, or the socket's reload_plugins): {reloaded, failed}.

Every value read from the host is bounded and type-checked before it reaches a page (Input Validation
Cheat Sheet: "Parse Safely, Then Validate").
"""
import base64
import json
import re
import shlex
import unicodedata
from datetime import datetime, timezone

from panel.core import i18n
from panel.services import addons as _ad

SOCKET_LINE = "@conf/b3.sock"       # [b3] control_socket while Panel actions is on: /data/b3.sock inside
SOCKET_PATH = "/data/b3.sock"
REQUEST_MAX = 4096                  # B3 refuses a longer request (too_large)
REPLY_MAX = 65536
REASON_MAX = 100                    # B3's own limit on a reason
ACTOR_MAX = 64                      # B3's own limit on `actor`
CLIENT_ID_MAX = 2 ** 31 - 1         # B3 takes 0 < client_id < 2**31
HEALTH_DEFAULT = 60                 # B3's default health_interval
HEALTH_MIN = 5                      # B3 never writes it more often
PURGE_MIN, PURGE_MAX = 1, 3650      # purge_aliases_days the card accepts (empty: off)
PURGE_EXAMPLE = 365
CHECK_INVALID = 230                 # --check-config's exit code for invalid settings
RELOAD_WAIT = 15                    # seconds a SIGHUP reload is given to write its result

# B3's exit code -> what the card says once the unit has stopped with it.
EXIT_REASONS = {
    220: "B3 stopped on an error (exit code 220). Its log says why.",
    221: "B3 stopped to restart itself (exit code 221: an admin's !restart in the game).",
    222: "B3 was shut down from the game (exit code 222: an admin's !die). It stays stopped until you start it.",
    223: "B3 stopped on an unexpected error while starting (exit code 223). Its log says why.",
    230: "B3's settings are invalid (exit code 230), so it stays stopped. Its log names the setting: fix it in "
         "b3.ini or its conf folder, then start it.",
    231: "B3 can't read the game's log (exit code 231). Start the game server so it writes one, then start B3.",
    232: "B3 couldn't set up RCON to the game (exit code 232). Its log says why.",
    233: "B3 couldn't reach its database when it started (exit code 233). It tries again every 30 seconds.",
}
S_STALE = "B3 is not answering: its health file was last written {minutes} minutes ago."
S_INVALID = "B3 refused the new settings, so nothing was changed or restarted. Its reason is below."
S_CHECK_FAILED = ("Couldn't run B3's settings check on this host, so nothing was changed or restarted. "
                  "The check's last lines are below.")
S_RELOAD_KEPT = ("B3 reloaded its plugin settings but kept the previous ones for: {plugins}. It is still running; "
                 "its reasons are below.")
S_RELOAD_SILENT = ("B3 was asked to reload its plugin settings but didn't say within 15 seconds whether it did. It "
                   "is still running; its log says more.")

_SVC_KEYS = ("control_socket", "purge_aliases_days", "health_interval")
_SVC_SH_ERE = "^[[:space:]]*(%s)[[:space:]]*[:=]" % "|".join(_SVC_KEYS)
_SVC_RE = re.compile(r"^[ \t]*(%s)[ \t]*[:=][ \t]*([^\r\n;]*)" % "|".join(_SVC_KEYS), re.I | re.M)
_INT_RE = re.compile(r"[0-9]{1,6}\Z")
_SLOT_RE = re.compile(r"[0-9]{1,3}\Z")
_ISO_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_COMMIT_RE = re.compile(r"[0-9a-f]{7,40}\Z")
_VERSION_RE = re.compile(r"[0-9A-Za-z.+-]{1,24}\Z")
_TEXT_MAX = 200
# B3's own "off" words for a path setting (b3/control.py from_config).
_OFF = ("", "off", "no", "none", "false", "0")

# The client run inside B3's container: the request on stdin, the reply (one line) on stdout. Prints
# B3SOCK_NONE when there is no socket to connect to (Panel actions off, or B3 not listening yet).
_CLIENT = ("import socket,sys\n"
           "d=sys.stdin.buffer.read(%d)\n"
           "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
           "s.settimeout(10)\n"
           "try:\n s.connect(%r)\n"
           "except OSError:\n print('B3SOCK_NONE');sys.exit(3)\n"
           "s.sendall(d)\nb=b''\n"
           "while len(b)<%d:\n c=s.recv(4096)\n if not c:break\n b+=c\n"
           "sys.stdout.write(b.decode('utf-8','replace'))\n" % (REQUEST_MAX + 1, SOCKET_PATH, REPLY_MAX))
NO_SOCKET = "B3SOCK_NONE"
_ERROR_MARK = "ERROR: "            # --check-config's mark before each problem


# ── the card ─────────────────────────────────────────────────────────────────────────────────────
def exit_sentence(code):
    """The card's words for B3's exit code `code` (an int), or "" for 0, None or a code B3 doesn't define."""
    said = EXIT_REASONS.get(code) if isinstance(code, int) else None
    return i18n.Sentence(said) if said else ""


def status_sh(home_rel):
    """The status read's extra lines for an installed B3 (`home_rel`: its folder, relative to the home).

    b3health.b64= (health.json, at most 16 kB), b3exit= (the unit's last main exit status), b3svc.b64=
    (b3.ini's control_socket, purge_aliases_days and health_interval lines) and b3now= (the host's clock,
    so a health file's age is judged on the clock that wrote it).
    """
    data = shlex.quote(home_rel + "/Data")
    return ('echo "b3health.b64=$(head -c 16000 %s/health.json 2>/dev/null | base64 -w0)"; '
            'echo "b3exit=$(systemctl --user show -p ExecMainStatus --value %s.service 2>/dev/null | head -n 1)"; '
            'echo "b3svc.b64=$(grep -iE \'%s\' %s/b3.ini 2>/dev/null | head -c 2000 | base64 -w0)"; '
            'echo "b3now=$(date +%%s)"; '
            % (data, _ad.unit_name(_ad.B3), _SVC_SH_ERE, data))


def service_settings(ini_text):
    """B3's service settings in b3.ini's text: {actions: socket on, purge: days or None, health_interval: seconds}.

    The last line of a key wins, as ConfigParser reads a repeated key in strict=False mode; the keys are
    [b3]'s only, so their section is not looked for. A value that is not a number is B3's default.
    """
    got = {}
    for m in _SVC_RE.finditer(ini_text or ""):
        got[m.group(1).lower()] = m.group(2).strip()
    sock = got.get("control_socket", "")
    purge = got.get("purge_aliases_days", "")
    every = got.get("health_interval", "")
    return {"actions": sock.lower() not in _OFF,
            "purge": int(purge) if _INT_RE.fullmatch(purge) and int(purge) > 0 else None,
            "health_interval": max(HEALTH_MIN, int(every)) if _INT_RE.fullmatch(every) else HEALTH_DEFAULT}


def parse_status(kv, unb64):
    """B3's part of a status read (status_sh's lines in `kv`): {health, exit, svc, now}.

    health is None unless health.json held a JSON object of schema 1.
    """
    exit_text = kv.get("b3exit", "")
    now = kv.get("b3now", "")
    return {"health": _health_doc(unb64(kv.get("b3health.b64", ""))),
            "exit": int(exit_text) if _INT_RE.fullmatch(exit_text) else None,
            "svc": service_settings(unb64(kv.get("b3svc.b64", ""))),
            "now": int(now) if now.isascii() and now.isdecimal() and len(now) < 12 else None}


def _health_doc(text):
    try:
        doc = json.loads(text) if text else None
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == 1 else None


def _epoch(iso):
    """Seconds since the epoch for B3's "2026-11-19T17:27:49Z", or None."""
    if not isinstance(iso, str) or not _ISO_RE.fullmatch(iso):
        return None
    try:
        return int(datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        return None


def _text(value):
    """A short line of B3's own text for the card: printable, at most _TEXT_MAX characters; "" otherwise."""
    if not isinstance(value, str):
        return ""
    return "".join(c for c in " ".join(value.split()) if unicodedata.category(c)[0] != "C")[:_TEXT_MAX]


def _flag(part, key="ok"):
    """True, False or None (not known yet) from one of health.json's parts."""
    v = part.get(key) if isinstance(part, dict) else None
    return v if isinstance(v, bool) else None


def _count(part, key):
    v = part.get(key) if isinstance(part, dict) else None
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10000 else None


def _age(doc, now):
    """Seconds since health.json was written, on the host's clock; None when either time is not known."""
    written = _epoch(doc.get("written_at"))
    return None if written is None or now is None else now - written


def running_version(doc):
    """What B3 says runs ("2.0.2dev (7da5ac86)"), from health.json; "" when it doesn't say both.

    B3 built from the pinned commit is named by the pin's release label ("2.0.2 (7c3bbe8c)"): its source
    tree says the development number the release build replaces (addons.B3_RELEASE). Any other commit
    (an image not updated yet) is shown as B3 itself says.
    """
    b3 = (doc or {}).get("b3")
    b3 = b3 if isinstance(b3, dict) else {}
    version, commit = b3.get("version"), b3.get("commit")
    if not (isinstance(version, str) and _VERSION_RE.fullmatch(version)
            and isinstance(commit, str) and _COMMIT_RE.fullmatch(commit)):
        return ""
    if _ad.B3_COMMIT.startswith(commit):            # the full id, or the short one (7 or more)
        return _ad.CATALOG[_ad.B3]["version"]
    return "%s (%s)" % (version, commit[:8])


def card(b3st, state):
    """The B3 row's own fields from parse_status's `b3st` and the unit's state.

    health: the lines to show, or None (no measurement). stale_minutes: set while the unit runs and the
    file is older than two health intervals. exit_reason: while the unit is not running and its last exit
    is one of B3's codes. version: what B3 says runs, only when it says it (else the row keeps the
    installed image's version: the pin's label would name an update not made yet).
    """
    doc, svc = b3st.get("health"), b3st.get("svc") or service_settings("")
    fields = {"b3_card": True, "health": None, "stale_minutes": None, "exit_reason": "",
              "actions": svc["actions"], "purge_aliases_days": svc["purge"], "purge_example": PURGE_EXAMPLE,
              "purge_bounds": [PURGE_MIN, PURGE_MAX]}
    if state != "active":
        why = exit_sentence(b3st.get("exit"))
        fields["exit_reason"] = i18n.tr(why) if why else ""
    if doc is None:
        return fields
    ran = running_version(doc)
    if ran:
        fields["version"] = ran
    age = _age(doc, b3st.get("now"))
    if state == "active" and age is not None and age > 2 * svc["health_interval"]:
        fields["stale_minutes"] = max(1, age // 60)
        return fields
    if state == "active":
        fields["health"] = _health_lines(doc)
    return fields


def _health_lines(doc):
    """The card's health lines from a health.json document."""
    return {"healthy": doc.get("healthy") is True, "reason": _text(doc.get("reason")),
            "game_log": _flag(doc.get("game_log")), "rcon": _flag(doc.get("rcon")), "database": _flag(doc.get("database")),
            "humans": _count(doc.get("players"), "humans"), "bots": _count(doc.get("players"), "bots")}


def stale_sentence(minutes):
    """The card's "not answering" line."""
    return i18n.Sentence(S_STALE, minutes=minutes)


# ── settings Apply: the check, then a reload or a restart ────────────────────────────────────────
def check_sh(user, ids, geo_text, own_plugins):
    """Shell running B3's --check-config on the settings Apply is about to write, in the image that will run.

    The new b3.ini is Data/b3.ini.new when Apply rewrites it (written from stdin before this runs), else
    the current one; `geo_text` is plugin_geolocation.ini's new text (None: the current file). They are
    copied, with the conf folder, into a folder of their own, mounted read-only at /data in a container
    as locked down as the add-on's (no network, read-only, no capability, no new privileges, the
    account's own ids), with the own-plugins folder read-only over /data/extplugins when it is on (a
    plugin there is imported by the check). Exit 230 prints ADDON_CONFIG_INVALID and the first ERROR
    line (base64); any other failure ADDON_CHECK_FAILED and the output's tail. Either way b3.ini.new is
    removed and the shell exits, so nothing was moved into place and nothing restarts.
    """
    d = _ad.addon_dir(user, _ad.B3)
    data, stage, new = shlex.quote(d + "/Data"), shlex.quote(d + "/check"), shlex.quote(d + "/Data/b3.ini.new")
    geo = ("printf %%s %s | base64 -d > %s/conf/plugin_geolocation.ini && "
           % (shlex.quote(_ad._b64(geo_text)), stage)) if geo_text is not None else ""
    own = (" -v %s:/data/extplugins:ro" % shlex.quote(d + "/" + _ad.B3_OWN_PLUGINS)) if own_plugins else ""
    run = ("podman run --rm --pull=never --network=none --read-only --cap-drop=all "
           "--security-opt=no-new-privileges --userns=keep-id --user %d:%d --memory=%s --pids-limit=%d "
           "-v %s:/data:ro -v %s:/geoip:ro%s --entrypoint python %s /opt/b3/b3_run.py --check-config -c /data/b3.ini"
           % (int(ids[0]), int(ids[1]), _ad.MEMORY, _ad.PIDS, stage, shlex.quote(d + "/geoip"), own,
              shlex.quote(_ad.CATALOG[_ad.B3]["image"])))
    gone = "rm -f %s; rm -rf -- %s; " % (new, stage)
    # .b3: B3 makes its home (~/.b3, HOME=/data) when it is imported unless it is there; /data is read-only here.
    return ("rm -rf -- %s && mkdir -p %s/conf %s/extplugins %s/.b3 && { [ ! -d %s/conf ] || cp -a %s/conf/. %s/conf/; } && "
            "{ if [ -f %s ]; then cp %s %s/b3.ini; else cp %s/b3.ini %s/b3.ini; fi; } && %s"
            "co=$(%s 2>&1); cr=$?; rm -rf -- %s; "
            "if [ $cr -eq %d ]; then %secho ADDON_CONFIG_INVALID; printf '%%s\\n' \"$co\" | grep -m1 '^ERROR: ' "
            "| head -c 600 | base64 -w0 | sed 's/^/err.b64=/'; echo; exit 27; fi; "
            "if [ $cr -ne 0 ]; then %secho ADDON_CHECK_FAILED; printf '%%s\\n' \"$co\" | tail -n %d | tail -c 4000 "
            "| base64 -w0 | sed 's/^/tail.b64=/'; echo; exit 28; fi; "
            % (stage, stage, stage, stage, data, data, stage, new, new, stage, data, stage, geo,
               run, stage, CHECK_INVALID, gone, gone, _ad.TAIL_LINES))


def actor(username):
    """The `actor` B3 records for a panel user: "panel:<username>", printable, at most ACTOR_MAX characters."""
    name = "".join(c for c in str(username or "") if unicodedata.category(c)[0] != "C")
    return ("panel:" + name)[:ACTOR_MAX]


def request(cmd, args, who):
    """One request line for B3's control socket (at most REQUEST_MAX bytes, ending in a newline)."""
    line = json.dumps({"id": 1, "actor": actor(who), "cmd": cmd, "args": args}, separators=(",", ":"),
                      ensure_ascii=False) + "\n"
    if len(line.encode("utf-8")) > REQUEST_MAX:
        raise ValueError("request too large")
    return line


def socket_sh():
    """Shell sending stdin's request to B3's control socket from inside its container, printing B3's reply line."""
    return _ad._ENV + "podman exec -i %s python -c %s" % (_ad.unit_name(_ad.B3), shlex.quote(_CLIENT))


def reload_sh(user, who):
    """Shell for a plugin-only Apply: B3 reloads its plugin settings without a restart, then the shell exits 0.

    Only while the unit runs and b3.ini is not newer than the running start (a hand edit there needs the
    restart this shell then falls through to). Through the control socket when it is on (its
    reload_plugins answers {reloaded, failed}); else SIGHUP, and the config_reload line B3 then writes to
    events.jsonl. Prints ADDON_RELOADED and reload.b64= (the answer, "" when none came).
    """
    unit = _ad.unit_name(_ad.B3)
    ini = shlex.quote(_ad.addon_dir(user, _ad.B3) + "/Data/b3.ini")
    return ("st=$(systemctl --user show -p ExecMainStartTimestamp --value --timestamp=unix %s.service 2>/dev/null); "
            "st=${st#@}; if systemctl --user is-active -q %s.service && [ -n \"$st\" ] "
            "&& [ \"$(stat -c %%Y %s 2>/dev/null || echo 9999999999)\" -le \"$st\" ]; then "
            "%secho ADDON_RELOADED; %s"
            "echo; exit 0; fi; "
            % (unit, unit, ini, reload_core_sh(user, who), RELOAD_PRINT_SH))


# Prints the reload's answer ($r, set by reload_core_sh) as reload.b64= (the line is "reload.b64=" when none came).
RELOAD_PRINT_SH = "printf %s \"$r\" | head -c 20000 | base64 -w0 | sed 's/^/reload.b64=/'; "


def reload_core_sh(user, who):
    """Shell asking the running B3 to reload its plugin settings; sets $r to its answer ("" when none came).

    Through the control socket when b3.ini turns it on (its reload_plugins answers {reloaded, failed});
    else SIGHUP, then up to RELOAD_WAIT seconds for the config_reload line B3 writes to events.jsonl.
    Only for a B3 built from a commit that has the reload (since v2.0.2): to an older one, SIGHUP is the
    default action, the end of the process.
    """
    d = _ad.addon_dir(user, _ad.B3)
    ini, ev, unit = shlex.quote(d + "/Data/b3.ini"), shlex.quote(d + "/Data/events.jsonl"), _ad.unit_name(_ad.B3)
    last = "tail -c 65536 %s 2>/dev/null | grep -F '\"event\": \"config_reload\"' | tail -n 1" % ev
    sock = "printf %%s %s | %s 2>/dev/null" % (shlex.quote(request("reload_plugins", {}, who)),
                                               "podman exec -i %s python -c %s" % (unit, shlex.quote(_CLIENT)))
    return ("if grep -qiE '^[[:space:]]*control_socket[[:space:]]*[:=][[:space:]]*@conf/b3\\.sock[[:space:]]*$' %s; "
            "then r=$(%s); else b=$(%s); podman kill --signal HUP %s >/dev/null 2>&1; r=; i=0; "
            "while [ $i -lt %d ]; do sleep 1; i=$((i + 1)); r=$(%s); [ -n \"$r\" ] && [ \"$r\" != \"$b\" ] && break; "
            "r=; done; fi; "
            % (ini, sock, last, unit, RELOAD_WAIT, last))


def reload_answered(text):
    """Whether `text` (reload.b64='s answer) is B3's report of a plugin reload: the reload happened."""
    return _reload_answer(text) is not None


def _reload_answer(text):
    """({reloaded}, {failed}) from a reload's answer (the socket's reply or the config_reload line), or None."""
    line = (text or "").strip().splitlines()[-1:] or [""]
    try:
        doc = json.loads(line[0])
    except ValueError:
        return None
    if isinstance(doc, dict) and isinstance(doc.get("result"), dict):
        doc = doc["result"] if doc.get("ok") is True else None
    if not isinstance(doc, dict) or not isinstance(doc.get("failed"), dict):
        return None
    return doc.get("reloaded") if isinstance(doc.get("reloaded"), list) else [], doc["failed"]


def change_outcome(out, rc, secrets):
    """(handled, why or "", tail) for a settings Apply's own marks; handled False leaves it to install_outcome.

    `secrets` are masked in what B3 printed (an ERROR line can quote a line of b3.ini).
    """
    kv = _ad.kv_lines(out)
    if "ADDON_CONFIG_INVALID" in (out or ""):
        return True, S_INVALID, _first_error(kv, secrets)
    if "ADDON_CHECK_FAILED" in (out or ""):
        return True, S_CHECK_FAILED, _ad.scrub(_ad._unb64(kv.get("tail.b64", "")), secrets)
    if rc == 0 and "ADDON_RELOADED" in (out or ""):
        return (True,) + _reload_outcome(_ad._unb64(kv.get("reload.b64", "")), secrets)
    return False, "", ""


def _first_error(kv, secrets):
    """B3's first ERROR line (err.b64=), its passwords masked and without its "ERROR: " mark."""
    error = _ad.scrub(_ad._unb64(kv.get("err.b64", "")).strip(), secrets)
    return error[len(_ERROR_MARK):] if error.startswith(_ERROR_MARK) else error


def _reload_outcome(answer, secrets):
    """(why or "", tail) for a reload's answer: a plugin that kept its old settings is named, no answer is said."""
    got = _reload_answer(answer)
    if got is None:
        return S_RELOAD_SILENT, ""
    failed = {str(k)[:64]: _text(v) for k, v in list(got[1].items())[:20]}
    if not failed:
        return "", ""
    tail = "\n".join("%s: %s" % item for item in sorted(failed.items()))
    return i18n.Sentence(S_RELOAD_KEPT, plugins=", ".join(sorted(failed))), _ad.scrub(tail, secrets)


# ── the control socket's commands ────────────────────────────────────────────────────────────────
def clean_reason(value, required=False):
    """A reason B3 takes (at most REASON_MAX characters, no control character or line break, no colour code `^`).

    -> the reason (trimmed; "" for none), or None when it is not one (or missing while `required`).
    """
    text = value.strip() if isinstance(value, str) else (None if value is not None else "")
    if text is None or len(text) > REASON_MAX or "^" in text or any(unicodedata.category(c) in ("Cc", "Zl", "Zp")
                                                                   for c in text):
        return None
    return None if required and not text else text


def slot(value):
    """A player's slot as B3 takes it (a short string of digits), or None."""
    text = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
    return text if isinstance(text, str) and _SLOT_RE.fullmatch(text) else None


def reply(out, rc):
    """B3's reply to one request: ("ok", result dict), ("error", (code, message)), ("off", None) or ("down", None).

    "off": no control socket to reach (Panel actions off, or B3 not listening yet). "down": B3's container
    isn't running, or nothing JSON came back.
    """
    if NO_SOCKET in (out or ""):
        return "off", None
    doc = _last_json(out) if rc == 0 else None
    if not isinstance(doc, dict) or not isinstance(doc.get("ok"), bool):
        return "down", None
    if doc["ok"]:
        return "ok", doc.get("result") if isinstance(doc.get("result"), dict) else {}
    return "error", (str(doc.get("error") or "failed")[:32], _text(doc.get("message")))


def _last_json(out):
    """The last line of `out` read as JSON, or None."""
    line = (out or "").strip().splitlines()[-1:] or [""]
    try:
        return json.loads(line[0])
    except ValueError:
        return None


def b64(text):
    """Base64 of `text` (UTF-8), for a line the host decodes."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")
