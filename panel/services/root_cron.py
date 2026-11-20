"""Root's crontab on a host, for the panel owner's root cron page (panel/routes/root_cron.py).

A job here runs as root, so the page is guarded in layers, each read against an OWASP cheat sheet
(2026-11-17):
- Off by default (config.json `root_cron_enabled`), and only the panel owner may turn it on, see
  it or change it (Authorization Cheat Sheet: "Enforce Least Privileges", "Deny by Default",
  "Validate the Permissions on Every Request").
- On the panel's own host the root-owned helper also refuses both verbs unless the operator
  opened them at install (PANEL_ROOT_CRON=1, panel.conf `root_cron=yes`), so a panel account that
  is not root cannot become root through this page alone (privileged.py ROOT_CRON_*).
- Every change asks for the password (and the 2FA code) in the same request, not only after a
  sign-in window (Transaction Authorization Cheat Sheet 2.1, 2.4).
- Every change, refused or not, is an audit row naming the host and the old and new line (Logging
  Cheat Sheet, "Which events to log": administrative actions and their changes).
- No shell is built from what is typed (OS Command Injection Defense Cheat Sheet, "Defense
  option 3: parameterization" and "Layer 2: input validation"): the schedule is cron's own grammar,
  checked field by field; the command is one line with no control character, its `%` escaped so
  cron does not cut it into standard input (stored_command); the whole file is checked again by the
  helper (or, on a remote, by privileged.py before it is sent base64) and installed with `crontab -u root -`.
  The command itself is root code by design: that is the feature, and why the layers above exist.
- Root's crontab is replaced only while it still hashes to what the page showed, so a change made
  meanwhile (from a shell, or another tab) is never overwritten unseen.
"""
import base64
import binascii
import hashlib
import os
import re

from panel.core import i18n
from panel.core.config import config_value, update_config
from panel.security import privileged as _priv

ENABLED_KEY = "root_cron_enabled"
COMMAND_MAX = 1000
# The /etc/cron.d files the panel writes itself (privileged.WRITE_TARGETS' node-tools-cron and the
# GMod content box's per-account update), marked on the page as the panel's.
PANEL_CROND = ("lgsm-node-tools",)
PANEL_CROND_PREFIXES = ("lgsm-gmod-content",)
_CONF = os.path.join(os.path.dirname(_priv.HELPER_PATH), "panel.conf")

NOT_OPENED = ("Root's crontab on this host was not opened to the panel at install. To allow it, run "
              "the installer again with PANEL_ROOT_CRON=1 (sudo PANEL_ROOT_CRON=1 bash install.sh).")
CHANGED = "Root's crontab changed since this page read it, so nothing was saved. Look again and redo the change."
UNREADABLE = "Root's crontab could not be read on this host."
NOT_SAVED = "Root's crontab could not be saved on this host."
BAD_LINE = ("Line {n} of root's crontab is not a cron job, a variable, a comment or a blank line, so the "
            "panel will not save it. Fix that line from a shell first.")
TOO_BIG = "Root's crontab would be too long after this change (at most 1,000 lines and 64 KiB)."
UNKNOWN = "Unknown change."
TWO_BACKSLASHES = ("The command has two backslashes in a row, which cron on Debian and Ubuntu reads as one and "
                   "other crons as two, so it cannot be saved as typed. Change it from a shell.")


def enabled():
    """Whether the owner has turned the root cron page on (off unless config.json holds exactly true)."""
    return config_value(ENABLED_KEY, False) is True


def set_enabled(on):
    """Turn the root cron page on or off."""
    def _mut(cfg):
        cfg[ENABLED_KEY] = bool(on)
    update_config(_mut)


def host_opened(is_local, helper_present):
    """Whether the helper on this host lets the panel at root's crontab, as far as the panel can tell.

    A remote has no helper (the panel is root there by design), and a panel host without one falls
    back to its wide grant: both yes. With the helper, panel.conf (root-owned, world-readable)
    says, as the helper reads it.
    """
    if not is_local or not helper_present:
        return True
    try:
        with open(_CONF, encoding="utf-8") as fh:
            for line in fh:
                k, sep, v = line.strip().partition("=")
                if sep and k.strip() == _priv.ROOT_CRON_CONF_KEY:
                    return v.strip() == "yes"
    except OSError:
        return False
    return False


def _b64(text):
    try:
        return base64.b64decode(text, validate=True).decode("utf-8", "surrogateescape")
    except (binascii.Error, ValueError):
        return None


def parse_read(out):
    """root-crontab-read's output -> {"state": "ok"|"none"|"", "text", "crond": [{name, text, panel}]}.

    "" state when the output is not the verb's format (a refusal, an error, nothing).
    """
    got = {"state": "", "text": "", "crond": []}
    for line in (out or "").splitlines():
        _read_line(got, line.split(" "))
    return got


def _read_line(got, parts):
    """Fold one line of root-crontab-read's output, split on spaces, into `got`."""
    body = _b64(parts[2]) if len(parts) == 3 else ("" if len(parts) == 2 else None)
    if body is None:
        return
    head = tuple(parts[:2])
    if head == ("root-crontab", "none") and len(parts) == 2:
        got["state"] = "none"
    elif head == ("root-crontab", "ok"):
        got.update(state="ok", text=body)
    elif parts[0] == "crond" and re.fullmatch(_priv.ROOT_CRON_DIR_FILE_RE, parts[1]):
        got["crond"].append({"name": parts[1], "text": shown(body), "panel": is_panel_file(parts[1])})


def shown(text):
    """`text` fit for the page: each byte that is not UTF-8 (a surrogate from _b64) shown as U+FFFD.

    The page is sent as strict UTF-8, so one such byte (a Latin-1 comment, a file cut mid-character
    at its size cap) made the whole page a 500. Only for display: the digest and the write path keep
    the bytes as read.
    """
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def is_panel_file(name):
    """Whether /etc/cron.d/`name` is one the panel writes itself."""
    return name in PANEL_CROND or name.startswith(PANEL_CROND_PREFIXES)


def digest(text):
    """The SHA-256 hex of root's crontab as read: what root-crontab-write compares against."""
    return hashlib.sha256((text or "").encode("utf-8", "surrogateescape")).hexdigest()


# How cron reads a job's command (crontab(5); do_command.c): the first `%` not escaped by a backslash ends
# the command and what follows is its standard input, and `\%` is a `%`. The two crons differ on `\\`:
# Debian's and Ubuntu's (3.0pl1, the cron install.sh installs) read it as one backslash, cronie as two.
# The page stores and shows only what both read the same: no `\\`, and a `%` after one backslash at most.


def cron_reads(raw):
    r"""(the command cron runs, its standard input or None) for a job's command text; None when crons disagree.

    None for text holding `\\`, which the crons read differently (above). Otherwise `\%` is a `%`, a
    backslash before anything else is kept, and the first bare `%` ends the command: the rest is the
    command's standard input, each further bare `%` a new line in it.
    """
    if "\\\\" in raw:
        return None
    pieces = raw.split("\\%")
    cut = next((i for i, piece in enumerate(pieces) if "%" in piece), None)
    if cut is None:
        return "%".join(pieces), None
    head, _bare, tail = pieces[cut].partition("%")
    return "%".join(pieces[:cut] + [head]), "%".join(p.replace("%", "\n") for p in [tail] + pieces[cut + 1:])


def stored_command(typed):
    r"""The command for the crontab line, so cron runs what was typed: each bare `%` escaped as `\%`.

    An unescaped `%` is a newline to cron, and what follows the first one goes to the command's
    standard input; escaping keeps what was typed one command, as typed. A `%` typed after a
    backslash is already cron's escape (`date +\%F`, as crontabs write it) and is kept: cron hands
    the shell `%`, and the page shows that. Escaping it again made `\\%`, a backslash and then a bare
    `%`, so root's job was cut there while the page showed the command as typed (review 1121 A04).
    Text with `\\` is refused before this (job_line).
    """
    return "\\%".join(piece.replace("%", "\\%") for piece in typed.split("\\%"))


def rows(text):
    r"""Each line of root's crontab as {n, kind, raw, schedule, command, mixed, stdin}; kind as root_cron_line_kind.

    `command` is what cron runs; `stdin` what cron gives it as standard input (text after a bare `%`),
    else None; `mixed` that the command holds `\\`, which crons read differently, so `command` is the
    line's own text. A job with either is shown, and may be deleted, but not edited here: saving it
    would change what it runs.

    A line holding a byte that is not UTF-8 is "other", shown with U+FFFD in its place (shown): it can't
    go back through the page's form as it was read, so it is never offered for edit or delete.
    """
    out = []
    for n, line in enumerate((text or "").split("\n")[:-1] if text else [], 1):
        readable = shown(line) == line
        kind = _priv.root_cron_line_kind(line) if readable else None
        row = {"n": n, "kind": kind or "other", "raw": line if readable else shown(line), "schedule": "",
               "command": "", "mixed": False, "stdin": None}
        if kind == "job":
            row.update(_job_fields(line))
        out.append(row)
    return out


def _job_fields(line):
    """A job line's schedule, command, mixed and stdin, as rows() shows them."""
    s = line.strip(" \t").replace("\t", " ")
    if s.startswith("@"):
        sched, _sep, cmd = s.partition(" ")
    else:
        fields = s.split(None, 5)
        sched, cmd = " ".join(fields[:5]), fields[5]
    got = cron_reads(cmd.strip(" "))
    return {"schedule": sched, "command": cmd.strip(" ") if got is None else got[0], "mixed": got is None,
            "stdin": None if got is None else got[1]}


def schedule_ok(schedule):
    """Whether `schedule` (spaces collapsed) is five cron fields or one @keyword."""
    if schedule.startswith("@"):
        return schedule in _priv.ROOT_CRON_SPECIALS
    fields = schedule.split(" ")
    return len(fields) == 5 and all(_priv.root_cron_field_ok(f, i) for i, f in enumerate(fields))


def job_line(schedule, command):
    """(the crontab line for `schedule` and `command`, "") or (None, why in fixed words)."""
    schedule = " ".join((schedule or "").split())
    command = (command or "").strip()
    if not command:
        return None, "Enter the command to run."
    if len(command) > COMMAND_MAX or not re.fullmatch(_priv.ROOT_CRON_TEXT_RE, command):
        return None, "The command must be one line of at most 1,000 characters, with no control characters."
    if "\\\\" in command:
        return None, TWO_BACKSLASHES
    if not schedule_ok(schedule):
        return None, ("The schedule must be five cron fields (minute hour day month weekday, such as "
                      "\"30 4 * * *\") or one of @reboot, @hourly, @daily, @weekly, @monthly, @yearly.")
    line = "%s %s" % (schedule, stored_command(command))
    if _priv.root_cron_line_kind(line) != "job":
        return None, "That line is not a cron job."
    return line, ""


def changed_text(text, op, n, was, line):
    """(root's crontab after `op`, "") or (None, why).

    op "add" appends `line`; "save" replaces line `n`, and "delete" removes it, each only while that
    line still reads `was` (the page's copy), so a line that moved is never the one changed.
    """
    lines = (text or "").split("\n")[:-1] if text else []
    why = _edit(lines, op, n, was, line)
    if why:
        return None, why
    new = "\n".join(lines) + "\n" if lines else ""
    return (new, "") if not _priv.root_crontab_problem(new) else (None, _invalid(new))


def _edit(lines, op, n, was, line):
    """Apply `op` to `lines` in place; "" when done, else why not."""
    if op == "add":
        lines.append(line)
        return ""
    if op not in ("save", "delete"):
        return UNKNOWN
    if not 1 <= n <= len(lines) or lines[n - 1] != was:
        return CHANGED
    if op == "save":
        lines[n - 1] = line
    else:
        del lines[n - 1]
    return ""


def _invalid(new):
    """Why `new` is not a crontab the panel will install: the first bad line, or its size."""
    bad = next((r["n"] for r in rows(new) if r["kind"] == "other"), None)
    return TOO_BIG if bad is None else i18n.Sentence(BAD_LINE, n=bad)
