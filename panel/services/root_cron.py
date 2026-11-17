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
  cron does not cut it into standard input; the whole file is checked again by the helper (or, on
  a remote, by privileged.py before it is sent base64) and installed with `crontab -u root -`.
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
        parts = line.split(" ")
        if parts[:2] == ["root-crontab", "none"] and len(parts) == 2:
            got["state"] = "none"
        elif parts[:2] == ["root-crontab", "ok"] and len(parts) in (2, 3):
            text = _b64(parts[2]) if len(parts) == 3 else ""
            if text is not None:
                got.update(state="ok", text=text)
        elif parts[0] == "crond" and len(parts) in (2, 3) and re.fullmatch(_priv.ROOT_CRON_DIR_FILE_RE, parts[1]):
            text = _b64(parts[2]) if len(parts) == 3 else ""
            if text is not None:
                got["crond"].append({"name": parts[1], "text": text, "panel": is_panel_file(parts[1])})
    return got


def is_panel_file(name):
    """Whether /etc/cron.d/`name` is one the panel writes itself."""
    return name in PANEL_CROND or name.startswith(PANEL_CROND_PREFIXES)


def digest(text):
    """The SHA-256 hex of root's crontab as read: what root-crontab-write compares against."""
    return hashlib.sha256((text or "").encode("utf-8", "surrogateescape")).hexdigest()


def shown_command(raw):
    r"""A job's command as cron runs it: `\%` is a literal `%` to cron, shown as one."""
    return raw.replace("\\%", "%")


def stored_command(typed):
    r"""The command as typed, for the crontab line: every `%` escaped as `\%`.

    An unescaped `%` is a newline to cron, and what follows the first one goes to the command's
    standard input; escaping keeps what was typed one command, as typed.
    """
    return typed.replace("%", "\\%")


def rows(text):
    """Each line of root's crontab as {n, kind, raw, schedule, command}; kind as privileged.root_cron_line_kind."""
    out = []
    for n, line in enumerate((text or "").split("\n")[:-1] if text else [], 1):
        kind = _priv.root_cron_line_kind(line)
        row = {"n": n, "kind": kind or "other", "raw": line, "schedule": "", "command": ""}
        if kind == "job":
            s = line.strip(" \t").replace("\t", " ")
            if s.startswith("@"):
                sched, _sep, cmd = s.partition(" ")
            else:
                fields = s.split(None, 5)
                sched, cmd = " ".join(fields[:5]), fields[5]
            row.update(schedule=sched, command=shown_command(cmd.strip(" ")))
        out.append(row)
    return out


def job_line(schedule, command):
    """(the crontab line for `schedule` and `command`, "") or (None, why in fixed words)."""
    schedule = " ".join((schedule or "").split())
    command = (command or "").strip()
    if not command:
        return None, "Enter the command to run."
    if len(command) > COMMAND_MAX or not re.fullmatch(_priv.ROOT_CRON_TEXT_RE, command):
        return None, "The command must be one line of at most 1,000 characters, with no control characters."
    if schedule.startswith("@"):
        ok = schedule in _priv.ROOT_CRON_SPECIALS
    else:
        fields = schedule.split(" ")
        ok = len(fields) == 5 and all(_priv.root_cron_field_ok(f, i) for i, f in enumerate(fields))
    if not ok:
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
    if op == "add":
        lines.append(line)
    elif op in ("save", "delete"):
        if not 1 <= n <= len(lines) or lines[n - 1] != was:
            return None, CHANGED
        if op == "save":
            lines[n - 1] = line
        else:
            del lines[n - 1]
    else:
        return None, UNKNOWN
    new = "\n".join(lines) + "\n" if lines else ""
    if not _priv.root_crontab_problem(new):
        return new, ""
    bad = next((r["n"] for r in rows(new) if r["kind"] == "other"), None)
    if bad is None:
        return None, TOO_BIG
    return None, i18n.Sentence(BAD_LINE, n=bad)
