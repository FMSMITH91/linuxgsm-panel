"""A WordPress site's administrators: list them, and give one a new password (and, if asked, a new email).

The app install shows the generated admin password once and never stores it, and an admin installed with an
address that receives no mail cannot use WordPress's own "Lost your password?". These steps do what that page
would, from the panel: each runs in a one-off container of the panel's wp-cli image as the site's account, the
same hardened step the install's wp-cli steps are (websites_recipes.step_sh, run-in-container): the site's files
mounted, its network, no log driver. The administrator's name, the new password and the email reach WordPress
only as files of the step's read-only values folder, read by PHP (`wp eval`): never on a command line, in an
environment, a log line or the journal (OWASP Secrets Management Cheat Sheet, "5.1 Injection of Secrets (file,
in-memory)"; Logging Cheat Sheet, "Data to exclude").

The reset signs the administrator out everywhere (WP_Session_Tokens destroy_all: OWASP Forgot Password Cheat
Sheet, "User Resets Password": invalidate the existing sessions) and changes only an account with the
administrator role. WordPress's "your email changed" mail is not sent: the old address may be the one that
receives no mail. Plugins and themes are not loaded for either step, so a broken one cannot stop the reset.

Each step prints its own marks (WPADMIN=<login>, WPADMIN_DONE and the WPADMIN_ refusals); only those are read.
"""
import re

ADMINS_MAX = 30
# A WordPress login: sanitize_user()'s strict alphabet (letters, digits, space, _ . - @), at most 60 characters.
LOGIN_RE = re.compile(r"[A-Za-z0-9 _.@-]{1,60}\Z")
MARK_DONE = "WPADMIN_DONE"
MARKS = {
    "WPADMIN_NO_SUCH": "That account is not an administrator of this WordPress site.",
    "WPADMIN_EMAIL_BAD": "WordPress refused that email address.",
    "WPADMIN_EMAIL_TAKEN": "Another account of this WordPress site already has that email address.",
}
S_NOT_SET_UP = "WordPress did not answer: is it installed on this site? Its database must be reachable too."
# The step values folder's file names, each read from the placeholder of the same name in lower case.
VALUES = {name.upper(): name for name in ("admin_user", "admin_password", "admin_email")}

# Each line of the list is one login, marked so nothing else the container prints is taken for one.
_LIST_SH = ("out=$(wp --skip-plugins --skip-themes user list --role=administrator --field=user_login --orderby=login --number=%d 2>/dev/null) "
            "|| exit 3; printf '%%s\\n' \"$out\" | sed 's/^/WPADMIN=/'" % ADMINS_MAX)
_RESET_PHP = (
    "$v = function ($n) { return (string) @file_get_contents('/run/panel-values/' . $n); }; "
    "$u = get_user_by('login', $v('ADMIN_USER')); "
    "if (! $u || ! in_array('administrator', (array) $u->roles, true)) { echo \"WPADMIN_NO_SUCH\\n\"; exit(3); } "
    "$e = $v('ADMIN_EMAIL'); "
    "if ($e !== '') { "
    "if (! is_email($e)) { echo \"WPADMIN_EMAIL_BAD\\n\"; exit(4); } "
    "$o = email_exists($e); "
    "if ($o && (int) $o !== (int) $u->ID) { echo \"WPADMIN_EMAIL_TAKEN\\n\"; exit(4); } "
    "add_filter('send_email_change_email', '__return_false'); "
    "$r = wp_update_user(array('ID' => $u->ID, 'user_email' => $e)); "
    "if (is_wp_error($r)) { echo \"WPADMIN_EMAIL_BAD\\n\"; exit(4); } } "
    "wp_set_password($v('ADMIN_PASSWORD'), $u->ID); "
    "WP_Session_Tokens::get_instance($u->ID)->destroy_all(); "
    "echo \"WPADMIN_DONE\\n\";")


def list_step():
    """The run-in-container step that prints the site's administrators' logins, one WPADMIN=<login> line each."""
    return {"name": "wp-admins", "type": "run-in-container", "image": "wpcli", "argv": ["sh", "-c", _LIST_SH]}


def reset_step():
    """The run-in-container step that sets the named administrator's password (and email, when one is given)."""
    return {"name": "wp-admin-reset", "type": "run-in-container", "image": "wpcli", "argv": ["wp", "--skip-plugins", "--skip-themes", "eval", _RESET_PHP],
            "values": dict(VALUES)}


def reset_values(user, password, email):
    """The reset step's placeholder values: {admin_user, admin_password, admin_email}."""
    return {"admin_user": user, "admin_password": password, "admin_email": email or ""}


def logins(out):
    """The administrators' logins in a list step's output, in its order, each one LOGIN_RE allows."""
    got = []
    for line in (out or "").splitlines():
        name = line.strip()[len("WPADMIN="):] if line.strip().startswith("WPADMIN=") else ""
        if LOGIN_RE.match(name) and name not in got:
            got.append(name)
    return got[:ADMINS_MAX]


def reset_answer(out):
    """(ok, sentence) for a reset step's output: done only when WordPress printed its done mark."""
    lines = {line.strip() for line in (out or "").splitlines()}
    for mark, sentence in MARKS.items():
        if mark in lines:
            return False, sentence
    if MARK_DONE in lines:
        return True, "The administrator has a new password and was signed out everywhere."
    return False, S_NOT_SET_UP
