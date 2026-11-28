"""A site's database password, rotated without breaking the app that uses it.

Reset password on a site's Database tab gives the database's user a new password. For the database a one-click
app was installed with (ws<id>_app), the app's own settings file holds the old one, so the reset writes the new
password into that file in the same step: as the site's account, the passwords on stdin only, the file replaced
atomically (a temporary file in the same folder, renamed over it, its mode kept), and read back. The panel then
checks that the site's database answers the new password from the site's own network, and on any failure puts
the old password back in both places (OWASP Secrets Management Cheat Sheet, "2.7.2 Rotation", and its database
rotation pattern in "2.4.1 Architectural Patterns for Automated Rotation": create, set, test, then finish).

Each app's file and the PHP assignment holding the password are fixed here: only an assignment whose value is the
database's CURRENT password is changed, exactly once, so nothing else in the file is touched and a file that holds
another password is left alone (and the reset is refused, the database unchanged). A Node.js app's variables are
the panel's own (Website.env_enc): a variable whose value is the current password gets the new one, written and
restarted by the panel's environment code.
"""
import base64
import shlex

APP_DB_SLUG = "app"
# recipe -> (the app's name, its settings files relative to the site's html, the first required and the rest kept
# in step when they hold it, the regex of the PHP text before the quoted password)
APP_SETTINGS = {
    "wordpress": ("WordPress", ("wp-config.php",), r"define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*'"),
    "phpbb": ("phpBB", ("config.php",), r"\$dbpasswd\s*=\s*'"),
    "drupal": ("Drupal", ("sites/default/settings.php",), r"'password'\s*=>\s*'"),
    "mybb": ("MyBB", ("inc/config.php",), r"\$config\['database'\]\['password'\]\s*=\s*'"),
    "smf": ("Simple Machines Forum", ("Settings.php", "Settings_bak.php"), r"\$db_passwd\s*=\s*'"),
}
MARK_DONE = "SITE_DBPW_DONE"
MARK_NOT_FOUND = "SITE_DBPW_NOT_FOUND"

# The rewriter (python3 -I -c, as the account). Arguments: the regex before the password, then the files, the
# first required. stdin: the old and the new password, base64, one per line. Prints SITE_DBPW_NOT_FOUND when the
# required file does not hold the old password exactly once, SITE_FILES_REFUSED for a path that leaves the site's
# files or is a link, SITE_WRITE_FAILED for a write the system refused, and SITE_DBPW_DONE when every file that held
# the old password holds the new one instead.
REWRITE_PY = r'''
import base64, os, re, stat, sys, tempfile
html = os.path.realpath(os.path.expanduser("~/site/html"))
old, new = (base64.b64decode(x).decode("utf-8") for x in sys.stdin.read().split()[:2])
def q(v):
    return v.replace("\\", "\\\\").replace("'", "\\'")
before = sys.argv[1]
pat = re.compile("(" + before + ")" + re.escape(q(old)) + "'")
done = re.compile("(" + before + ")" + re.escape(q(new)) + "'")
def write(path, text):
    d = os.path.dirname(path)
    dmode, mode = stat.S_IMODE(os.stat(d).st_mode), stat.S_IMODE(os.lstat(path).st_mode)
    tmp = None
    try:
        os.chmod(d, dmode | stat.S_IWUSR | stat.S_IXUSR)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".panel-db-")
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        tmp = None
    except OSError as e:
        print("SITE_WRITE_FAILED")
        print("error=%s: %s" % (e.strerror or "error", os.path.relpath(path, html)))
        sys.exit(34)
    finally:
        if tmp:
            os.unlink(tmp)
        os.chmod(d, dmode)
for i, rel in enumerate(sys.argv[2:]):
    path = os.path.join(html, rel)
    d = os.path.dirname(path)
    if os.path.realpath(d) != d or not (d == html or d.startswith(html + os.sep)) or os.path.islink(path):
        print("SITE_FILES_REFUSED"); sys.exit(25)
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            text = fh.read()
    except OSError:
        text = ""
    if len(pat.findall(text)) != 1:
        if i == 0:
            print("SITE_DBPW_NOT_FOUND"); sys.exit(35)
        continue
    write(path, pat.sub(lambda m: m.group(1) + q(new) + "'", text))
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        if len(done.findall(fh.read())) != 1:
            print("SITE_DBPW_NOT_FOUND"); sys.exit(35)
print("SITE_DBPW_DONE")
'''


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def app_settings(site, row):
    """Name the app whose settings hold `row`'s password: (name, files, the regex before the password) or None.

    Only the database `site`'s one-click app was installed with: any other is one the site's own code uses,
    which the panel cannot know.
    """
    from panel.ops.ssh_manager import databases as _dbs
    got = APP_SETTINGS.get(getattr(site, "app_recipe", "") or "")
    try:
        mine = row.name == _dbs.site_db_name(site.id, APP_DB_SLUG)
    except ValueError:
        mine = False
    return got if got and mine else None


def rewrite_sh(files, before):
    """The shell (as the site's account) that puts the new password where the old one is in `files`."""
    return "python3 -I -c %s %s %s" % (shlex.quote(REWRITE_PY), shlex.quote(before),
                                        " ".join(shlex.quote(f) for f in files))


def rewrite_stdin(old, new):
    """The rewriter's stdin: the old password, then the new, base64, one per line."""
    return "%s\n%s\n" % (_b64(old), _b64(new))


def env_names(env, old):
    """The names of the app's variables whose value is the database's current password `old`, sorted."""
    return sorted(k for k, v in (env or {}).items() if old and v == old)
