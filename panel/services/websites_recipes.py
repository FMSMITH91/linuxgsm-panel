"""The one-click app recipe engine: the shell each install step runs as the site's account, and its undo.

A recipe is catalog data (websites_catalog checks it): a list of steps of the fixed types below.
Nothing a recipe holds is run as code by the panel: a config template is text with {placeholders},
a command line is argv words, a web installer is pages of form fields. The install job (the routes)
runs the steps in order, records each one finished, and on a failure runs undo_sh for each finished
step in reverse, so no half-installed site is left behind.

    create-database        the job creates the site's database through the Databases code (no shell
                           here); undone by dropping it there.
    download-verify-unpack the release is downloaded (https only, size and time capped) into the
                           site's home, its sha256 checked against the catalog BEFORE anything is
                           unpacked, then unpacked by a checker that refuses absolute, `..`, link and
                           device entries and caps entries, total size and depth (OWASP File Upload
                           Cheat Sheet: archives, limits after decompression; Path Traversal).
    render-config          the template, its values escaped for PHP or YAML strings and fresh salts
                           from the CSPRNG, written through stdin into the site's files, refusing a
                           path that leaves them or passes through a link.
    run-in-container       a one-off container of the site's image (or wp-cli's), hardened like the
                           site's, its files mounted; secrets reach it on its stdin or through
                           `-e NAME` from the shell's environment, never on a command line.
    set-permissions        files made read-only, folders removed (an installer left behind is a
                           takeover risk), then checked: the installer path must answer 404.
    drive-web-installer    the app's own install pages walked over the site's loopback port (never
                           the public address, before the site is public), with the proxy token and
                           secret fields read from files; each page must show its expected text.

Secrets (the database password, the admin password, the proxy token) travel only on stdin: the
OWASP Secrets Management Cheat Sheet's advice against secrets in argv and logs.
"""
import base64
import re
import secrets as _secrets
import shlex

from panel.services import websites as _ws

DOWNLOAD_MAX_BYTES = 200 * 1024 * 1024
UNPACK_MAX_BYTES = 1024 * 1024 * 1024
UNPACK_MAX_ENTRIES = 50000
UNPACK_MAX_DEPTH = 32
STEP_CONTAINER = "lgsm-site-step"
DL_DIR = _ws.SITE + "/.download"
_ADMIN_USER_RE = re.compile(r"[A-Za-z0-9_.@-]{3,60}\Z")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z")
_SITE_NAME_RE = re.compile(r"[^\x00-\x1f\x7f\"'\\{}<>$`]{1,80}\Z")


def _q(text):
    return shlex.quote(text)


def _b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# ── values ──────────────────────────────────────────────────────────────────────────────────────
def values_for(site, db=None, admin=None, domains=()):
    """The placeholder values of an install: {name: text}. Raises ValueError on an admin value it refuses.

    `db` = {"name", "user", "password", "host", "port"} (the Databases code's new database; host as
    the container sees it, 127.0.0.1, port 3306); `admin` = {"user", "email", "password", "site_name"}.
    """
    from panel.services import websites_proxy as _wp
    admin, db = dict(admin or {}), dict(db or {})
    why = _admin_problem(admin) if admin else ""
    if why:
        raise ValueError(why)
    names = [d for d in domains if _wp._DOMAIN_RE.match(d or "")]
    domain = names[0] if names else ""
    return {"db_name": db.get("name", ""), "db_user": db.get("user", ""), "db_password": db.get("password", ""),
            "db_host": "%s:%s" % (db.get("host", "127.0.0.1"), db.get("port", 3306)),
            "db_host_name": str(db.get("host", "127.0.0.1")), "db_port": str(db.get("port", 3306)),
            "site_name": admin.get("site_name", site.name), "site_url": "https://%s" % domain if domain else "",
            "domain": domain, "admin_user": admin.get("user", ""), "admin_email": admin.get("email", ""),
            "admin_password": admin.get("password", ""),
            "trusted_hosts": ", ".join("'^%s$'" % re.escape(d).replace("\\-", "-") for d in names)}


_ADMIN_CHECKS = (
    ("user", lambda v: bool(_ADMIN_USER_RE.match(v)), "an admin name is 3-60 letters, digits and . _ @ -"),
    ("email", lambda v: bool(_EMAIL_RE.match(v)), "the admin email address is not one"),
    ("password", lambda v: 12 <= len(v) <= 128, "the admin password is 12-128 characters"),
    ("site_name", lambda v: bool(_SITE_NAME_RE.match(v)),
     "a site title is 1-80 characters without quotes, braces, $, ` or angle brackets"),
)


def _admin_problem(admin):
    """The first reason the install form's admin values are refused, or ""."""
    for key, ok, why in _ADMIN_CHECKS:
        value = admin.get(key, "")
        if not (isinstance(value, str) and ok(value)):
            return why
    return ""


def generate_password():
    """A generated admin password: 24 characters from the CSPRNG (shown once, never stored)."""
    return _secrets.token_urlsafe(18)


def _escape(value, mode):
    if any(ord(c) < 0x20 and c not in "\t" for c in value):
        raise ValueError("a value holds a control character")
    if mode == "php":
        return value.replace("\\", "\\\\").replace("'", "\\'")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_template(template, values, escape):
    """`template` with each {name} replaced by its escaped value; every {salt} a fresh 64-character salt.

    {trusted_hosts} is inserted as built (PHP strings already quoted, the domains escaped as regex).
    """
    def one(match):
        name = match.group(1)
        if name == "salt":
            return _secrets.token_urlsafe(48)
        if name == "trusted_hosts":
            return values.get("trusted_hosts", "")
        return _escape(values.get(name, ""), escape)
    return re.sub(r"\{([a-z_]{1,24})\}", one, template)


def _argv_word(word, values):
    from panel.services import websites_catalog as _wc
    def one(match):
        if match.group(1) in _wc.SECRETS:
            raise ValueError("a secret may not be put on a command line")
        return values.get(match.group(1), "")
    return re.sub(r"\{([a-z_]{1,24})\}", one, word)


# ── the safe unpacker (python3 -I -c, as the account; arguments: archive, destination, strip) ──
UNPACK_PY = r'''
import os, stat, sys, tarfile, zipfile
src, dest, strip = sys.argv[1], sys.argv[2], sys.argv[3]
MAXB, MAXN, MAXD = %d, %d, %d
def bad(why):
    print("SITE_UNPACK_FAILED " + why); sys.exit(26)
def rel(name):
    if "\x00" in name or "\\" in name or name.startswith("/"):
        bad("absolute or odd name")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        bad("a .. entry")
    if strip:
        if not parts or parts[0] != strip:
            return None
        parts = parts[1:]
    if len(parts) > MAXD:
        bad("too deep")
    return "/".join(parts) if parts else None
def entries():
    if zipfile.is_zipfile(src):
        z = zipfile.ZipFile(src)
        for i in z.infolist():
            mode = (i.external_attr >> 16) & 0o170000
            if mode and mode not in (stat.S_IFREG, stat.S_IFDIR):
                bad("a link or device entry")
            yield rel(i.filename), i.is_dir(), i.file_size, (lambda i=i: z.open(i))
    else:
        t = tarfile.open(src, "r:gz")
        for m in t:
            if not (m.isreg() or m.isdir()):
                bad("a link or device entry")
            yield rel(m.name), m.isdir(), m.size, (lambda m=m: t.extractfile(m))
total = count = 0
real = os.path.realpath(dest)
for name, is_dir, size, opener in entries():
    count += 1
    total += max(0, size)
    if count > MAXN or total > MAXB:
        bad("too many entries or too large unpacked")
    if not name:
        continue
    path = os.path.join(dest, name)
    if not os.path.realpath(path).startswith(real + os.sep):
        bad("an entry outside the site")
    if is_dir:
        os.makedirs(path, mode=0o755, exist_ok=True)
        continue
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    written = 0
    with os.fdopen(fd, "wb") as out, opener() as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            written += len(chunk)
            if written > size or written > MAXB:
                bad("an entry larger than it said")
            out.write(chunk)
print("unpacked=%%d" %% count)
''' % (UNPACK_MAX_BYTES, UNPACK_MAX_ENTRIES, UNPACK_MAX_DEPTH)

# The safe writer (python3 -I -c, as the account; arguments: destination relative to html, a|w).
WRITE_PY = r'''
import os, sys
html = os.path.realpath(os.path.expanduser("~/site/html"))
path = os.path.join(html, sys.argv[1])
d = os.path.dirname(path)
if os.path.realpath(d) != d or not (d == html or d.startswith(html + os.sep)) or os.path.islink(path):
    print("SITE_FILES_REFUSED"); sys.exit(25)
data = sys.stdin.buffer.read()
flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_APPEND if sys.argv[2] == "a" else os.O_TRUNC)
fd = os.open(path, flags, 0o600)
with os.fdopen(fd, "wb") as fh:
    fh.write(data)
print("written=" + sys.argv[1])
'''


# ── the steps ───────────────────────────────────────────────────────────────────────────────────
def _download_sh(recipe, step):
    url, sha = recipe["url"], recipe["sha256"]
    archive = DL_DIR + "/release"
    return ("if [ -n \"$(ls -A %s 2>/dev/null)\" ]; then echo SITE_NOT_EMPTY; exit 27; fi; " % _q(_ws.HTML)
            + "rm -rf %s; mkdir -m 0700 -p %s || exit 1; " % (_q(DL_DIR), _q(DL_DIR))
            + "curl -fsSL --proto =https --tlsv1.2 --max-redirs 3 --max-time 600 --max-filesize %d -o %s %s "
              "|| { rm -rf %s; echo SITE_DOWNLOAD_FAILED; exit 28; }; " % (DOWNLOAD_MAX_BYTES, _q(archive), _q(url),
                                                                         _q(DL_DIR))
            + "echo %s | sha256sum -c --status - || { rm -rf %s; echo SITE_SHA_MISMATCH; exit 29; }; "
            % (_q("%s  %s" % (sha, archive)), _q(DL_DIR))
            + "python3 -I -c %s %s %s %s; rc=$?; rm -rf %s; " % (_q(UNPACK_PY), _q(archive), _q(_ws.HTML),
                                                                 _q(step.get("strip", "")), _q(DL_DIR))
            + "[ $rc -eq 0 ] || { find %s -mindepth 1 -delete; exit $rc; }" % _q(_ws.HTML))


def _render_sh(step, values):
    text = render_template(step["template"], values, step["escape"])
    mode = "a" if step.get("append") else "w"
    return "python3 -I -c %s %s %s" % (_q(WRITE_PY), _q(step["dest"]), mode), text


def _run_sh(account, site, step, values):
    """The one-off container command, and its stdin (an env bundle, then the stdin secret)."""
    from panel.services import websites_catalog as _wc
    home = _ws._home(account)
    image = _ws.image_for(site) if step["image"] == "site" else _wc.pins("wpcli")["image"]
    if not (str(values.get("_uid", "")).isdecimal() and str(values.get("_gid", "")).isdecimal()):
        raise ValueError("a container step needs the account's uid and gid")
    env = step.get("env", {})
    lines = ["env %s %s" % (name, _b64(values.get(ph, ""))) for name, ph in sorted(env.items())]
    if "stdin" in step:
        lines.append("in %s" % _b64(values.get(step["stdin"], "")))
    args = ["podman", "run", "--rm", "-i", "--name", STEP_CONTAINER, "--pull=never", "--userns=keep-id",
            "--user", "%s:%s" % (values["_uid"], values["_gid"]), "--read-only", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--pids-limit=%d" % int(site.pids), "--memory=%dm" % int(site.mem_mb),
            "--dns=none", "--network=%s" % values.get("_network", "none"), "--tmpfs=/tmp:rw,mode=1777,size=256m",
            "-v", "%s/%s:%s" % (home, _ws.HTML, _ws.DOCROOT_PHP), "-w", _ws.DOCROOT_PHP, "-e", "HOME=/tmp"]
    for name in sorted(env):
        args += ["-e", name]
    args += ["--entrypoint", step["argv"][0], image] + [_argv_word(w, values) for w in step["argv"][1:]]
    body = ("while read -r k n v; do case \"$k\" in env) case \"$n\" in %s) export \"$n=$(printf %%s \"$v\" | base64 -d)\" ;; "
            "*) exit 25 ;; esac ;; in) inp=\"$n\" ;; esac; done; " % ("|".join(sorted(env)) or "_none_")
            + "printf %%s \"${inp:-}\" | base64 -d | %s 2>&1 | tail -n 40; rc=${PIPESTATUS[2]}; " % shlex.join(args)
            + "[ \"$rc\" -eq 0 ] || { echo SITE_STEP_FAILED; exit \"$rc\"; }")
    # the `in` line has no name field: "in <b64>" reads as k=in n=<b64>
    return body, "".join(line + "\n" for line in lines)


def _qd(word):
    """`word` for the shell: double-quoted when it names the step's temp folder ($d; the panel's own text
    of field names and fixed file names only), else single-quoted."""
    return '"%s"' % word if "$d/" in word else _q(word)


def _field_args(form, values):
    """curl's --data-urlencode arguments for a page's form: a secret field read from its file, others inline."""
    from panel.services import websites_catalog as _wc
    args = []
    for name, value in sorted(form.items()):
        whole = re.fullmatch(r"\{([a-z_]{1,24})\}", value)
        if whole and whole.group(1) in _wc.SECRETS:
            args += ["--data-urlencode", "%s@$d/%s" % (name, whole.group(1))]
        else:
            args += ["--data-urlencode", "%s=%s" % (name, _argv_word(value, values))]
    return args


def _page_sh(i, page, values, host, port):
    """The shell that fetches one installer page and checks its expected text."""
    args = ["curl", "-sS", "--max-time", "180", "-b", "$d/jar", "-c", "$d/jar", "-H", "Host: %s" % host,
            "-H", "@$d/token", "-o", "$d/page"]
    if page["method"] == "POST":
        args += _field_args(page["form"], values) or ["--data", ""]
    url = "http://127.0.0.1:%d%s" % (port, page["path"])
    return ("%s || { echo SITE_STEP_FAILED; echo page=%d; exit 30; }; " % (" ".join(_qd(a) for a in args + [url]), i + 1)
            + "grep -qF -- %s \"$d/page\" || { echo SITE_STEP_FAILED; echo page=%d; exit 31; }; "
            % (_q(page["expect"]), i + 1))


def _installer_sh(site, step, values, token):
    """Walk the app's install pages over the site's loopback port; stdin carries the secrets."""
    from panel.services import websites_catalog as _wc
    secret_names = sorted({ph for page in step["pages"] for v in page["form"].values()
                           for ph in re.findall(r"\{([a-z_]{1,24})\}", v) if ph in _wc.SECRETS})
    stdin = "".join("%s %s\n" % (n, _b64(values.get(n, ""))) for n in secret_names)
    stdin += "token %s\n" % _b64("%s: %s" % (_ws.TOKEN_HEADER, token))
    body = ["d=$(mktemp -d) || exit 1; trap 'rm -rf \"$d\"' EXIT; chmod 0700 \"$d\"; ",
            "while read -r n v; do case \"$n\" in %s|token) printf %%s \"$v\" | base64 -d > \"$d/$n\" ;; *) exit 25 ;; "
            "esac; done; " % ("|".join(secret_names) or "_none_")]
    host = values.get("domain", "") or "localhost"
    body += [_page_sh(i, page, values, host, int(site.port)) for i, page in enumerate(step["pages"])]
    body.append("echo installer=done")
    return "".join(body), stdin


def _permissions_sh(site, step, recipe, token):
    lines = []
    for path in step.get("readonly", []):
        lines.append("chmod a-w %s || exit 1; " % _q(_ws.HTML + "/" + path))
    for path in step.get("remove", []):
        lines.append("rm -rf -- %s; [ -e %s ] && { echo SITE_INSTALLER_LEFT; exit 32; }; "
                     % (_q(_ws.HTML + "/" + path), _q(_ws.HTML + "/" + path)))
    stdin = None
    if recipe.get("installer_path"):
        stdin = "%s: %s\n" % (_ws.TOKEN_HEADER, token)
        lines.append("h=$(mktemp) || exit 1; trap 'rm -f \"$h\"' EXIT; cat > \"$h\"; "
                     "c=$(curl -s -o /dev/null -w '%%{http_code}' --max-time 30 -H @\"$h\" http://127.0.0.1:%d%s); "
                     "[ \"$c\" = 404 ] || { echo SITE_INSTALLER_LEFT; echo code=$c; exit 32; }; "
                     % (int(site.port), recipe["installer_path"]))
    lines.append("echo permissions=done")
    return "".join(lines), stdin


def step_sh(account, site, step, values, recipe=None, token=None):
    """(bash to run as the site's account, its stdin or None) for one recipe step; ("", None) for create-database.

    `values` is values_for()'s dict plus the job's _uid, _gid and _network (the site's Network= value)
    for a container step; `recipe` the catalog recipe (its url, sha256, installer_path); `token` the
    site's proxy token in clear (the web installer and the 404 check send it; stdin only).
    """
    _ws._home(account)
    kind = step["type"]
    if kind == "create-database":
        return "", None
    if kind == "download-verify-unpack":
        return _ws._ENV + _download_sh(recipe, step), None
    if kind == "render-config":
        body, text = _render_sh(step, values)
        return _ws._ENV + body, text
    if kind == "run-in-container":
        body, stdin = _run_sh(account, site, step, values)
        return _ws._ENV + body, stdin
    if kind == "drive-web-installer":
        body, stdin = _installer_sh(site, step, values, token or "")
        return _ws._ENV + body, stdin
    if kind == "set-permissions":
        body, stdin = _permissions_sh(site, step, recipe or {}, token or "")
        return _ws._ENV + body, stdin
    raise ValueError("unknown step type %r" % kind)


def undo_sh(account, site, step):
    """Bash that undoes one finished install step (the job runs these in reverse on a failure); "" for none.

    create-database is undone by the job through the Databases code; a container or installer step by
    removing any one-off container left (the database and the files go with their own steps' undo).
    """
    _ws._home(account)
    kind = step["type"]
    if kind == "download-verify-unpack":
        return _ws._ENV + "rm -rf %s; find %s -mindepth 1 -delete; echo undone" % (_q(DL_DIR), _q(_ws.HTML))
    if kind == "render-config" and not step.get("append"):
        return _ws._ENV + "rm -f -- %s; echo undone" % _q(_ws.HTML + "/" + step["dest"])
    if kind in ("run-in-container", "drive-web-installer"):
        return _ws._ENV + "podman rm -f -i %s >/dev/null 2>&1; echo undone" % STEP_CONTAINER
    if kind == "set-permissions":
        paths = " ".join(_q(_ws.HTML + "/" + p) for p in step.get("readonly", []))
        return _ws._ENV + ("chmod -R u+w -- %s 2>/dev/null; " % paths if paths else "") + "echo undone"
    return ""
