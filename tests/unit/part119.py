"""Part 119 of the unit suite: the twenty-first review's panel-host fixes (review 1022a, builder A).

* The login jail's boot self-heal runs in the app's context, after the boot bind is recorded: an
  unset bind that boot resolved to loopback (logins through Tailscale Serve) got the web-port-only
  ban on every start, and undid the all-ports jail a whitelist edit wrote.
* Change-port: re-asking for a saved BIND whose restart could not be scheduled is a change, as the
  port already was, not "That's already the panel's binding".
* Every full-upgrade the panel or its installer runs keeps a package the host's pinning would
  DOWNGRADE (the host bootstrap's apt-full-upgrade verb, both transports; install.sh's two runs),
  the keeps written BEFORE the host's own preferences (apt takes a version's first matching
  record); the OS update job's keep step can no longer stop the update; install.sh says "up to
  date" only when the upgrade said so.
* uninstall.sh closes the port panel.conf records for this install when config.json's is unreadable.
* The debug report's file no longer says, per remote, whether the panel uses sudo there.
* The helper's line-by-line content rules split lines as cron/sshd/systemd do.
* The Tailscale page's Enable form counts a route to a pending port as the panel's own.

HOW IT RUNS. Routes and app functions on part12's app with every host call stubbed; the helper
in-process (part05's) with its subprocess calls stood in; the remote form and install.sh's and
uninstall.sh's own text under bash in this part's temp dir, with stand-in tools first on PATH.
Nothing reaches apt, a host, sudo or the checkout's data/.
"""
import io as _io119
import os
import shutil as _shutil119
import subprocess as _sp119  # nosec B404 - bash over this part's own temp dir, fixed argv
import tempfile as _tf119
import threading as _th119
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _h119, _root
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_arm, _p9_cfg, _p9_client, _p9_patch,
                         _p9_restore_all, _p9_so)
from unit.part108 import _ANY108
from unit.part116 import _LOOP116 as _LOOP119, _boot116, _move116
from unit.part117 import _hosts_report117, _serve_table117
from unit.part118 import _DPKG118, _SIM118
from panel.ops.debug_report import _base as _base119
from panel.routes import tailscale as _tsr119
from panel.security import privileged as _priv119

_TRIP119_START = len(_P9_TRIPPED)
_TMP119 = _tf119.mkdtemp(prefix="lgsm-unit-p119-")
_CFG119 = _p9_cfg.load_config()
# The operator's own record for the package, by RELEASE: it matches the installed version too.
_OWN119 = "Package: proftpd-core\nPin: release a=noble-updates\nPin-Priority: 100\n"
_KEEP119 = "Package: proftpd-core\nPin: version 1.3.8.b+dfsg-4ubuntu1\nPin-Priority: 32000"


def _standin119(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(path, 0o700)  # nosec B103 - this part's own temp dir


def _bash119(script, env):
    r = _sp119.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   env=env)
    return r.stdout, r.stderr, r.returncode


def _bin119(name):
    """A fresh dir with stand-in apt-get (the plan for -s, a call log otherwise) and dpkg."""
    d = os.path.join(_TMP119, name)
    os.makedirs(d)
    calls = os.path.join(d, "calls")
    _standin119(os.path.join(d, "apt-get"),
                "#!/bin/bash\n"
                "for a in \"$@\"; do [ \"$a\" = -s ] && { printf '%%s' \"$SIM119\"; exit 0; }; done\n"
                "echo \"$*\" >> %s\n"
                "for a in \"$@\"; do case $a in Dir::Etc::Preferences=*) cp \"${a#*=}\" %s/prefs.seen;; "
                "esac; done\nexit \"${APT_RC119:-0}\"\n" % (calls, d))
    _standin119(os.path.join(d, "dpkg"), _DPKG118)
    own = os.path.join(d, "own-preferences")
    with open(own, "w", encoding="utf-8") as fh:
        fh.write(_OWN119)
    return d, calls, own


def _resolve119(d):
    """The helper's tool lookup with dpkg pointed at `d`'s stand-in (the build machine need not have dpkg)."""
    real = _h119.resolve
    return lambda prog: os.path.join(d, prog) if prog == "dpkg" else real(prog)


def _read119(path):
    return open(path, encoding="utf-8").read() if os.path.exists(path) else ""


def _env119(bin_, **extra):
    return dict({"PATH": bin_ + ":/usr/bin:/bin", "SIM119": _SIM118, "HOME": _TMP119, "LC_ALL": "C.UTF-8"},
                **extra)


# ── 1. the login jail's boot self-heal reads the boot bind ───────────────────────────────────────
def _f2b_boot119():
    import app as _app119
    got = {}
    for case, bound in (("boot resolved loopback", _LOOP119), ("boot public", _ANY108)):
        seen = []
        _p9_patch(_p9_so, "ensure_panel_host_whitelist", lambda wl: (True, "ok"))
        _p9_patch(_p9_so, "ensure_panel_fail2ban",
                  lambda log, port, wl=None: (seen.append(_p9_so._panel_login_proxied()), (True, "j"))[1])
        _p9_patch(_app119, "_security_whitelist", lambda: [])
        _p9_cfg.save_config(dict(_CFG119, bind_host="", trust_proxy=False, tailscale_setup_done=False))
        with _boot116(BOOT_BIND=bound, BOOT_PORT=5000):
            # On a thread of its own, as at boot: no app context comes with it.
            t = _th119.Thread(target=_app119._r34a_f2b_autostart, args=(_p9,))
            t.start()
            t.join(30)
        # A thread still running past the wait reads the next case's stubs, or none (review 1022c lead).
        got[case] = seen + (["thread still running"] if t.is_alive() else [])
    check("login jail: the boot self-heal (no bind in config.json, boot resolved loopback behind Serve) writes "
          "the all-ports jail, as the whitelist edit does (it read no boot bind and banned the web port only)",
          got == {"boot resolved loopback": [True], "boot public": [False]}, repr(got))
    text = open(os.path.join(_root, "app.py"), encoding="utf-8").read()
    main = text[text.index('\nif __name__ == "__main__":'):]
    rec, start = main.find('app.config["BOOT_BIND"] = host'), main.find("target=_r34a_f2b_autostart")
    check("login jail: ...and app.py records BOOT_BIND before it starts the self-heal's thread (it was set "
          "after, so even a context could not have seen it)", 0 <= rec < start, repr((rec, start)))


# ── 2. change-port: a saved bind waiting for its restart can be retried ───────────────────────────
def _rebind119(client):
    got = {}
    for case, bound in (("bound loopback, public saved", _LOOP119), ("bound as saved", _ANY108)):
        with _boot116(BOOT_BIND=bound):
            body, _calls = _move116(client, 5000, 5000, 5000, True)
        got[case] = (body.get("success"), "already" in str(body.get("message")))
    check("change-port: re-asking for the saved bind while the panel still listens on the old one (its restart "
          "could not be scheduled) applies it, not 'already the panel's binding'",
          got["bound loopback, public saved"] == (True, False), repr(got))
    check("change-port: ...and the bind the panel really has is still refused as unchanged (control)",
          got["bound as saved"] == (False, True), repr(got))


# ── 3. the OS update's keep step never stops the update (panel host) ─────────────────────────────
class _Sub119(object):
    """The helper's subprocess with run() recorded and answered rc 0."""

    STDOUT = _sp119.STDOUT
    TimeoutExpired = _sp119.TimeoutExpired

    def __init__(self):
        self.argvs = []

    def run(self, argv, **_k):
        self.argvs.append(list(argv))
        return NS(returncode=0, stdout="", stderr="")


class _NoTmp119(object):
    def __getattr__(self, name):
        return getattr(_tf119, name)

    def mkdtemp(self, *a, **k):
        raise OSError(28, "No space left on device")


def _os_update119():
    sub, log = _Sub119(), os.path.join(_TMP119, "os-update.log")
    _p9_patch(_h119, "subprocess", sub)
    _p9_patch(_h119, "tempfile", _NoTmp119())
    _p9_patch(_h119, "resolve", lambda prog: "/usr/bin/" + prog)
    _p9_patch(_h119, "OS_UPDATE_LOG", log)
    rc = _h119._os_update_run()
    text = _read119(log)
    ups = [a for a in sub.argvs if a[-1:] == ["full-upgrade"] and "-s" not in a]
    check("os update (panel host): a keep step that fails (no temp dir: /tmp full) still runs the upgrade and "
          "says why in the log (the update ended at the failure sentinel with full-upgrade never run)",
          rc == 0 and len(ups) == 1 and text.rstrip().endswith(_h119.OS_UPDATE_DONE + "0")
          and "Could not check for packages apt would downgrade (OSError)" in text, repr((rc, sub.argvs, text)))


def _undecodable119():
    d, _calls, _own = _bin119("undecodable")
    # The byte from the stand-in itself, after the plan: an environment cannot carry it.
    _standin119(os.path.join(d, "apt-get"), "#!/bin/bash\nprintf '%s' \"$SIM119\"\n"
                "printf 'Inst tzdata2 [1] (2 Some \\377Label:24.04 [all])\\n'\n")
    env = dict(_h119._clean_env(), PATH=d + ":/usr/bin:/bin", SIM119=_SIM118)
    _p9_patch(_h119, "resolve", _resolve119(d))
    try:
        opts = _h119._r33_keep_installed_opts(os.path.join(d, "apt-get"), env, d, _io119.StringIO())
    except Exception as exc:  # noqa: BLE001 - the old decode raised; named below
        opts = type(exc).__name__
    check("os update (panel host): a plan with a byte that is not UTF-8 (a third-party Release label) is read "
          "past, and the downgrade still kept (it raised UnicodeDecodeError)",
          isinstance(opts, list) and len(opts) == 2, repr(opts))


def _helper_prefs_order119():
    d, _calls, own = _bin119("order")
    env = dict(_h119._clean_env(), PATH=d + ":/usr/bin:/bin", SIM119=_SIM118)
    _p9_patch(_h119, "_R34A_APT_PREFS", own)
    _p9_patch(_h119, "resolve", _resolve119(d))
    _h119._r33_keep_installed_opts(os.path.join(d, "apt-get"), env, d, _io119.StringIO())
    text = _read119(os.path.join(d, "preferences"))
    # A dpkg on PATH that calls every version older, and the TOOLS one (the stand-in) that does not.
    os.makedirs(os.path.join(d, "path-dpkg"))
    _standin119(os.path.join(d, "path-dpkg", "dpkg"), "#!/bin/bash\nexit 0\n")
    older = _h119._r33_is_older("2", "1", dict(env, PATH=os.path.join(d, "path-dpkg") + ":/usr/bin:/bin"))
    check("os update (panel host): dpkg is run by the helper's own TOOLS path, never looked up on PATH (a "
          "PATH dpkg answered for it)", older is False, repr(older))
    check("os update (panel host): the keep's records come BEFORE the host's own (apt takes a version's first "
          "matching record, so an operator's release pin matching the installed version undid the keep)",
          _KEEP119 in text and _OWN119.strip() in text and text.index(_KEEP119) < text.index(_OWN119.strip()),
          repr(text))


# ── 4. the host bootstrap's apt-full-upgrade verb keeps them too ──────────────────────────────────
def _verb_local119():
    sub = _Sub119()
    made = []

    def keep(apt, env, tmpdir, log):
        made.append(tmpdir)
        return ["-o", "Dir::Etc::Preferences=" + os.path.join(tmpdir, "preferences")]
    _p9_patch(_h119, "subprocess", sub)
    _p9_patch(_h119, "resolve", lambda prog: "/usr/bin/" + prog)
    _p9_patch(_h119, "_r33_keep_installed_opts", keep)
    out = _io119.StringIO()
    _p9_patch(_h119.sys, "stdout", out)
    rc = _h119.main(["panel-helper", "apt-full-upgrade"])
    _p9_restore_all()
    argv = sub.argvs[-1] if sub.argvs else []
    want = ["/usr/bin/apt-get", "-o", "Dir::Etc::Preferences=" + os.path.join(made[0] if made else "", "preferences"),
            "full-upgrade"]
    check("helper: apt-full-upgrade (the host bootstrap's) hands apt the keep's preferences, before the "
          "subcommand, and removes its temp dir (apt refused the whole run on a downgrade pin)",
          rc == 0 and len(made) == 1 and argv[:4] == want
          and argv[4:] == _h119.VERBS["apt-full-upgrade"][1]([])[2:] and not os.path.exists(made[0]),
          repr((rc, sub.argvs, made)))


def _remote_run119(rc):
    """Run apt-full-upgrade's remote form under bash; (exit, apt-get calls, prefs seen, stdout, temp left)."""
    d, calls, own = _bin119("remote-" + rc)
    cmd = _priv119.remote_command("apt-full-upgrade", []).replace("/etc/apt/preferences", own)
    out, _err, code = _bash119(cmd, _env119(d, APT_RC119=rc, TMPDIR=d))
    left = [n for n in os.listdir(d) if n.startswith("tmp.")]
    return code, _read119(calls), _read119(os.path.join(d, "prefs.seen")), out, left


def _verb_remote119():
    code, calls, prefs, out, left = _remote_run119("0")
    failed = _remote_run119("100")[0]
    up = [ln for ln in calls.splitlines() if "full-upgrade" in ln]
    kept_first = _KEEP119 in prefs and prefs.index(_KEEP119) < prefs.index(_OWN119.strip())
    check("remote: apt-full-upgrade (the bootstrap's) keeps the package the plan would DOWNGRADE, its records "
          "before the host's own, names it, removes its temp dir, and exits with apt's status",
          (code, len(up), up[0].startswith("-o Dir::Etc::Preferences=") if up else None, kept_first,
           "proftpd-core 1.3.8.b+dfsg-4ubuntu1" in out, left, failed) == (0, 1, True, True, True, [], 100),
          repr((code, calls, prefs, out, left, failed)))
    text = _priv119._REMOTE_ACTIONS["os-update-run"]([])
    check("remote: ...and the OS update job writes the keeps before the host's own records too",
          text.index("Pin-Priority: 32000") < text.index("cat /etc/apt/preferences"), text[:300])


# ── 5. install.sh: the keep, and "up to date" only when it is ──────────────────────────────────────
def _install_text119():
    return open(os.path.join(_root, "install.sh"), encoding="utf-8").read()


def _install_keep119():
    text = _install_text119()
    i = text.index("\n_r34a_keep_installed() {\n") + 1
    fn = text[i:text.index("\n}\n", i) + 3]
    d, _calls, own = _bin119("install")
    out, err, rc = _bash119("set -euo pipefail\nwarn() { echo \"WARN $*\"; }\n_R34A_KEEP_OPTS=()\n"
                            + fn.replace("/etc/apt/preferences", own) + "_r34a_keep_installed\n"
                            "printf 'OPT<%s>\\n' \"${_R34A_KEEP_OPTS[@]}\"\ncat \"${_R34A_KEEP_DIR}/preferences\"\n"
                            "rm -rf -- \"${_R34A_KEEP_DIR}\"\n", _env119(d, TMPDIR=d))
    kept_first = _KEEP119 in out and out.index(_KEEP119) < out.index(_OWN119.strip())
    said = all(w in out for w in ("OPT<-o>", "OPT<Dir::Etc::Preferences=", "WARN Kept"))
    check("install.sh: a package the plan would DOWNGRADE is kept for the installer's full-upgrade, through a "
          "preferences file whose keeps come before the host's records (apt refused the whole run)",
          (rc, said, kept_first) == (0, True, True), repr((out, err[-300:])))
    calls_with = [ln for ln in text.splitlines() if "--force-confold" in ln and "_r30a_apt_ni" in ln]
    check("install.sh: ...and BOTH of its full-upgrades (update path, fresh install) are handed the keep",
          ([("${_R34A_KEEP_OPTS[@]}" in ln) for ln in calls_with],
           text.count("\n                _r34a_keep_installed\n"), text.count("\n    _r34a_keep_installed\n"))
          == ([True, True], 1, 1), repr(calls_with))


def _install_uptodate119():
    text = _install_text119()
    block = text[text.index("# ── One-time full OS upgrade"):text.index("# ── Automatic OS security updates")]
    block = block[block.index("if [[ "):]
    got = {}
    for case, rc_up in (("upgrade refused", "100"), ("upgrade ok", "0")):
        out, err, rc = _bash119(
            "set -euo pipefail\ninfo() { :; }\nwarn() { echo \"WARN $*\"; }\nok() { echo \"OK $*\"; }\n"
            "_r34a_keep_installed() { _R34A_KEEP_OPTS=(); _R34A_KEEP_DIR=''; }\n"
            "_r30a_apt_ni() { shift; case \" $* \" in *' full-upgrade '*) return %s;; esac; return 0; }\n"
            "command() { return 0; }\nid() { echo 0; }\n%s" % (rc_up, block), _env119(_TMP119))
        got[case] = (rc, "OK System packages up to date" in out, "WARN Some packages" in out, err[-200:])
    check("install.sh: a fresh install's refused upgrade no longer also prints 'System packages up to date'",
          (got["upgrade refused"][:3], got["upgrade ok"][:3]) == ((0, False, True), (0, True, False)), repr(got))


# ── 6. uninstall.sh: the recorded port when config.json's cannot be read ───────────────────────────
def _uninstall119():
    text = open(os.path.join(_root, "uninstall.sh"), encoding="utf-8").read()
    rec = text[text.index('_R32A_REC_PORT=""'):text.index("\n# ── Stop + remove the service")]
    warn = text[text.index('if [[ -z "${PANEL_PORT}" ]] && command -v ufw'):
                text.index('_r32a_cfg_port="${PANEL_PORT}"')]
    ufw_end, tsl_end = 'PANEL_PORT="${_r32a_cfg_port}"\n', 'PANEL_PORT="${_r32a_ts_port}"\n'
    ufw = text[text.index('_r32a_cfg_port="${PANEL_PORT}"'):text.index(ufw_end) + len(ufw_end)]
    tsl = text[text.index('_r32a_ts_port="${PANEL_PORT}"'):text.index(tsl_end) + len(tsl_end)]
    panel_dir, other = os.path.join(_TMP119, "inst"), os.path.join(_TMP119, "other")
    for dd in (panel_dir, other):
        os.makedirs(dd, exist_ok=True)
    conf, state = os.path.join(_TMP119, "shared.conf"), os.path.join(_TMP119, "ufw-state")
    shims = ('warn() { echo "WARN $*"; }\nok() { echo "OK $*"; }\nsudo_note() { :; }\nU_SUDO=""\n'
             'ufw() { case "$1" in\n'
             '  show) cat "$UFW_STATE" ;;\n'
             '  delete) grep -vxF "ufw $2 $3" "$UFW_STATE" > "$UFW_STATE.n" || true;'
             ' mv -f "$UFW_STATE.n" "$UFW_STATE" ;;\n'
             '  esac; return 0; }\n'
             'tailscale() { :; }\n_ts_sudo_note_first() { return 0; }\n'
             '_ts_panel_routes() { echo "ROUTES<$1>"; }\n_ts_remove_routes() { echo "REMOVE $1"; }\n')
    got = {}
    for case, owner in (("this install's record", panel_dir), ("another install's record", other)):
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("panel_dir=%s\npanel_port=5000\n" % owner)
        with open(state, "w", encoding="utf-8") as fh:
            fh.write("ufw allow 5000/tcp\n")
        out, err, rc = _bash119("set -euo pipefail\nPANEL_DIR=%s\nSHARED_CONF=%s\nUFW_STATE=%s\nPANEL_PORT=''\n"
                                "TS_DONE=0\nTS_CONF_UNREAD=1\n%s%s\n%s%s\n%s\n"
                                % (panel_dir, conf, state, shims, rec, warn, ufw, tsl),
                                dict(os.environ, LC_ALL="C.UTF-8"))
        with open(state, encoding="utf-8") as fh:
            got[case] = (fh.read(), [ln for ln in out.split("\n") if ln.startswith("REMOVE")],
                         "Could not read the panel's port" in out, rc, err[-200:])
    check("uninstall.sh: with config.json's port unreadable, the port panel.conf records for THIS install loses "
          "its rule and its Serve routes (both were left on a host with no panel behind them)",
          got["this install's record"][:4] == ("", ["REMOVE ROUTES<5000>"], False, 0), repr(got))
    check("uninstall.sh: ...and another install's recorded port is still never touched, and the warning stays "
          "(control)", got["another install's record"][:4] == ("ufw allow 5000/tcp\n", [], True, 0), repr(got))


# ── 7. the debug report's file never says whether a remote runs commands under sudo ────────────────
def _report_sudo119():
    files, pages = {}, {}
    for login in ("root", "non-root"):
        files[login], pages[login] = _hosts_report117(login)
    check("debug report: the Hosts section's file no longer says, per remote, whether the panel runs its "
          "commands under sudo (`sudo yes` stated the privilege model there)",
          "- host 2 · key" in files["root"] and "sudo yes" not in files["root"] and "sudo no" not in files["root"]
          and not _base119.POSTURE_RE.search(files["root"]), files["root"][:600])
    check("debug report: ...and it is on the page instead, beside the login class",
          "**Host 2 login**: root · sudo yes" in pages["root"]
          and "**Host 3 login**: non-root · sudo no" in pages["non-root"], repr(pages))
    held = [_base119.POSTURE_RE.search(s) is not None for s in (
        "- host 2 · key (paramiko, pooled) · port 22 · sudo yes · address private IPv4 · host key pinned",
        "- host 2 · key (paramiko, pooled) · port 22 · address private IPv4 · host key pinned")]
    check("debug report: the posture backstop withholds a host line still naming its sudo use, not one without",
          held == [True, False], repr(held))


# ── 8. the helper's line-by-line content rules split lines as cron does ────────────────────────────
def _lines119():
    rule = _h119.content_cron_line_re("p119u")
    good = ("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "5 1 * * 0 p119u /home/p119u/gmodserver update > /dev/null 2>&1\n")
    bad = {name: good.replace("2>&1\n", "2>&1" + sep + "#;touch /tmp/p119\n", 1)
           for name, sep in (("form feed", "\x0c"), ("vertical tab", "\x0b"), ("CR", "\r"),
                             ("NEL", "\x85"), ("line separator", "\u2028"))}
    got = {name: _h119._lines_match(body, rule) for name, body in bad.items()}
    check("helper: a cron body whose line hides `#;<cmd>` behind a form feed (or any line break cron does not "
          "split on) is refused (str.splitlines read a valid entry and a skipped comment; cron runs <cmd>)",
          not any(got.values()), repr(got))
    check("helper: ...and the panel's own body is still accepted (control)", _h119._lines_match(good, rule), "")


# ── 9. the Tailscale page's Enable form: a route to the pending port is the panel's own ───────────
def _enable_mount119():
    info = NS(serve_config=_serve_table117({"/": 6000}))
    got = {}
    for case, stored in (("pending port's route", 6000), ("another app's", 7000)):
        with _boot116(BOOT_PORT=5000), _p9.app_context():
            got[case] = _tsr119._serve_default_mount(info, {"port": stored, "tailscale_mount": "/"}, 5000)
    check("Tailscale page: a route at / to the port a saved change waits to move to is the panel's own, so "
          "Enable offers / (it was read as another app's and pushed the panel to /lgsm)",
          got == {"pending port's route": "/", "another app's": "/lgsm"}, repr(got))


try:
    _p9_arm(who="part119")
    _f2b_boot119()
    _p9_restore_all()
    _p9_arm(who="part119")
    _rebind119(_p9_client(P9_ADMIN))
    _p9_restore_all()
    _p9_arm(who="part119")
    for _fn119 in (_os_update119, _undecodable119, _helper_prefs_order119, _verb_local119, _verb_remote119,
                   _install_keep119, _install_uptodate119, _uninstall119, _report_sudo119, _lines119, _enable_mount119):
        _fn119()
        _p9_restore_all()
        _p9_arm(who="part119")
finally:
    _p9_restore_all()
    _p9_cfg.save_config(_CFG119)
    _shutil119.rmtree(_TMP119, ignore_errors=True)

check("part119: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP119_START, repr(_P9_TRIPPED[_TRIP119_START:][:6]))
