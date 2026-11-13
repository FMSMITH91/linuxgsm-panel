"""Part 186 of the unit suite: which account a root run of the installer works in the panel's tree as.

Held here:
* install.sh asked `stat -c %U PANEL_DIR`, which reads the ENTRY in the panel user's home, not the
  directory it leads to. With fs.protected_hardlinks=0 the panel user can hard-link a root-owned
  symlink there: relative, it resolves into the panel's own tree; absolute, into any root-owned
  directory. Either read as "root's tree", so _owner_read, choose_and_record_port, fetch_code's
  extract, install_deps (pip over a requirements file), the snapshot/rollback's TREE_SUDO and the
  panel.conf port record all ran as root. _r42i_tree_owner decides now: a real directory by its
  owner, a link only when root made it under its one name and its target is beyond the panel
  user's reach, anything else as the panel user. uninstall.sh's _conf_read reads through any link
  as the panel user.
* Controls: a root-owned tree (a fresh install), the panel's own tree, an operator's root-made
  link (to a root-owned and to the panel's directory), the panel user's own link, and nothing there.

HOW IT RUNS. Each caller, cut out of install.sh / uninstall.sh and run under bash in a throwaway
directory, with `id` answering as root, `stat` reporting the owners each layout stands for (this
account's files are reported as root's or as the panel user's, by path), `sudo` recording the
account and running the rest as this account, and python3 recorded instead of run. The links are
real: a hard link to a symlink this account made. Nothing here reads or writes /etc, sudo, the
network, or the checkout's data/.
"""
import atexit as _atexit186
import os
import pwd as _pwd186
import shutil as _shutil186
import stat as _stat186
import subprocess as _sp186  # nosec B404 - bash over the repo's own scripts, in a throwaway dir
import tempfile as _tf186

from unit.part01 import check, skip
from unit import REPO_ROOT as _root

_TMP186 = _tf186.mkdtemp(prefix="p186-")
_atexit186.register(_shutil186.rmtree, _TMP186, True)


def _read186(name):
    with open(os.path.join(_root, name), encoding="utf-8") as fh:
        return fh.read()


_INS186 = _read186("install.sh")
_UNI186 = _read186(os.path.join("panel", "install", "uninstall.sh"))


def _fn186(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


def _between186(src, start, end):
    i = src.find(start)
    return src[i:src.index(end, i)] if i >= 0 else "exit 97\n"


_ME186 = _pwd186.getpwuid(os.getuid()).pw_name
_STUBS186 = r"""
id() {
    if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0
    elif [ "$#" -eq 2 ] && [ "$1" = -u ]; then
        case "$2" in lgsmpanel) echo 4242 ;; root) echo 0 ;; *) return 1 ;; esac
    elif [ "$#" -eq 2 ] && [ "$1" = -G ] && [ "$2" = lgsmpanel ]; then echo 4242
    elif [ "$#" -eq 1 ] && [ "$1" = lgsmpanel ]; then return 0
    else command id "$@"; fi
}
_r42i_as() {   # _r42i_as <path>: root|panel, by the layout's P186_ROOTS (exact) and P186_PANEL (prefixes)
    local x
    for x in ${P186_ROOTS:-}; do [ "$1" = "$x" ] && { echo root; return 0; }; done
    for x in ${P186_PANEL:-}; do case "$1" in "$x"|"$x"/*) echo panel; return 0 ;; esac; done
    echo root
}
stat() {
    local p="${!#}" out
    out="$(command stat "$@")" || return $?
    [ -z "${P186_BADMODE:-}" ] || out="$(printf '%s\n' "$out" | sed -E '1s/^[0-9a-f]+ /? /')"
    if [ "$(_r42i_as "$p")" = panel ]; then
        printf '%s\n' "$out" | sed -E "s/\b${ME_UID}\b/4242/g; s/\b${ME_NAME}\b/lgsmpanel/g"
    else
        printf '%s\n' "$out" | sed -E "s/\b${ME_UID}\b/0/g; s/\b${ME_NAME}\b/root/g"
    fi
}
sudo() { echo "AS $2" >> "$P186_LOG"; shift 2; "$@"; }
python3() { cat >/dev/null 2>&1; return 0; }
ok() { :; }; warn() { :; }; info() { :; }; die() { exit 9; }
"""

_HELPERS186 = "".join(_fn186(_INS186, n) for n in ("_r42i_tree_owner", "_r26a_fixed_target", "_panel_ids",
                                                    "_panel_cannot_write"))
_TREE186 = _between186(_INS186, '    TREE_SUDO=""\n', "    snapshot_service_unit\n")
_CONF186 = _between186(_UNI186, "_conf_read() {", "\n}\n") + "\n}\n"
# Each caller, its own section of the log; a subshell each, so one that stops ends only itself.
_CALLERS186 = (
    ("_owner_read", _fn186(_INS186, "_owner_read"), '_owner_read "${PANEL_DIR}/VERSION" >/dev/null'),
    ("choose_and_record_port", _fn186(_INS186, "choose_and_record_port"), "choose_and_record_port 5000"),
    ("install_deps", _fn186(_INS186, "install_deps")
     + 'panel_file() { echo "${PANEL_DIR}/$1"; }\n_venv_stale() { return 1; }\n', "install_deps"),
    ("TREE_SUDO", "", _TREE186 + '[ -z "${TREE_SUDO}" ] || ${TREE_SUDO} true\n'),
    ("panel.conf port", "".join(_fn186(_INS186, n) for n in ("_r25j_panel_port_to_record", "_r25j_is_panel_port"))
     + "_r26a_cfg_port() { echo 5002; }\n_R25J_CHOSEN_PORT=''\n"
     + '_r32a_owner_listens() { echo "UID $2" >> "$P186_LOG"; return 1; }\n'
     + '_r25j_port_held_by_other() { echo "UID $2" >> "$P186_LOG"; return 0; }\n',
     '_r25j_panel_port_to_record "$P186_CONF" >/dev/null'),
    ("uninstall _conf_read", _CONF186, '_conf_read "${PANEL_DIR}/data/config.json" >/dev/null'),
    # Last: with nothing there, its mkdir makes the tree the callers above would then find.
    ("fetch_code", _fn186(_INS186, "fetch_code"), "fetch_code"),
)


def _accounts186(lines):
    """The accounts one caller's section of the log names: `root` when it never switched."""
    names = set()
    for ln in lines:
        if ln.startswith("AS "):
            names.add(ln[3:])
        elif ln.startswith("UID "):
            names.add({"4242": "lgsmpanel", "0": "root"}.get(ln[4:], "uid " + ln[4:]))
    return ",".join(sorted(names)) or "root"


def _run186(panel_dir, roots=(), panel=(), badmode=""):
    """{caller: accounts} for every caller over PANEL_DIR, owners as `roots`/`panel` stand for."""
    d = _tf186.mkdtemp(dir=_TMP186)
    log, conf, src = os.path.join(d, "log"), os.path.join(d, "panel.conf"), os.path.join(d, "src")
    os.makedirs(src)
    with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as fh:
        fh.write("# app\n")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write("panel_port=5001\n")
    body = ""
    for name, fns, call in _CALLERS186:
        body += 'echo "== %s" >> "$P186_LOG"\n( %s\n%s\n) </dev/null >/dev/null 2>&1\n' % (name, fns, call)
    env = dict(os.environ, PANEL_DIR=panel_dir, PANEL_USER="lgsmpanel", SRC=src, P186_LOG=log, P186_CONF=conf,
               P186_ROOTS=" ".join(roots), P186_PANEL=" ".join(panel), P186_BADMODE=badmode, ME_UID=str(os.getuid()), ME_NAME=_ME186)
    r = _sp186.run(["bash", "-c", "set +e\n" + _STUBS186 + _HELPERS186 + body], cwd=d,  # nosec B603 B607
                   capture_output=True, text=True, stdin=_sp186.DEVNULL, timeout=60, env=env,
                   start_new_session=True)
    got, cur = {}, None
    try:
        with open(log, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        lines = []
    sections = {}
    for ln in lines:
        if ln.startswith("== "):
            cur = ln[3:]
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(ln)
    for name, _fns, _call in _CALLERS186:
        got[name] = _accounts186(sections[name]) if name in sections else "not run: " + r.stderr[-200:]
    # The port record asks nothing when there is no tree to ask about.
    if "panel.conf port" in sections and not sections["panel.conf port"]:
        got["panel.conf port"] = "none"
    return got


def _layout186(tag):
    """A home the panel user owns, its tree, and a root-owned directory outside it."""
    base = os.path.join(_TMP186, tag)
    home, tree, rootdir, bindir = (os.path.join(base, n) for n in ("home", "home/python3.12", "srv/rootdir", "bin"))
    for p in (tree, rootdir, bindir, os.path.join(tree, "data")):
        os.makedirs(p)
    return base, home, tree, rootdir, bindir


def _expect186(account, uninstall=None, port=None):
    out = {name: account for name, _f, _c in _CALLERS186}
    out["panel.conf port"] = port or account
    out["uninstall _conf_read"] = uninstall or account
    return out


_R42I_PANEL_ALL = _expect186("lgsmpanel")
_R42I_ROOT_ALL = _expect186("root")

# 1. The report's case: a hard link to a root-owned RELATIVE symlink, resolving into the panel's tree.
_b1, _h1, _t1, _r1, _bin1 = _layout186("rel")
os.symlink("python3.12", os.path.join(_bin1, "python3"))
_pd1 = os.path.join(_h1, "linuxgsm-panel")
_hard_ok186 = True
try:
    os.link(os.path.join(_bin1, "python3"), _pd1, follow_symlinks=False)
except OSError:
    _hard_ok186 = False
# 2. The same with an ABSOLUTE root-owned symlink, to a directory root owns outside the home.
_b2, _h2, _t2, _r2, _bin2 = _layout186("abs")
os.symlink(_r2, os.path.join(_bin2, "run"))
_pd2 = os.path.join(_h2, "linuxgsm-panel")
try:
    os.link(os.path.join(_bin2, "run"), _pd2, follow_symlinks=False)
except OSError:
    _hard_ok186 = False

if _hard_ok186:
    _premise186 = (_stat186.S_ISLNK(os.lstat(_pd1).st_mode) and os.lstat(_pd1).st_nlink == 2
                   and os.path.realpath(_pd1) == os.path.realpath(_t1)
                   and os.path.realpath(_pd2) == os.path.realpath(_r2))
    check("part186 premise: a hard link to a relative symlink is a symlink entry with two names that "
          "resolves next to its NEW name (into the panel's tree); an absolute one, to its target",
          _premise186, "%r %r" % (os.path.realpath(_pd1), os.path.realpath(_pd2)))
    _rel186 = _run186(_pd1, roots=(_pd1,), panel=(_h1,))
    check("install.sh: a root-owned symlink the panel user hard-linked in as PANEL_DIR, resolving into "
          "its own tree, is not read as root's tree: _owner_read, choose_and_record_port, fetch_code's "
          "extract, install_deps, TREE_SUDO and the panel.conf port record run as the panel user, and "
          "uninstall.sh reads config.json as it", _rel186 == _R42I_PANEL_ALL, repr(_rel186))
    _abs186 = _run186(_pd2, roots=(_pd2,), panel=(_h2,))
    check("install.sh: ...nor one whose absolute target is a root-owned directory (the rollback's rm "
          "and tar ran as root there): a root link with a second name is never the operator's",
          _abs186 == _R42I_PANEL_ALL, repr(_abs186))
else:
    skip("install.sh: a hard-linked root symlink as PANEL_DIR", "this filesystem refused a hard link to a symlink")

# 3-8. Controls.
_b3, _h3, _t3, _r3, _bin3 = _layout186("rootdir")
_pd3 = os.path.join(_h3, "linuxgsm-panel")
os.makedirs(os.path.join(_pd3, "data"))
_ctl186 = {"root's own tree (a fresh install)": (_run186(_pd3, roots=(_pd3,), panel=(_h3,)), _R42I_ROOT_ALL)}
_ctl186["the panel's own tree"] = (_run186(_pd3, panel=(_h3,)), _R42I_PANEL_ALL)
_ctl186["a stat whose %f is not hex, over root's tree"] = (_run186(_pd3, roots=(_pd3,), panel=(_h3,), badmode="1"),
                                                         _R42I_PANEL_ALL)
_b4, _h4, _t4, _r4, _bin4 = _layout186("oplink")
_pd4 = os.path.join(_h4, "linuxgsm-panel")
os.symlink(_r4, _pd4)
_ctl186["an operator's root link to a root-owned directory"] = (
    _run186(_pd4, roots=(_pd4,), panel=(_h4,)), _expect186("root", uninstall="lgsmpanel"))
_ctl186["an operator's root link to the panel's directory"] = (
    _run186(_pd4, roots=(_pd4,), panel=(_h4, _r4)), _R42I_PANEL_ALL)
_ctl186["the panel user's own link to a root-owned directory"] = (_run186(_pd4, panel=(_h4,)), _R42I_PANEL_ALL)
_pd8 = os.path.join(_TMP186, "gone", "linuxgsm-panel")
os.makedirs(os.path.dirname(_pd8))
_gone186 = _run186(_pd8, roots=(_pd8,))
_gone_want186 = _expect186("root", port="none")
_ctl186["nothing there yet"] = (_gone186, _gone_want186)
check("install.sh: ...while a real directory is judged by its owner, an operator's single-name root link "
      "by its target's (when the panel user cannot redirect it), the panel user's own link as the panel "
      "user, a mode it cannot read as the panel user, and a fresh install (nothing there, or root's tree) "
      "stays root (controls)",
      all(got == want for got, want in _ctl186.values()),
      repr({k: v[0] for k, v in _ctl186.items() if v[0] != v[1]}))

_ins_left186 = _INS186.count("stat -c '%U' \"${PANEL_DIR}\"") + _INS186.count("stat -c '%u' \"${PANEL_DIR}\"")
check("install.sh/uninstall.sh: no step takes the tree's account from PANEL_DIR's entry any more "
      "(every one asks _r42i_tree_owner; uninstall.sh's _conf_read reads a link as the panel user)",
      _ins_left186 == 0 and "stat -c '%U' \"${PANEL_DIR}\"" not in _UNI186
      and _INS186.count("$(_r42i_tree_owner)") == 6, repr(_ins_left186))
