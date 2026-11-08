"""Part 165 of the unit suite: the twenty-seventh review's installer fixes (builder D, review 1109).

Held here, each against the code path the finding named:

* the documented way to drop the panel host's root grant (delete /etc/sudoers.d/linuxgsm-panel, then
  update by hand) was undone by that very update, every time. The choice is recorded root-owned now
  (panel.conf's local_grant, PANEL_LOCAL_GRANT=0|1, unset keeps it); an update that finds the file
  already deleted and nothing recorded honours the deletion and records it; write_sudoers_grant and
  write_terminal_sudo_grant both remove their files and write none while it is "no".
* uninstall.sh re-run after a system uninstall that stopped part-way answered "nothing to remove"
  while the panel account, its grants and the root-owned pieces were still there.
* a by-hand update of a panel switched to another branch moved the code to main while config.json
  went on naming that branch; it now stops before fetching and names both ways on.
* the unit suite's tailscale guard lost a nested shell's double-quoted -c script holding a separator.

HOW IT RUNS. install.sh's and uninstall.sh's own text, cut out and run under bash in a throwaway
directory, with every /etc path pointed into it and `id`, `visudo`, `_owner_read` stood in. Nothing
here reads or writes this machine's /etc, sudo, or the checkout's data/.
"""
import atexit as _atexit165
import os
import shutil as _shutil165
import subprocess as _sp165  # nosec B404 - bash over the repo's own scripts, in a throwaway dir
import tempfile as _tf165

from unit import ts_nested as _tn165
from unit.part01 import check
from unit.part05 import _root

_TMP165 = _tf165.mkdtemp(prefix="p165-")
_atexit165.register(_shutil165.rmtree, _TMP165, True)


def _read165(name):
    with open(os.path.join(_root, name), encoding="utf-8") as fh:
        return fh.read()


_INS165 = _read165("install.sh")
_UNI165 = _read165("uninstall.sh")


def _fn165(src, name):
    """The text of shell function `name` in `src`, from its `name() {` line to its closing `}`."""
    i = src.find("\n%s() {" % name)
    if i < 0:
        return "%s() { exit 97; }\n" % name
    return src[i + 1:src.index("\n}\n", i) + 3]


def _bash165(script, env=None):
    """Run `script` under bash with no terminal; (rc, stdout + stderr)."""
    base = {k: v for k, v in os.environ.items()
            if k not in ("PANEL_LOCAL_GRANT", "PANEL_SELF_UPDATE", "PANEL_TERMINAL_SUDO", "PANEL_BRANCH",
                         "SHARED_CONF")}
    base.update(env or {})
    r = _sp165.run(["bash", "-c", script], cwd=_TMP165, capture_output=True, text=True,  # nosec B603 B607
                   stdin=_sp165.DEVNULL, timeout=60, env=base, start_new_session=True)
    return r.returncode, r.stdout + r.stderr


_STUBS165 = ("ok(){ echo \"OK: $*\"; }\nwarn(){ echo \"WARN: $*\"; }\ninfo(){ echo \"INFO: $*\"; }\n"
             "die(){ echo \"DIE: $*\"; exit 9; }\n")

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The panel host's root grant: the operator's choice, recorded, and kept by every update
# ════════════════════════════════════════════════════════════════════════════════════════════════


def _choice165(env_val=None, record=None, is_update=1, as_root=1, grant_file=True, self_update=False):
    """What _r39d_local_grant_choice prints, with the sudoers dir pointed at a throwaway one."""
    d = _tf165.mkdtemp(dir=_TMP165)
    sd = os.path.join(d, "sudoers.d")
    os.makedirs(sd)
    if grant_file:
        with open(os.path.join(sd, "linuxgsm-panel"), "w", encoding="utf-8") as fh:
            fh.write("lgsmpanel ALL=(root) NOPASSWD: /x\n")
    conf = os.path.join(d, "panel.conf")
    if record is not None:
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("panel_dir=/x\n%s" % record)
    fn = _fn165(_INS165, "_r39d_local_grant_choice").replace("/etc/sudoers.d", sd)
    env = {"IS_UPDATE": str(is_update), "RUN_AS_ROOT": str(as_root)}
    if env_val is not None:
        env["PANEL_LOCAL_GRANT"] = env_val
    if self_update:
        env["PANEL_SELF_UPDATE"] = "1"
    rc, out = _bash165("set -euo pipefail\n%s\n_r39d_local_grant_choice '%s'\n" % (fn, conf), env)
    return rc, out.strip()


_lg165 = {
    "env 0": _choice165("0"),
    "env 1 over a recorded no": _choice165("1", "local_grant=no\n"),
    "recorded no, grant file present": _choice165(None, "local_grant=no\n"),
    "recorded yes, grant file deleted": _choice165(None, "local_grant=yes\n", grant_file=False),
    "update, nothing recorded, grant file deleted": _choice165(None, "", grant_file=False),
    "update, nothing recorded, grant file present": _choice165(None, ""),
    "fresh install, no grant file yet": _choice165(None, None, is_update=0, grant_file=False),
    "per-user update, no grant file": _choice165(None, None, as_root=0, grant_file=False),
    "env 1 on a run the panel started": _choice165("1", "local_grant=no\n", self_update=True),
    "a record that is not yes|no": _choice165(None, "local_grant=maybe\n"),
}
check("install.sh: the root-grant choice is PANEL_LOCAL_GRANT when set; else the one panel.conf "
      "recorded (an update never changes it); else no for a root update whose grant file was "
      "already deleted (the operator removed it as SECURITY.md said); else yes; and a run the panel "
      "started never takes the answer from the environment",
      _lg165 == {"env 0": (0, "no env"), "env 1 over a recorded no": (0, "yes env"),
                 "recorded no, grant file present": (0, "no kept"),
                 "recorded yes, grant file deleted": (0, "yes kept"),
                 "update, nothing recorded, grant file deleted": (0, "no deleted"),
                 "update, nothing recorded, grant file present": (0, "yes default"),
                 "fresh install, no grant file yet": (0, "yes default"),
                 "per-user update, no grant file": (0, "yes default"),
                 "env 1 on a run the panel started": (0, "no kept"),
                 "a record that is not yes|no": (0, "yes default")}, repr(_lg165))

_irt165 = _fn165(_INS165, "install_root_tools")
_rd165 = _irt165.find("_r39d_local_grant_choice")
_ret165 = _irt165.find("return 0")
_wr165 = _irt165.find('tee "${PANEL_CONF}"')
check("install.sh: install_root_tools reads the root-grant choice before its first early return and "
      "before it rewrites panel.conf, and records it as `local_grant=` beside tailscale_ssh",
      0 <= _rd165 < _ret165 and _rd165 < _wr165 and "\\nlocal_grant=%s\\n" in _irt165
      and '"${LOCAL_GRANT_CHOICE}"' in _irt165[_rd165:_wr165 + 400], repr((_rd165, _ret165, _wr165)))
_order165 = [(_INS165.rfind("install_root_tools", 0, i), i)
             for i in [j for j in range(len(_INS165)) if _INS165.startswith("write_sudoers_grant\n", j)
                       and not _INS165.startswith("write_sudoers_grant() {", j)]]
check("install.sh: every write_sudoers_grant call runs after an install_root_tools call (which reads "
      "the choice it acts on)",
      len(_order165) >= 3 and all(0 <= a < b for a, b in _order165), repr(_order165))


def _grants165(choice, terminal_env=None, have_main=True, have_term=False):
    """Run write_sudoers_grant then write_terminal_sudo_grant with LOCAL_GRANT_CHOICE=`choice`.

    Returns (rc, output, main grant lines or None, terminal file exists).
    """
    d = _tf165.mkdtemp(dir=_TMP165)
    sd = os.path.join(d, "sudoers.d")
    os.makedirs(sd)
    main, term = os.path.join(sd, "linuxgsm-panel"), os.path.join(sd, "00-linuxgsm-panel-terminal")
    if have_main:
        with open(main, "w", encoding="utf-8") as fh:
            fh.write("lgsmpanel ALL=(ALL) NOPASSWD:ALL\n")
    if have_term:
        with open(term, "w", encoding="utf-8") as fh:
            fh.write("lgsmpanel ALL=(ALL) ALL\n")
    script = ("RUN_AS_ROOT=1 HELPER_OK=1 ROOT_TOOLS_OK=1 PANEL_USER=lgsmpanel GAME_GROUP=lgsmpanel-games\n"
              "HELPER_DIR=/usr/local/lib/linuxgsm-panel\n"
              "HELPER_DST=/usr/local/lib/linuxgsm-panel/panel-helper\n"
              "HELPER_SECURE_PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
              "LOCAL_GRANT_CHOICE=%s\n"
              "sync_game_user_group(){ :; }\nroot_tools_present(){ return 0; }\n"
              "visudo(){ return 0; }\npasswd(){ echo 'lgsmpanel P'; }\n" % choice
              + _STUBS165
              + _fn165(_INS165, "write_sudoers_grant").replace("/etc/sudoers.d", sd)
              + _fn165(_INS165, "write_terminal_sudo_grant").replace("/etc/sudoers.d", sd)
              + "write_sudoers_grant\nwrite_terminal_sudo_grant\necho \"[rc=$?]\"\n")
    env = {} if terminal_env is None else {"PANEL_TERMINAL_SUDO": terminal_env}
    rc, out = _bash165(script, env)
    lines = open(main, encoding="utf-8").read().splitlines() if os.path.exists(main) else None
    return rc, out, lines, os.path.exists(term)


_no165 = _grants165("no", have_term=True)
check("install.sh write_sudoers_grant: local_grant=no removes /etc/sudoers.d/linuxgsm-panel and writes "
      "none, and says how to put it back (PANEL_LOCAL_GRANT=1)",
      _no165[0] == 0 and _no165[2] is None and "PANEL_LOCAL_GRANT=1" in _no165[1]
      and "[rc=0]" in _no165[1] and "DIE:" not in _no165[1], repr((_no165[0], _no165[2], _no165[1][-700:])))
check("install.sh write_terminal_sudo_grant: ...and the host-terminal grant goes with it",
      _no165[3] is False and "local_grant=no" in _no165[1], _no165[1][-700:])
_noterm165 = _grants165("no", terminal_env="1", have_main=False)
check("install.sh write_terminal_sudo_grant: PANEL_TERMINAL_SUDO=1 does not bring a grant back while "
      "local_grant=no, and says why",
      _noterm165[3] is False and _noterm165[2] is None
      and "WARN: PANEL_TERMINAL_SUDO=1 ignored" in _noterm165[1], _noterm165[1][-700:])
_yes165 = _grants165("yes", terminal_env="1")
check("install.sh write_sudoers_grant: local_grant=yes still writes the narrow grant, and "
      "PANEL_TERMINAL_SUDO=1 still writes the terminal one (control)",
      _yes165[0] == 0 and _yes165[2] is not None and len(_yes165[2]) == 3
      and _yes165[2][1] == "lgsmpanel ALL=(root) NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper"
      and _yes165[3] is True, repr((_yes165[0], _yes165[2], _yes165[1][-500:])))


def _docs_path165():
    """The update SECURITY.md prescribes, end to end: grant deleted by hand, nothing recorded, update."""
    d = _tf165.mkdtemp(dir=_TMP165)
    sd = os.path.join(d, "sudoers.d")
    os.makedirs(sd)
    conf = os.path.join(d, "panel.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write("panel_dir=/x\ntailscale_ssh=no\n")
    script = ("RUN_AS_ROOT=1 IS_UPDATE=1 HELPER_OK=1 ROOT_TOOLS_OK=1 PANEL_USER=lgsmpanel\n"
              "GAME_GROUP=lgsmpanel-games HELPER_DIR=/usr/local/lib/linuxgsm-panel\n"
              "HELPER_DST=/usr/local/lib/linuxgsm-panel/panel-helper HELPER_SECURE_PATH=/usr/bin\n"
              "sync_game_user_group(){ :; }\nroot_tools_present(){ return 0; }\nvisudo(){ return 0; }\n"
              + _STUBS165
              + _fn165(_INS165, "_r39d_local_grant_choice").replace("/etc/sudoers.d", sd)
              + _fn165(_INS165, "write_sudoers_grant").replace("/etc/sudoers.d", sd)
              + "read -r LOCAL_GRANT_CHOICE _w <<< \"$(_r39d_local_grant_choice '%s')\"\n" % conf
              + "write_sudoers_grant\necho \"[choice=${LOCAL_GRANT_CHOICE} why=${_w}]\"\n")
    rc, out = _bash165(script)
    return rc, out, os.path.exists(os.path.join(sd, "linuxgsm-panel"))


_dp165 = _docs_path165()
check("install.sh: an update after the operator deleted /etc/sudoers.d/linuxgsm-panel by hand (the "
      "documented way to drop it) leaves it deleted instead of writing it straight back",
      _dp165[0] == 0 and _dp165[2] is False and "[choice=no why=deleted]" in _dp165[1],
      repr((_dp165[0], _dp165[2], _dp165[1][-600:])))
_sec165 = _read165(os.path.join(".github", "SECURITY.md"))
_hdr165 = _INS165[:_INS165.index("REPO_URL=")]
check("SECURITY.md and install.sh's own notes name the switch (PANEL_LOCAL_GRANT=0), not \"delete the "
      "file\" as the way to drop the grant",
      "PANEL_LOCAL_GRANT=0" in _sec165 and "PANEL_LOCAL_GRANT=0" in _hdr165
      and "delete\n#     /etc/sudoers.d/linuxgsm-panel" not in _hdr165
      and "and delete\n    # /etc/sudoers.d/linuxgsm-panel if you only manage remotes" not in _INS165
      and "**If you only manage remote servers from this panel**, delete" not in _sec165)

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. uninstall.sh: a re-run after a partial system uninstall finishes the job
# ════════════════════════════════════════════════════════════════════════════════════════════════
# From the leftover scan to the "Found a ... install" line: the whole decision, whatever its shape.
_U_START165 = _UNI165.find('_r39d_leftover=""\n')
if _U_START165 < 0:
    _U_START165 = _UNI165.find('if [[ ! -e "${UNIT_FILE}" ]] && [[ ! -d "${PANEL_DIR}" ]]')
_UBLK165 = _UNI165[_U_START165:_UNI165.find('info "Found a ${MODE} install:"')] if _U_START165 >= 0 else "exit 3\n"


def _uninst165(mode="system", account=False, files=(), conf_dir=None):
    """Run uninstall.sh's install-detection block; (rc, output). Unit and panel dir are both gone."""
    d = _tf165.mkdtemp(dir=_TMP165)
    etc = os.path.join(d, "etc")
    for sub in ("sudoers.d", "sysctl.d"):
        os.makedirs(os.path.join(etc, sub))
    for f in files:
        with open(os.path.join(etc, f), "w", encoding="utf-8") as fh:
            fh.write("x\n")
    conf = os.path.join(d, "lib", "panel.conf")
    if conf_dir is not None:
        os.makedirs(os.path.dirname(conf))
        with open(conf, "w", encoding="utf-8") as fh:
            fh.write("db_path=/x\npanel_dir=%s\n" % conf_dir)
    script = ("set -euo pipefail\n" + _STUBS165.replace("exit 9", "exit 1")
              + "id(){ %s; }\n" % ("return 0" if account else "return 1")
              + "MODE=%s SERVICE_USER=lgsmpanel PANEL_USER=lgsmpanel\n" % mode
              + "PANEL_DIR=%s/home/lgsmpanel/linuxgsm-panel UNIT_FILE=%s/unit.service\n" % (d, d)
              + "SHARED_CONF=%s\n" % conf
              + _UBLK165.replace("/etc/", etc + "/") + "\necho PROCEEDS\n")
    return _bash165(script)


_PD165 = "/home/lgsmpanel/linuxgsm-panel"
_un165 = {
    "nothing left": _uninst165(),
    "the panel account": _uninst165(account=True),
    "the sudoers grant": _uninst165(files=("sudoers.d/linuxgsm-panel",)),
    "the terminal grant": _uninst165(files=("sudoers.d/00-linuxgsm-panel-terminal",)),
    "the sysctl file": _uninst165(files=("sysctl.d/99-linuxgsm-panel.conf",)),
    "per-user, nothing left": _uninst165(mode="user"),
    "per-user, a stray sudoers grant": _uninst165(mode="user", files=("sudoers.d/linuxgsm-panel",)),
    "panel.conf naming another install": _uninst165(conf_dir="/home/alice/linuxgsm-panel"),
}


def _proceeds165(r):
    return r[0] == 0 and "PROCEEDS" in r[1] and "Nothing to remove" not in r[1]


def _stops165(r):
    return r[0] == 1 and "Nothing to remove" in r[1] and "PROCEEDS" not in r[1]


check("uninstall.sh: a system re-run with the unit and files gone but the panel account, a sudoers "
      "grant or the sysctl file still there finishes the uninstall instead of saying nothing is left",
      all(_proceeds165(_un165[k])
          for k in ("the panel account", "the sudoers grant", "the terminal grant", "the sysctl file"))
      and "finishing an uninstall that stopped part-way" in _un165["the panel account"][1],
      repr(_un165))
check("uninstall.sh: ...and still says nothing to remove when nothing is left, in a per-user run "
      "(those pieces are a system install's), and for a panel.conf naming another install (control)",
      all(_stops165(_un165[k])
          for k in ("nothing left", "per-user, nothing left", "per-user, a stray sudoers grant",
                    "panel.conf naming another install")),
      repr(_un165))


def _uninst_conf_mine165():
    d = _tf165.mkdtemp(dir=_TMP165)
    os.makedirs(os.path.join(d, "lib"))
    pd = os.path.join(d, "home", "lgsmpanel", "linuxgsm-panel")
    conf = os.path.join(d, "lib", "panel.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write("panel_dir=%s\n" % pd)
    script = ("set -euo pipefail\n" + _STUBS165.replace("exit 9", "exit 1") + "id(){ return 1; }\n"
              + "MODE=system SERVICE_USER=lgsmpanel PANEL_USER=lgsmpanel\n"
              + "PANEL_DIR=%s UNIT_FILE=%s/unit.service SHARED_CONF=%s\n" % (pd, d, conf)
              + _UBLK165.replace("/etc/", os.path.join(d, "etc") + "/") + "\necho PROCEEDS\n")
    return _bash165(script)


_mine165 = _uninst_conf_mine165()
check("uninstall.sh: ...and the root-owned set left behind (its panel.conf naming this install) is "
      "an install to finish removing too",
      _proceeds165(_mine165), repr(_mine165))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A by-hand update of a panel switched to another branch stops before fetching
# ════════════════════════════════════════════════════════════════════════════════════════════════


def _tracked165(branch_json, panel_branch_env=None, self_update=False, have_conf=True):
    """What _r39d_tracked_branch prints for a config.json holding `branch_json` (raw JSON text)."""
    d = _tf165.mkdtemp(dir=_TMP165)
    os.makedirs(os.path.join(d, "data"))
    if have_conf:
        with open(os.path.join(d, "data", "config.json"), "w", encoding="utf-8") as fh:
            fh.write(branch_json)
    env = {"PANEL_DIR": d, "TRUSTED_BRANCH": "main"}
    if panel_branch_env is not None:
        env["PANEL_BRANCH"] = panel_branch_env
    if self_update:
        env["PANEL_SELF_UPDATE"] = "1"
    script = ("set -euo pipefail\n_owner_read(){ cat -- \"$1\"; }\n"
              + _fn165(_INS165, "_r39d_tracked_branch") + "\nprintf '[%s]' \"$(_r39d_tracked_branch)\"\n")
    return _bash165(script, env)


_tb165 = {
    "a panel on fix-x": _tracked165('{"panel_branch": "fix-x"}'),
    "a panel on main": _tracked165('{"panel_branch": "main"}'),
    "no panel_branch": _tracked165('{"port": 5000}'),
    "PANEL_BRANCH named": _tracked165('{"panel_branch": "fix-x"}', panel_branch_env="fix-x"),
    "a run the panel started": _tracked165('{"panel_branch": "fix-x"}', self_update=True),
    "no config.json": _tracked165("", have_conf=False),
    "config.json not an object": _tracked165('["fix-x"]'),
}
check("install.sh: _r39d_tracked_branch names the branch config.json tracks only for a by-hand run "
      "that names none, and only when it is not main",
      {k: v[1] for k, v in _tb165.items()}
      == {"a panel on fix-x": "[fix-x]", "a panel on main": "[]", "no panel_branch": "[]",
          "PANEL_BRANCH named": "[]", "a run the panel started": "[]", "no config.json": "[]",
          "config.json not an object": "[]"}
      and all(v[0] == 0 for v in _tb165.values()), repr(_tb165))

_UP165 = _INS165[_INS165.index('if [[ "${IS_UPDATE}" -eq 1 ]]; then\n'):]
_G_START165 = _UP165.find('    _r39d_branch="$(_r39d_tracked_branch)"')
_G_END165 = (_UP165.find("    fi\n", _UP165.find("     Nothing was changed.", _G_START165)) + 7
             if _G_START165 >= 0 else 0)
check("install.sh: the update path asks it before it fetches or changes anything (ahead of "
      "resolve_update_target and ensure_nodejs)",
      0 < _G_START165 < _UP165.find("resolve_update_target") and _G_START165 < _UP165.find("ensure_nodejs"),
      repr(_G_START165))


def _stop165(branch, as_root=1):
    script = ("set -euo pipefail\n" + _STUBS165
              + "_r39d_tracked_branch(){ printf '%%s' '%s'; }\n" % branch
              + "RUN_AS_ROOT=%d TRUSTED_BRANCH=main HELPER_DIR=/usr/local/lib/linuxgsm-panel PANEL_DIR=/p\n"
              % as_root + (_UP165[_G_START165:_G_END165] if _G_START165 >= 0 else "") + "echo GOES-ON\n")
    return _bash165(script)


_st165 = {"root, fix-x": _stop165("fix-x"), "per-user, fix-x": _stop165("fix-x", as_root=0),
          "an unsafe name": _stop165("--upload-pack=x"), "nothing tracked": _stop165("")}
check("install.sh: ...and stops with the command that updates that branch and the way back to main, "
      "changing nothing",
      _st165["root, fix-x"][0] == 9
      and "cd / && sudo PANEL_BRANCH=fix-x bash /usr/local/lib/linuxgsm-panel/install.sh" in _st165["root, fix-x"][1]
      and "switch the panel to main" in _st165["root, fix-x"][1]
      and "Nothing was changed." in _st165["root, fix-x"][1]
      and "GOES-ON" not in _st165["root, fix-x"][1]
      and "PANEL_BRANCH=fix-x bash /p/install.sh" in _st165["per-user, fix-x"][1],
      repr(_st165))
check("install.sh: ...never prints a panel-written name it would not accept as PANEL_BRANCH, and "
      "goes on when nothing is tracked (control)",
      _st165["an unsafe name"][0] == 9 and "upload-pack" not in _st165["an unsafe name"][1]
      and _st165["nothing tracked"][0] == 0 and "GOES-ON" in _st165["nothing tracked"][1],
      repr(_st165))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The unit tailscale guard reads a nested -c script in double quotes that holds a separator
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The split cut `bash -c "sh f.sh; true"` at the `;` inside the quotes, and the unbalanced piece left the
# -c word `"sh`: f.sh was never read, so a tailscale in it was neither shimmed nor judged (review 1109
# T10). Text only, on the runner's own bound reader (unit_test.py binds unit.ts_nested), under the
# runner's Landlock block: nothing here runs a shell.
_tnd165 = _tf165.mkdtemp(dir=_TMP165)
_tnf165 = os.path.join(_tnd165, "inner-165.sh")
with open(_tnf165, "w", encoding="utf-8") as _fh165:
    _fh165.write("tailscale version\n")
_dq165 = {_s: _tn165.shell_text(["bash", "-c", _s % _tnf165], {}) for _s in (
    'bash -c "sh %s; true"', 'bash -c "sh %s && true"', 'bash -c "sh %s | cat"', 'bash -c "sh %s & wait"',
    'bash -c "sh %s"', "bash -c 'sh %s; true'")}
check("unit suite guard: a script file a nested shell's double-quoted -c script runs is read even when "
      "that script holds a separator (; && | &), and the forms read before still are",
      all((_t or "").count("tailscale version") >= 1 for _t in _dq165.values()),
      repr({_k: (_v or "")[-200:] for _k, _v in _dq165.items()}))
