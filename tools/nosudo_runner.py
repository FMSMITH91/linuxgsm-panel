#!/usr/bin/env python3
"""Run a test suite with every privileged command stubbed out.

The smoke and rbac suites boot the real app and render every page. Several of those renders probe
host state — system_ops._check_sudo() runs a genuine `sudo -n true`, and ufw/fail2ban/apt status
calls go through _run(sudo=True). On a machine WITHOUT passwordless sudo each of those is logged as
an authentication failure and counted by pam_faillock, which is how a few dozen suite runs in one
session can lock a developer out of sudo on their own workstation.

Nothing either suite ASSERTS depends on a privileged result: every caller of those probes already
handles "couldn't run it", because that is the path an unprivileged install takes in production. So
this refuses the sudo commands at the three local-exec choke points and lets everything else run
for real. That is faithful to a real unprivileged install, and strictly safer than the alternative
of granting sudo — under which the suite really would run ufw / fail2ban-client / apt / tailscale
against the developer's own machine.

    python tools/nosudo_runner.py tests/smoke_test.py

Prefer tools/smoke-local.sh, which also gives the suite a throwaway data dir.
"""
import os
import re
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BLOCKED = []
# What a real `sudo -n` prints when it wants a password. Callers act on the non-zero rc.
_DENIED = ("", "sudo: a password is required", 1)


def _is_sudo(cmd, sudo_flag=False):
    """Whether this command would escalate. Checks EVERY element, not just argv[0].

    argv[0] alone was not enough, and the shape it missed is the common one: the local privileged
    path builds ["/bin/bash", "-c", "sudo bash -c '<cmd>'"], so the sudo is in argv[2] and argv[0]
    is bash. Verified: _is_sudo(["/bin/bash", "-c", "sudo bash -c x"]) was False. An absolute
    /usr/bin/sudo missed too."""
    if sudo_flag:
        return True
    if isinstance(cmd, (list, tuple)):
        return any(_mentions_sudo(part) for part in cmd)
    return _mentions_sudo(cmd)


def _mentions_sudo(part):
    """True if `part` is the sudo binary, or a shell string that invokes it."""
    text = str(part)
    if os.path.basename(text) == "sudo":
        return True
    return bool(re.search(r"(?:^|[\s;&|(])sudo(?:\s|$)", text))


def _install():
    from panel.ops import system_ops
    # The SUBMODULE that defines _run_local and holds the real subprocess handles. Since the
    # ssh_manager split, assigning to the PACKAGE only shadows its __getattr__ — the definition
    # site is untouched and every internal caller resolves through its own module globals, so the
    # stub is seen by nobody. That is the "half a stub, no error" failure the package docstring
    # warns about, and this runner was doing exactly it: _run_local, subprocess and
    # _real_subprocess were all assigned onto the package while _core kept the real ones, so a
    # local privileged command ran REAL sudo and the summary still printed "0 refused".
    from panel.ops.ssh_manager import _core as _sm_core

    _real_so_run = system_ops._run
    _real_sm_local = _sm_core._run_local

    def _so_run(cmd, timeout=30, sudo=False, text=True):
        if _is_sudo(cmd, sudo):
            BLOCKED.append(("system_ops._run", str(cmd)[:120]))
            return _DENIED
        return _real_so_run(cmd, timeout=timeout, sudo=sudo, text=text)

    def _sm_local(cmd, timeout=30, sudo=False, **kw):
        # **kw: _run_local also takes stdin_text (a secret run_privileged keeps off the command
        # line). A wrapper that drops it turns every such call into a TypeError under this runner.
        if _is_sudo(cmd, sudo):
            BLOCKED.append(("ssh_manager._run_local", str(cmd)[:120]))
            return _DENIED
        return _real_sm_local(cmd, timeout=timeout, sudo=sudo, **kw)

    system_ops._run = _so_run
    # The DEFINITION SITE, and only that. Every caller inside the package resolves _run_local
    # through _core's own globals, and an external `ssh_manager._run_local` reaches it through the
    # package's __getattr__ — so stubbing here covers both. Assigning to the package as well is
    # what the unit gate forbids, and rightly: doing so is what made the original version look
    # complete while intercepting nothing.
    _sm_core._run_local = _sm_local

    # Patching the two helpers is NOT enough on its own. Several callers reach subprocess
    # directly — system_ops builds ["sudo", "systemd-run", ...] for the self-update, the reboot
    # and the scheduled-script paths, tailscale_integration shells out to ["sudo", "tailscale"],
    # and backup.py launches the restore the same way. Those bypass _run entirely, which is how a
    # run that reported "0 refused" still logged real sudo failures. So shim the subprocess module
    # object on every panel module that imports it — one choke point that also covers code added
    # later.
    # ONLY modules that actually import subprocess, and only leaf ones: importing `manage` (or
    # `app`, which pulls it) builds the database as a side effect, which trips smoke_test's own
    # "refuse to run against an existing DB" guard and silently turns the whole run into a SKIP.
    # Neither of those two calls subprocess anyway.
    # Imported by name, explicitly: the set is fixed, and a module that fails to import must be a
    # loud error rather than a skipped shim. Skipping one silently is precisely how real sudo got
    # through before — the run reports "0 refused" while the unshimmed module escalates for real.
    from panel.ops import backup
    import db_maintenance
    from panel.ops import tailscale_integration

    # Each ssh_manager SUBMODULE by name, not the package: `ssh_manager.subprocess` resolves
    # through __getattr__ to whichever submodule happens to define it, and the assignment then
    # lands on the package while every submodule keeps its own real one. cron.py and files.py
    # both call subprocess.Popen(["sudo", "-u", ...]) through their own globals.
    from panel.ops.ssh_manager import cron as _sm_cron, files as _sm_files, game as _sm_game
    from panel.ops.ssh_manager import firewall as _sm_fw, gmod as _sm_gmod, hosts as _sm_hosts
    from panel.ops.ssh_manager import portscan as _sm_ps

    # ONE shim object, shared by every target — not one per module. The real `subprocess` IS one
    # object that all of them import, and a test that reaches for it expects that: part01 patches
    # `_sm_core.subprocess.Popen` and then asserts what files.py's Popen received. With a shim per
    # module that assignment lands on _core's instance and files.py keeps its own, so the patch
    # reached nothing, files.py ran the shim's real Popen against a `sudo -n panel-helper` argv,
    # got /bin/false, and the download tests failed with an empty argv list.
    # what every module above holds after eventlet.monkey_patch()
    import subprocess as _greened  # nosec B404 - the shim below is what refuses sudo
    _shim = _make_shim(_greened)
    _targets = (system_ops, backup, db_maintenance, tailscale_integration,
                _sm_core, _sm_cron, _sm_files, _sm_game, _sm_fw, _sm_gmod, _sm_hosts, _sm_ps)
    for mod in _targets:
        if getattr(mod, "subprocess", None) is not None:
            mod.subprocess = _shim
    # _core keeps a SEPARATE handle for use inside eventlet's thread pool: eventlet.patcher's
    # ORIGINAL, ungreened subprocess, which _run_local runs every local command through. It needs
    # its own shim standing over THAT module, not over the greened one — eventlet's Popen
    # re-implements communicate() and drops the `errors` argument, so _POPEN_KW's
    # errors="replace" stopped applying and a game server printing latin-1 (which is what the
    # three "transports must decode leniently" checks are about) came back as
    # ("", "command execution error", -1) instead of text with a U+FFFD in it.
    if getattr(_sm_core, "_real_subprocess", None) is not None:
        _sm_core._real_subprocess = _make_shim(_sm_core._real_subprocess)


def _caller_label(suffix):
    """Which module called into the shim, for the refusal report. Taken from the calling frame
    because the shim is shared — it cannot be baked in at construction any more."""
    try:
        return "%s.%s" % (sys._getframe(2).f_globals.get("__name__", "?"), suffix)
    except Exception:
        return "?.%s" % suffix


def _make_shim(_sp):
    """A stand-in for one subprocess module that refuses anything invoking sudo, and passes the
    rest to `_sp` — the module it is standing in FOR, so its semantics are the ones that module
    had. Substituting a different subprocess module here changes behaviour the app depends on."""
    class _Shim:
        def __getattr__(self, name):
            return getattr(_sp, name)

        def run(self, cmd, *a, **kw):
            if _is_sudo(cmd):
                BLOCKED.append((_caller_label("run"), str(cmd)[:120]))
                return _sp.CompletedProcess(cmd, 1, "", "sudo: a password is required")  # nosemgrep
            # Passthrough: exactly the command the app would have run unwrapped, minus sudo.
            return _sp.run(cmd, *a, **kw)  # nosec B603  # nosemgrep

        def Popen(self, cmd, *a, **kw):
            if _is_sudo(cmd):
                BLOCKED.append((_caller_label("Popen"), str(cmd)[:120]))
                # Still hand back a real process object: callers poll/wait on it. /bin/false is
                # the cheapest thing that exits non-zero and honours the stdout/stderr kwargs.
                return _sp.Popen(["/bin/false"], *a, **kw)  # nosec B603  # nosemgrep - fixed literal
            return _sp.Popen(cmd, *a, **kw)  # nosec B603  # nosemgrep - passthrough, see run()

    return _Shim()


def _greenify_first():
    """eventlet.monkey_patch() REPLACES socket.socket wholesale, so any patch we install before it
    runs is silently discarded. app.py line 53 calls it when the suite imports the app — i.e. after
    us — which is exactly how the first version of the egress guard came to do nothing at all while
    the run happily opened SSH sockets. monkey_patch is idempotent, so calling it here first just
    fixes the ordering."""
    try:
        import eventlet
        eventlet.monkey_patch()
    except ImportError:
        # No eventlet installed: nothing has replaced socket.socket, so the egress guard the
        # caller installs next is already in the right place and there is no ordering to fix.
        pass


def _install_egress_guard():
    """Refuse outbound connections to anything but loopback, and record them.

    smoke_test's own docstring says it "needs no configured install and no network" — this turns
    that from a claim into something enforced. It is not hypothetical: the query-budget fixture
    seeded hosts in 10.20.0.0/24, which is a LIVE network on plenty of developer machines, and the
    background threads create_app() starts dialed real SSH on them. Repeated failed auth against
    your own hosts is what the fail2ban this panel installs on remotes exists to ban.
    """
    import socket

    _real_connect = socket.socket.connect
    _real_connect_ex = socket.socket.connect_ex

    def _local(addr):
        if not isinstance(addr, tuple) or not addr:
            return True          # AF_UNIX and friends: not egress
        host = str(addr[0])
        # "0.0.0.0" is a DESTINATION here, not a bind address: connecting to it reaches this
        # host, so it belongs with loopback in the allowlist. B104 is about binding a listener.
        return host.startswith("127.") or host in ("::1", "localhost", "0.0.0.0", "")  # nosec B104

    def connect(self, addr):
        if not _local(addr):
            BLOCKED.append(("socket.connect", str(addr)))
            raise ConnectionRefusedError("egress blocked by nosudo_runner: %s" % (addr,))
        return _real_connect(self, addr)

    def connect_ex(self, addr):
        if not _local(addr):
            BLOCKED.append(("socket.connect_ex", str(addr)))
            return 111           # ECONNREFUSED
        return _real_connect_ex(self, addr)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    target = sys.argv[1]
    _greenify_first()
    _install()
    if "--allow-egress" in sys.argv:
        sys.argv.remove("--allow-egress")
    else:
        _install_egress_guard()
    sys.argv = sys.argv[1:]
    code = 0
    try:
        runpy.run_path(target, run_name="__main__")
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)

    seen = {}
    for where, cmd in BLOCKED:
        seen.setdefault((where, cmd), 0)
        seen[(where, cmd)] += 1
    print("\n── privileged / outbound calls refused (%d call%s, %d distinct) ─────────────"
          % (len(BLOCKED), "" if len(BLOCKED) == 1 else "s", len(seen)))
    if not seen:
        print("  (none — this run never tried to escalate or leave the machine)")
    for (where, cmd), n in sorted(seen.items(), key=lambda kv: -kv[1]):
        print("  %4dx  %-28s %s" % (n, where.split(".")[0], cmd))
    print("sudo calls returned rc=1 (as on a machine without passwordless sudo); connections were")
    print("refused. Pass --allow-egress if a suite genuinely needs to reach the network.")
    return code


if __name__ == "__main__":
    sys.exit(main())
