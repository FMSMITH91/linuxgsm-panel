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
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BLOCKED = []
# What a real `sudo -n` prints when it wants a password. Callers act on the non-zero rc.
_DENIED = ("", "sudo: a password is required", 1)


def _is_sudo(cmd, sudo_flag=False):
    if sudo_flag:
        return True
    if isinstance(cmd, (list, tuple)):
        return bool(cmd) and str(cmd[0]) == "sudo"
    return "sudo" in str(cmd)


def _install():
    import ssh_manager
    import system_ops

    _real_so_run = system_ops._run
    _real_sm_local = ssh_manager._run_local

    def _so_run(cmd, timeout=30, sudo=False, text=True):
        if _is_sudo(cmd, sudo):
            BLOCKED.append(("system_ops._run", str(cmd)[:120]))
            return _DENIED
        return _real_so_run(cmd, timeout=timeout, sudo=sudo, text=text)

    def _sm_local(cmd, timeout=30, sudo=False):
        if _is_sudo(cmd, sudo):
            BLOCKED.append(("ssh_manager._run_local", str(cmd)[:120]))
            return _DENIED
        return _real_sm_local(cmd, timeout=timeout, sudo=sudo)

    system_ops._run = _so_run
    ssh_manager._run_local = _sm_local

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
    import backup
    import db_maintenance
    import tailscale_integration

    for mod in (system_ops, ssh_manager, backup, db_maintenance, tailscale_integration):
        if getattr(mod, "subprocess", None) is not None:
            mod.subprocess = _shim_for(mod.__name__)
    # ssh_manager keeps a SEPARATE unpatched handle for use inside eventlet's thread pool.
    if getattr(ssh_manager, "_real_subprocess", None) is not None:
        ssh_manager._real_subprocess = _shim_for("ssh_manager._real_subprocess")


def _shim_for(label):
    """A stand-in subprocess module that refuses anything invoking sudo and passes the rest on."""
    import subprocess as _sp  # nosec B404 - this IS the subprocess wrapper; it refuses sudo

    class _Shim:
        def __getattr__(self, name):
            return getattr(_sp, name)

        def run(self, cmd, *a, **kw):
            if _is_sudo(cmd):
                BLOCKED.append(("%s.run" % label, str(cmd)[:120]))
                return _sp.CompletedProcess(cmd, 1, "", "sudo: a password is required")  # nosemgrep
            # Passthrough: exactly the command the app would have run unwrapped, minus sudo.
            return _sp.run(cmd, *a, **kw)  # nosec B603  # nosemgrep

        def Popen(self, cmd, *a, **kw):
            if _is_sudo(cmd):
                BLOCKED.append(("%s.Popen" % label, str(cmd)[:120]))
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
