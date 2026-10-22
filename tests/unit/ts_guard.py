"""The unit suite's tailscale guard: its word tables (tests/unit_test.py reads them). Not a test part.

Kept apart from the runner, which is past the 1700-lines-of-code limit the complexity gate holds
every file to (review 1022b added the exec-wrappers below). The readers that use them, and every
check of them, stay in tests/unit_test.py; this module holds data only.
"""

# Commands that run the rest of their argv as a command: (short options taking a value, operands
# before the command). The script form's pattern is built from this table too (_R19D_SCRIPT_WRAPPED).
WRAPPERS = {"env": ("uCSa", 0), "timeout": ("sk", 1), "nice": ("n", 0), "nohup": ("", 0),
            "setsid": ("", 0), "stdbuf": ("ioe", 0), "ionice": ("cnpPu", 0),
            "sudo": ("ugCDhprtTU", 0), "doas": ("aCu", 0), "runuser": ("ugGcsw", 0),
            "su": ("cgGsw", 0), "xargs": ("adEILnPs", 0), "chrt": ("TPD", 1), "taskset": ("", 1),
            "flock": ("wEc", 1), "time": ("fo", 0), "watch": ("n", 0),
            # ...and the exec-wrappers util-linux, systemd and the tracing tools ship (review 1022b:
            # argv `["setpriv", "tailscale", "version"]`, `prlimit` and `unshare` ran the machine's
            # binary with no shell at all, each read as the program itself).
            "setpriv": ("", 0), "prlimit": ("po", 0), "unshare": ("lRwSG", 0), "nsenter": ("tNW", 0),
            "chroot": ("", 1), "setarch": ("p", 0), "linux32": ("p", 0), "linux64": ("p", 0),
            "numactl": ("iwpPCNmLoMISf", 0), "strace": ("abeEIoOpPsSuUX", 0),
            "ltrace": ("aADeFlnopsuwx", 0), "systemd-run": ("HMCupE", 0), "fakeroot": ("lsib", 0),
            "faketime": ("", 1)}
# A wrapper whose first word is an operand when it is not an option (setarch's <arch>, optional), its
# options read after it as before it.
ARCH_FIRST = ("setarch",)
# Long flags of a wrapper that another wrapper's table reads as taking a value (systemd-run's --user is
# runuser's --user <name>): read as flags after that wrapper.
LONG_FLAGS = {"systemd-run": ("--user", "--system", "--scope", "--wait", "--pty", "--pipe", "--quiet",
                              "--verbose", "--collect", "--shell", "--same-dir", "--no-block")}
# Wrappers that reset PATH for the command they run: it is found on the default PATH. systemd-run hands
# the command to the service manager, which searches its own (review 1022b).
PATH_RESETS = ("sudo", "doas", "runuser", "su", "systemd-run")
# Words only a script has (shell builtins, a nested shell that does not read bash's exported
# functions, and commands that run another): judged in a script, never an argv wrapper.
SCRIPT_ONLY = ("command", "exec", "builtin", "type", "hash", "whereis", "sh", "dash", "zsh", "ksh",
               "mksh", "busybox", "awk", "find")
# Long options of those that take their value as the next word.
LONG_VALUE = {"--unset", "--chdir", "--argv0", "--split-string", "--signal", "--kill-after", "--adjustment",
              "--input", "--output", "--error", "--class", "--classdata", "--pid", "--pgid", "--uid",
              "--user", "--group", "--close-from", "--chroot", "--host", "--prompt", "--role",
              "--type", "--other-user", "--command-timeout", "--command", "--shell", "--supp-group",
              "--whitelist-environment", "--arg-file", "--delimiter", "--eof", "--replace",
              "--max-lines", "--max-args", "--max-procs", "--max-chars", "--timeout",
              "--conflict-exit-code", "--format", "--interval", "--sched-runtime", "--sched-period",
              "--sched-deadline",
              # The 1022b exec-wrappers' (unshare, nsenter, setpriv, prlimit, systemd-run, numactl,
              # chroot, fakeroot, faketime): getopt_long takes a required value as the next word too.
              "--load-interp", "--propagation", "--root", "--wd", "--setuid", "--setgid", "--map-user",
              "--map-group", "--map-users", "--map-groups", "--owner", "--setgroups", "--monotonic",
              "--boottime", "--target", "--net-socket", "--wdns", "--ambient-caps", "--inh-caps",
              "--bounding-set", "--ruid", "--euid", "--rgid", "--egid", "--reuid", "--regid", "--groups",
              "--securebits", "--pdeathsig", "--ptracer", "--selinux-label", "--apparmor-profile",
              "--landlock-access", "--landlock-rule", "--seccomp-filter", "--machine", "--capsule",
              "--unit", "--property", "--description", "--slice", "--expand-environment",
              "--service-type", "--gid", "--nice", "--working-directory", "--root-directory",
              "--setenv", "--json", "--job-mode", "--background", "--path-property",
              "--socket-property", "--timer-property", "--on-active", "--on-boot", "--on-startup",
              "--on-unit-active", "--on-unit-inactive", "--on-calendar", "--interleave",
              "--weighted-interleave", "--preferred", "--preferred-many", "--physcpubind",
              "--cpunodebind", "--membind", "--length", "--offset", "--shmmode", "--shmid", "--shm",
              "--file", "--userspec", "--lib", "--faked", "--date-prog"}


# The rows tests/unit_test.py's review-1022b reader check reads (its comments there say what each set is).
WRAPPED_ROWS = (
    'PATH=$PATH; "zsh" -c "tailscale version"', 'PATH=$PATH; z\\sh -c "tailscale version"',
    '"env" -i tailscale version', "'sudo' tailscale version", "\\env -i tailscale version",
    "e''nv -i tailscale version", 'PATH=$PATH; "nohup" tailscale version', 'echo version | "xargs" tailscale',
    'PATH=$PATH; "timeout" 5 ${T:-tail}scale version', "PATH=$PATH; unshare tailscale version",
    "PATH=$PATH; python3 -c 'import os; os.execvp(\"tailscale\", [\"tailscale\"])'",
    "shopt -s expand_aliases; alias x='command tailscale'; x version",
    'echo "envx" tailscale', "awk '$1 >= c' /x/f", "'sudo' true", 'echo "timeout"; echo done')
ARGV_ROWS = (
    ["unshare", "tailscale", "version"], ["nsenter", "-t", "1", "tailscale"], ["chroot", "/", "tailscale"],
    ["setarch", "x86_64", "-R", "tailscale"], ["setarch", "-R", "tailscale"], ["linux32", "tailscale"],
    ["numactl", "-i", "all", "tailscale"], ["strace", "-o", "/x", "tailscale"], ["ltrace", "-e", "x", "tailscale"],
    ["systemd-run", "--user", "tailscale"], ["systemd-run", "-u", "x", "tailscale"], ["fakeroot", "tailscale"],
    ["faketime", "@1", "tailscale"], ["setpriv", "--reuid", "1", "tailscale"], ["prlimit", "-n1", "tailscale"],
    ["unshare", "-R", "tailscale", "x"], ["prlimit", "-p", "1"])
ZSH_CO_ROWS = (
    ["zsh", "-co", "pipefail", "tailscale"], ["zsh", "-oc", "pipefail", "tailscale"], ["zsh", "-co", "pipefail", "ls"])
RESTRICTED_ROWS = (
    "bash -r -c 'tailscale version'", "bash --restricted -c 'tailscale version'", "rbash -c 'tailscale version'",
    "/bin/rbash -c 'tailscale version'", "bash -er -c 'tailscale version'",
    "bash --posix -c 'tailscale version'", "bash --rcfile /x -c 'tailscale version'")
RESTRICTED_ARGV_ROWS = (
    ["env", "X=1", "bash", "-r", "-c", "x"], ["bash", "-rc", "x"], ["bash", "--restricted", "-c", "x"],
    ["bash", "--rcfile", "/x", "-c", "x"], ["bash", "-c", "x", "-r"], ["bash", "--posix", "-c", "x"])
CO_ROWS = (
    'P=PA; bash -co pipefail "${P}TH=/x; tailscale"', 'P=PA; bash -oc pipefail "${P}TH=/x; tailscale"',
    'P=PA; sh -eco pipefail "${P}TH=/x; tailscale"', "bash -co pipefail 'tailscale'")
# The env-reset reader's rows (the rows above `env -u X y` reset), and the shell-option readers' rows and
# slow words (tests/unit_test.py's ReDoS children).
ENV_RESET_ROWS = (
    "env -i x", "env -v -i x", "env -u PATH x", "env --unse PATH x", "env -u X -i y",
    "env --chdir /x -i y", "env -C! -i x", "env -uPATH x", "env -S x", "env --split-string=x",
    # A value letter inside a cluster takes the next word, and -a/--argv0 takes one (review 1016c).
    "env -vu X -i y", "env -vC /x -i y", "env -0u X -i y", "env -vuPATH y", "env -a x -i y",
    "env --argv0 x -i y", "env --arg x -i y", "env -va x -i y",
    # --ig is --ignore-environment to an env older than --ignore-signal (coreutils 9), and refused
    # as ambiguous by a newer one; --ignore-signal itself resets nothing (review 1016e).
    "env --ig x",
    "env -u X y", "env -C /x y", "env --debug x", "env FOO=1 x", "env -u -u PATH x", "env -vu X y",
    "env -a x y", "env -vC /x y", "env -va -i y", "env --ignore-signal x", "env --ignore-s=INT x")
OPTS_ROWS = ('bash --rcfile /x -c "y"', "bash --init-file /x -c y", "bash -o pipefail -c y",
             "bash -O extglob -lc y", "sh --norc -c 'y'", "bash -o c x", "bash --rcfile -c")
OPTS_SLOW = ("-o +a ", "--rcfile -x ", "+O +x ", "--init-file --x ", "-o -o ", "-eo x ", "-eo -eo ", "-oo x ",
             "-oooo x ", "-co x ", "-oc x ", "-rc x ")
# The review-1022a function-off rows (12 judged, then 6 controls).
FUNC_OFF_ROWS = (
    "T=tail; unset -f ${T}scale; tailscale version", 'U=un; eval "${U}set -f tailscale"; tailscale version',
    'T=tail; eval "unset -f ${T}scale"; tailscale version', "f=tailscale; unset -f $f; tailscale version",
    "u=unset; $u -f tailscale; tailscale version", "$(echo unset) -f tailscale; tailscale version",
    "export -nf tailscale; bash -c 'tailscale version'", "declare +x -f tailscale; bash -c 'tailscale version'",
    "typeset +x -f which; bash -c 'which tailscale'", "bash -p -c 'tailscale version'",
    "bash -eo privileged -c 'tailscale version'", 'eval "$(x)"; tailscale version',
    "unset X; echo hi", "export -n FOO; echo $HOME", 'unset "$v"; echo done', "bash +p -c 'tailscale version'",
    '. /etc/os-release 2>/dev/null; printf %s "${ID}-${VERSION_ID}"', "bash -P -c 'tailscale version'")
