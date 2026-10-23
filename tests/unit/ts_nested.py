"""The unit suite's tailscale guard: the script a shell reads with no -c (tests/unit_test.py reads it). Not a part.

Kept apart from the runner, which the complexity gate holds to 1700 lines of code (review 1022c added the
readers below). What a shell is handed as its script when it has no -c: the file its first operand names, or
its stdin (the run's `input=`); and, inside a script, each shell it runs with no -c (`bash /f.sh`, `sh < f`,
`x | sh`). The runner's own readers it calls (its PATH, wrapper and option readers, its quote stripper) are
looked up in the runner's namespace when called: bind() hands it over once.
"""
import os
import re
import shlex

# A shell script the reader cannot see (stdin a pipe written later, a file this run may not read) is read as
# one that may run any tailscale on any PATH: `command -p` and a built word keep it off the shim, and judge
# it on the run's PATH and the default one (review 1022b).
UNREAD = "command -p $(:)"
SCRIPT_MAX = 1 << 20
# The names a shell opens its own stdin by: a script operand naming one reads the run's input.
STDIN_NAMES = ("/dev/stdin", "/dev/fd/0", "/proc/self/fd/0", "/proc/thread-self/fd/0")
# A shell a script runs with no -c reads its script from a file or from its stdin (review 1022c: `bash /f.sh`,
# `sh < f`, `x | sh`, a bare `bash` reading the run's input, and `env -S 'bash -s'` were read as the outer
# words alone, and the inner `tailscale` ran with no guard and no judgement). Read where the outer script
# splits into commands (SPLIT), at a command word, to DEPTH levels.
SHELLS = frozenset(("sh", "bash", "dash", "rbash", "zsh", "ksh", "mksh"))
SPLIT = re.compile(r"(\|\||&&|\$\(|[|&;\n()`])")
DEPTH = 3
# Words before a command that leave it the command: a keyword, a group, and the builtins that run it.
LEADS = frozenset(("then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "exec", "builtin",
                   "command"))
REDIRECT = re.compile(r"(\d*)(<<<|<<-?|<>|<&|<|>>|>&|>\||>|&>>|&>)(.*)", re.S)
_RUNNER = {}


def bind(namespace):
    """Hand over the runner's namespace: its _r20d_run_env, _r19d_unwrap, _r18d_* and _r26d_strip_single."""
    _RUNNER.update(namespace=namespace)


def _runner(name):
    return _RUNNER["namespace"][name]


def shell_text(cmd, kw):
    """The shell source `cmd` runs, or None when it is not a shell command.

    As the guard judges it (judged_text): also with its line continuations joined, and with the script each
    shell it runs with no -c reads (review 1022c).
    """
    cmd = text_words(cmd)
    if kw.get("shell"):
        # A list with shell=True runs its first item as the script (review 1012b: it was not read).
        _first = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else cmd
        return judged_text(_first, kw) if isinstance(_first, str) else None
    return judged_text(shell_at(cmd, kw)[1], kw) if isinstance(cmd, (list, tuple)) else None


def shell_at(argv, kw):
    """(index of the shell word, the script it runs) for an argv that runs a shell, else (None, None).

    Its -c script (_r18d_dash_c); with no -c, the script it reads from stdin (`bash`, `bash -s`: the run's
    `input=`) or from the file its first operand names (review 1022b: neither was read, so
    `run(["bash"], input="tailscale version")` and `["sh", "<f>.sh"]` got no guard and no judgement).
    """
    _i, _script = _runner("_r18d_dash_c")(argv)
    if _i is not None:
        return _i, _script
    _i = _runner("_r18d_shell_word")(argv)
    if _i is None:
        return None, None
    _c, _j = _runner("_r18d_shell_opts")(argv, _i + 1)
    if _c:
        return None, None       # -c with no script: the shell refuses it
    # `-` ends the options as `--` does, and the word after it is the script file (review 1022c: `bash - f`
    # was read as reading stdin, so the run's input was judged and f ran unread); stdin only with no
    # operand left or an `-s` cluster.
    if _j < len(argv) and not stdin_flag(argv[_i + 1:_j]):
        # A wrapper that changes the directory or the root first (`env -C d`, chroot, nsenter --wd) has the
        # shell find its file there, not where the run starts (review 1022c lead): unread.
        return _i, (UNREAD if moves_dir(argv[:_i]) else read_script(argv[_j], kw))
    return _i, stdin_script(kw)


def ambiguous_long(word):
    """Is argv word `word` a long option the runner reads both ways (its _r25d_readings)?

    A prefix of a value-taking name, or one whose value is optional in some releases (ts_guard's LONG_EITHER,
    review 1022c: nsenter's --setuid and --setgid).
    """
    if not isinstance(word, str) or "=" in word:
        return False
    _values = _runner("_R19D_LONG_VALUE")
    return (word in _runner("_r35d_ts_guard").LONG_EITHER
            or (word not in _values and _runner("_r23d_long_prefix")(word, _values)))


def text_words(cmd):
    """`cmd` with each bytes or path-like word as the str the kernel is handed (os.fsdecode), else `cmd` itself.

    subprocess takes either, and every reader matched str alone (review 1022c: `run(b"tailscale version",
    shell=True)`, `["bash", "-c", b"tailscale version"]` and `["bash", b"-c", "…"]` ran unread). Decoding is
    lossless on POSIX (surrogateescape), so the decoded argv runs exactly what was given.
    """
    def _one(_w):
        return os.fsdecode(_w) if isinstance(_w, (bytes, os.PathLike)) else _w
    if isinstance(cmd, (list, tuple)):
        return type(cmd)(map(_one, cmd)) if any(isinstance(_w, (bytes, os.PathLike)) for _w in cmd) else cmd
    return _one(cmd)


def stdin_flag(opts):
    """Do a shell's option words (as _r18d_shell_opts passes them) hold an `-s` cluster, an option's value not?

    The value of --rcfile, --init-file or an o/O cluster is skipped, as the shell takes it (review 1022c lead:
    `bash --rcfile -s f.sh` read the rcfile's name `-s` as reading stdin, and f.sh ran unread).
    """
    _k = 0
    while _k < len(opts):
        _o = str(opts[_k])
        if re.fullmatch(r"-[A-Za-z]*s[A-Za-z]*", _o):
            return True
        _k += 2 if _o in ("--rcfile", "--init-file") or re.fullmatch(r"[-+][A-Za-z]*[oO][A-Za-z]*", _o) else 1
    return False


def moves_dir(words):
    """Do the wrapper words in front of a shell change the directory or root it starts in?

    `env -C d`, sudo -D, chroot, nsenter --wd or --root, unshare -R or -w: the shell finds its script file
    there, not where the run starts (review 1022c lead: it was read against the run's directory).
    """
    return any(isinstance(_w, str) and (os.path.basename(_w) == "chroot" or re.match(
        r"-[A-Za-z]*[CDRrw]|--(?:ch|wd|root|working-directory)", _w)) for _w in words)


def stdin_script(kw):
    """The script a shell reads from its stdin: the run's `input=`, none from /dev/null, else unread."""
    _in = kw.get("input")
    _in = _in.decode("utf-8", "replace") if isinstance(_in, bytes) else _in
    if _in is None and kw.get("stdin") == -3:
        return ""               # subprocess.DEVNULL: an empty script (review 1022c lead: read as unread)
    return _in if isinstance(_in, str) else UNREAD


def read_script(name, kw):
    """The text of the script file `name` a shell is handed: from the run's directory, else (bash) its PATH.

    A name that is there but no regular file (review 1022c: `/dev/stdin`, `/dev/fd/0`, a FIFO, `<(…)`) was
    read as "no such file", so `run(["bash", "/dev/stdin"], input="tailscale version")` ran unread: one
    naming the shell's stdin reads the run's input, any other is a script the reader cannot see. So is a
    file past the size read (it was judged on its head alone).
    """
    try:
        name = os.fsdecode(os.fspath(name))
    except TypeError:
        return UNREAD
    for _f in _script_paths(name, kw):
        if os.path.lexists(_f) and not os.path.isdir(_f):
            return _read_one(_f, kw)
    return ""                   # no such file (or a directory): the shell runs nothing


def _script_paths(name, kw):
    """Where a shell looks for script file `name`: the run's directory, then (no slash in it) the run's PATH."""
    if not name:
        return []
    _tries = [os.path.join(os.fsdecode(kw.get("cwd") or os.getcwd()), name)]
    if os.sep not in name:
        _path = _runner("_r20d_run_env")(kw).get("PATH", os.defpath)
        _tries += [os.path.join(_d, name) for _d in _path.split(os.pathsep) if _d]
    return _tries


def _read_one(path, kw):
    """The script at `path`, which is there: the run's input for a stdin name, else the file's text or unread."""
    if os.path.normpath(path) in STDIN_NAMES:
        return stdin_script(kw)
    if not os.path.isfile(path):
        return UNREAD
    try:
        with open(path, encoding="utf-8", errors="replace") as _fh:
            _text = _fh.read(SCRIPT_MAX + 1)
    except OSError:
        return UNREAD
    return UNREAD if len(_text) > SCRIPT_MAX else _text


def judged_text(script, kw, depth=0):
    r"""`script` as the guard reads it: as written, joined at each `\<newline>`, and each nested shell's script.

    bash drops a backslash-newline before it splits words (review 1022c: `command \<newline>tailscale` and
    `com\<newline>mand tailscale` ran the PATH binary unread). Joined everywhere, inside '…' too, where bash
    keeps it: that reads more, never less. The nested scripts (nested_scripts) follow, each read the same
    way, to DEPTH levels; past it, a nested shell is one the reader cannot see.
    """
    if not isinstance(script, str):
        return script
    _joined = script.replace("\\\n", "")
    _out = [script] + ([_joined] if _joined != script else [])
    _nested = nested_scripts(_joined, kw)
    if depth >= DEPTH:
        return "\n".join(_out + ([UNREAD] if _nested else []))
    return "\n".join(_out + [judged_text(_t, kw, depth + 1) for _t in _nested])


def nested_scripts(script, kw):
    """The script each shell `script` runs with no -c reads (_nested_one), per command it splits into."""
    _out, _piped = [], False
    _parts = SPLIT.split(_runner("_r26d_strip_single")(script))
    for _k, _part in enumerate(_parts):
        if _k % 2:
            _piped = _part == "|"
            continue
        _argv = _command_argv(_words(_part))
        _text = _nested_one(_argv, _piped, kw, script) if _argv else None
        if _text is not None:
            _out.append(_text)
    return _out


def option_scripts(cmdlines, kw):
    """The scripts the shells in an argv's option command lines (`env -S 'bash -s'`) read with no -c."""
    return [_t for _v in cmdlines for _t in nested_scripts(_v, kw)]


def _words(text):
    """The words of one simple command, as the shell splits them (by whitespace when its quotes do not balance)."""
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _command_argv(words):
    """The argv from the shell word on, when the command `words` runs a shell, else None.

    Past assignments, keywords and wrappers: `sudo -u x bash f`, `exec sh`, `busybox sh`.
    """
    _k = 0
    while _k < len(words) and (words[_k] in LEADS or re.fullmatch(r"[A-Za-z_]\w*=.*", words[_k], re.S)):
        _k += 1
    _k += _runner("_r19d_unwrap")(words[_k:], None)[0]
    if _k + 1 < len(words) and os.path.basename(words[_k]) == "busybox":
        _k += 1
    return words[_k:] if _k < len(words) and os.path.basename(words[_k]) in SHELLS else None


def _redirects(argv):
    """(argv without its redirections, where its stdin comes from: None, "|" for unseen, or a file name)."""
    _argv, _stdin, _k = [], None, 0
    while _k < len(argv):
        _m = REDIRECT.fullmatch(argv[_k])
        if not _m:
            _argv.append(argv[_k])
            _k += 1
            continue
        _target = _m.group(3) or (argv[_k + 1] if _k + 1 < len(argv) else "")
        if _m.group(1) in ("", "0") and _m.group(2).startswith("<") and _m.group(2) != "<&":
            _stdin = _target if _m.group(2) in ("<", "<>") else "|"
        _k += 1 if _m.group(3) else 2
    return _argv, _stdin


def _nested_one(argv, piped, kw, script):
    """The script the shell argv[0] reads: None for a -c (read already), a file's text, its stdin, or unread.

    A pipe, a here-document or here-string, and a file not there yet (the script may write it first) or named
    relative to a directory the script may change to, are what the reader cannot see.
    """
    _argv, _stdin = _redirects(argv)
    _stdin = "|" if _stdin is None and piped else _stdin
    _c, _j = _runner("_r18d_shell_opts")(_argv, 1)
    if _c:
        return None
    if _j < len(_argv) and not stdin_flag(_argv[1:_j]):
        return _nested_file(_argv[_j], kw, script)
    if _stdin == "|":
        return UNREAD
    return stdin_script(kw) if _stdin is None else _nested_file(_stdin, kw, script)


def _nested_file(name, kw, script):
    """The text of a script file a nested shell reads, or UNREAD where the reader cannot see it."""
    if not os.path.isabs(name) and re.search(r"\b(?:cd|pushd|popd)\b", script):
        return UNREAD
    return read_script(name, kw) or UNREAD
