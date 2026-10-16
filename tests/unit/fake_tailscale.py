"""A stateful stand-in for the `tailscale` CLI, for the Serve subcommands the panel and its scripts run.

Not a test part. tests/unit/part32.py writes a two-line `tailscale` wrapper that execs this file and
puts it first on PATH, so the panel's own code (tailscale_integration._run_ts), install.sh and
uninstall.sh all reach it exactly as they would reach the real binary.

STATE is the JSON file named by $FAKE_TS_STATE:

    {"web": {"443": {"/": "http://127.0.0.1:5000"}}, "funnel": ["443"], "http": ["8080"]}

`web` maps a listener port to {mount: backend}; a port named in `http` is an HTTP listener (the rest
are HTTPS); a port in `funnel` has Funnel on. Every call is appended to $FAKE_TS_LOG as one JSON
argv line. $FAKE_TS_SERVE_UNREADABLE=1 makes `serve status` fail the way a non-operator account sees
it; $FAKE_TS_OFF_FAIL=1 makes every `off` fail the same way, and $FAKE_TS_WRITE_FAIL=1 every write.

`"operator_required": true` in STATE models a host where this account is NOT the Tailscale operator:
`serve status` still answers (reading Serve needs no privilege), but every write and every `off` is
refused with "Access denied" until `set --operator=<user>` has run, which records "operator". That
is Tailscale's own split (1.102.4: ipnserver actor.Permissions answers read=true for any local
socket client and write only for root or the operator; localapi serves GET serve-config on read,
POST on write), so a page that can LIST a route cannot necessarily remove it.

$FAKE_TS_AS_ROOT=1 is a call made as root (the helper's verbs, install.sh, uninstall.sh): it may
change Serve whoever the operator is. Every call that CHANGES something (a Serve write or `off`,
`set`) made without it is also appended to $FAKE_TS_UNPRIV_LOG when that is set, so a part can
show the panel's own account changed nothing. as_helper() below is system_ops._run_verb as the
helper would answer the Tailscale verbs: their tool argv, through the panel's _run_ts, as root.
`debug prefs` reports the state's "operator" as OperatorUser, and `set --operator=` (empty) clears it.

$FAKE_TS_TAKEOVER, a STATE as JSON, replaces the state right after the first `serve status` read
answers: another app taking a mount between a caller's read and its `off`.

THE SEMANTICS THE TESTS DEPEND ON were checked against the real CLI (Tailscale 1.102.4) on the test
VPS by the investigation that found these bugs, and against serve_v2.go of that version:
  * `serve --bg --https=443 [--set-path=M] <backend>` REPLACES whatever is at M, silently (rc 0).
    It also drops the mount that differs from M only by one trailing "/": ipn/serve.go
    SetWebHandler deletes every other handler whose mount, less one trailing "/", equals M's ("/foo/
    overwrites /foo ... the opposite example is also handled"). Measured on the VPS, a write at
    "/lgsm/" turned ['/', '/lgsm'] into ['/', '/lgsm/'], and the boot's write at "/lgsm" turned it
    back. So no write leaves "/x" and "/x/" side by side.
  * `serve set-raw` (an undocumented debug command, serve_v2.go runServeCombined) replaces the whole
    config with the ipn.ServeConfig JSON on stdin, as given and with no dedupe. It is the one CLI
    path that can leave "/x" beside "/x/". Like every write, it needs the operator.
  * `serve --https=N --set-path=M off` removes ONLY M; a missing M is rc 1 "handler does not exist".
  * `off` WITHOUT --set-path removes EVERY mount on that listener (no TTY, so no prompt).
  * Removing a listener's last mount clears it, and its Funnel flag with it.
  * A plain `serve` write (not `funnel`) turns Funnel OFF for its whole listener: setServe ends with
    applyFunnel(..., allowFunnel=false), printing "Removing Funnel for <host>:<port>" — another app's
    route on that listener drops off the internet with it.
  * A flag the CLI does not define is rc 2 "flag provided but not defined: -<name>" — `--remove`
    among them: the serve CLI that has --bg never had it.
  * `serve status` prints one block per listener, shortest mount first, "(Funnel on)" or
    "(tailnet only)" after the URL; `serve status --json` prints the ipn.ServeConfig shape
    (TCP / Web / AllowFunnel), and `{}` when nothing is published.
"""
import json
import os
import sys

HOST = "fakehost.tail0000.ts.net"


def _load():
    try:
        with open(os.environ["FAKE_TS_STATE"], encoding="utf-8") as fh:
            st = json.load(fh)
    except (OSError, ValueError):
        st = {}
    st.setdefault("web", {})
    st.setdefault("funnel", [])
    st.setdefault("http", [])
    return st


def _save(st):
    st["web"] = {p: h for p, h in st["web"].items() if h}
    st["funnel"] = [p for p in st["funnel"] if p in st["web"]]
    with open(os.environ["FAKE_TS_STATE"], "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1, sort_keys=True)


def _out(text="", rc=0, err=""):
    sys.stdout.write(text)
    sys.stderr.write(err)
    sys.exit(rc)


def _url(st, port):
    scheme = "http" if port in st["http"] else "https"
    default = "80" if scheme == "http" else "443"
    return "%s://%s%s" % (scheme, HOST, "" if port == default else ":" + port)


def _status_text(st):
    if not st["web"]:
        return "No serve config\n"
    lines = []
    for port in sorted(st["web"], key=int):
        lines.append("%s (%s)" % (_url(st, port),
                                  "Funnel on" if port in st["funnel"] else "tailnet only"))
        handlers = st["web"][port]
        width = max(len(m) for m in handlers)
        for mount in sorted(handlers, key=lambda m: (len(m), m)):
            lines.append("|-- %s proxy %s" % (mount.ljust(width), handlers[mount]))
        lines.append("")
    return "\n".join(lines) + "\n"


def _status_json(st):
    if not st["web"]:
        return "{}\n"
    sc = {"TCP": {}, "Web": {}}
    for port, handlers in st["web"].items():
        sc["TCP"][port] = {"HTTP": True} if port in st["http"] else {"HTTPS": True}
        sc["Web"]["%s:%s" % (HOST, port)] = {
            "Handlers": {m: {"Proxy": b} for m, b in handlers.items()}}
    if st["funnel"]:
        sc["AllowFunnel"] = {"%s:%s" % (HOST, p): True for p in st["funnel"]}
    return json.dumps(sc, indent=2) + "\n"


def _parse_serve(rest):
    """(listener port, set-path or None, positionals) of a serve/funnel argv, or exit 2."""
    port, path, pos, i = None, None, [], 0
    while i < len(rest):
        a = rest[i]
        if a in ("--bg", "--yes"):
            pass
        elif a.startswith(("--https=", "--http=")):
            port = a.split("=", 1)[1]
        elif a in ("--https", "--http"):
            i += 1
            port = rest[i] if i < len(rest) else ""
        elif a.startswith("--set-path="):
            path = a.split("=", 1)[1]
        elif a.startswith("-"):
            _out(rc=2, err="flag provided but not defined: -%s\n" % a.lstrip("-").split("=")[0])
        else:
            pos.append(a)
        i += 1
    return port or "443", path, pos


def _denied(st):
    """True when this call may not change Serve: OFF/WRITE_FAIL aside, a non-operator account."""
    return (bool(st.get("operator_required")) and not st.get("operator")
            and not os.environ.get("FAKE_TS_AS_ROOT"))


def _off(st, port, path):
    if os.environ.get("FAKE_TS_OFF_FAIL") or _denied(st):
        _out(rc=1, err="Access denied: serve config denied\n")
    handlers = st["web"].get(port) or {}
    if path is None:
        if not handlers:
            _out(rc=1, err="error: handler does not exist\n")
        st["web"][port] = {}
    elif path not in handlers:
        _out(rc=1, err="error: handler does not exist\n")
    else:
        del handlers[path]
    _save(st)
    _out()


def _trim_slash(mount):
    """Go's strings.TrimSuffix(mount, "/"): ONE trailing "/" off, so "//" becomes "/"."""
    return mount[:-1] if mount.endswith("/") else mount


def _set_web_handler(handlers, mount, backend):
    """Write `backend` at `mount` as ipn.ServeConfig.SetWebHandler (1.102.4) does.

    Every OTHER mount that is the same less one trailing "/" goes: "/foo/" overwrites "/foo", and
    the other way round.
    """
    handlers[mount] = backend
    for other in [m for m in handlers if m != mount]:
        if _trim_slash(other) == _trim_slash(mount):
            del handlers[other]


def _write_refused(st):
    if os.environ.get("FAKE_TS_WRITE_FAIL") or _denied(st):
        _out(rc=1, err="Access denied: serve config denied\n")


def _apply_funnel(st, verb, port):
    """A `funnel` write turns Funnel on for the listener; a `serve` write turns it off."""
    if verb == "funnel" and port not in st["funnel"]:
        st["funnel"].append(port)
    elif verb == "serve" and port in st["funnel"]:
        # setServe ends with applyFunnel(..., allowFunnel=false): a plain `serve` write turns
        # Funnel OFF for the whole listener ("Removing Funnel for ..."), other apps' mounts included.
        st["funnel"].remove(port)
        sys.stderr.write("Removing Funnel for %s:%s\n" % (HOST, port))


def _serve(verb, rest):
    if rest == ["set-raw"]:
        _set_raw()
    st = _load()
    port, path, pos = _parse_serve(rest)
    if pos == ["off"]:
        _off(st, port, path)
    if len(pos) != 1 or "://" not in pos[0]:
        _out(rc=1, err="invalid argument format\n")
    _write_refused(st)
    _set_web_handler(st["web"].setdefault(port, {}), path or "/", pos[0])
    _apply_funnel(st, verb, port)
    _save(st)
    _out("Available within your tailnet:\n\n%s%s\n" % (_url(st, port), path or "/"))


def _raw_config():
    """The ipn.ServeConfig JSON on stdin, or exit 1 as the CLI does for one it cannot parse."""
    try:
        sc = json.loads(sys.stdin.read() or "{}")
    except ValueError:
        sc = None
    if not isinstance(sc, dict):
        _out(rc=1, err="invalid JSON\n")
    return sc


def _raw_port(hostport):
    return hostport.rsplit(":", 1)[1]


def _raw_web(sc):
    """{listener: {mount: backend}} of a ServeConfig's Web block, every handler kept as given."""
    web = {}
    for hostport, cfg in (sc.get("Web") or {}).items():
        handlers = (cfg or {}).get("Handlers") or {}
        web[_raw_port(hostport)] = {m: (h or {}).get("Proxy", "") for m, h in handlers.items()}
    return web


def _raw_http(sc):
    """The listeners a ServeConfig's TCP block marks HTTP (not HTTPS)."""
    tcp = sc.get("TCP") or {}
    return [p for p, h in tcp.items() if (h or {}).get("HTTP") and not h.get("HTTPS")]


def _set_raw():
    """`serve set-raw`: the whole config becomes the ipn.ServeConfig JSON on stdin, as given."""
    st = _load()
    _write_refused(st)
    sc = _raw_config()
    st["web"] = _raw_web(sc)
    st["http"] = _raw_http(sc)
    st["funnel"] = [_raw_port(hp) for hp, on in (sc.get("AllowFunnel") or {}).items() if on]
    _save(st)
    _out()


def _set(rest):
    """`set --operator=<user>`: from now on this account may change Serve."""
    st = _load()
    for a in rest:
        if a.startswith("--operator="):
            st["operator"] = a.split("=", 1)[1]
    _save(st)
    _out()


def _takeover(st):
    """Once: the state becomes $FAKE_TS_TAKEOVER after the read that has just been answered."""
    raw = os.environ.get("FAKE_TS_TAKEOVER")
    if raw and not st.get("taken_over"):
        new = json.loads(raw)
        new["taken_over"] = True
        with open(os.environ["FAKE_TS_STATE"], "w", encoding="utf-8") as fh:
            json.dump(new, fh, indent=1, sort_keys=True)


def _changes(args):
    """Whether `args` asks the daemon to CHANGE something (every write the panel could make)."""
    if args[:1] == ["set"]:
        return True
    return args[:1] in (["serve"], ["funnel"]) and args[1:2] != ["status"]


def _log_call(args):
    """Log `args` to $FAKE_TS_LOG, and to $FAKE_TS_UNPRIV_LOG if it is an unprivileged change."""
    unpriv = os.environ.get("FAKE_TS_UNPRIV_LOG")
    if not unpriv or os.environ.get("FAKE_TS_AS_ROOT") or not _changes(args):
        unpriv = None
    for path in (os.environ.get("FAKE_TS_LOG"), unpriv):
        if path:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(args) + "\n")


# The marker as_helper puts first in its own call's argv: a call made as root, for that call only.
AS_ROOT_ARG = "--fake-ts-as-root"


def _as_root(args):
    """`args` without AS_ROOT_ARG, marking this process (the fake's own) as root when it led them."""
    if args[:1] == [AS_ROOT_ARG]:
        os.environ["FAKE_TS_AS_ROOT"] = "1"
        return args[1:]
    return args


def main(args):
    args = _as_root(args)
    _log_call(args)
    if args in (["version"], ["--version"]):
        _out("1.102.4\n  tailscale commit: fake\n")
    if args == ["status", "--json"]:
        _out(json.dumps({"BackendState": "Running", "TailscaleIPs": ["100.64.0.9"],
                         "Self": {"HostName": "fakehost", "DNSName": HOST + "."}, "Peer": {}}))
    if args == ["debug", "prefs"]:
        _out(json.dumps({"RouteAll": False, "OperatorUser": _load().get("operator") or "",
                         "RunSSH": False}))
    if args[:1] == ["set"]:
        _set(args[1:])
    if args[:2] == ["serve", "status"]:
        if os.environ.get("FAKE_TS_SERVE_UNREADABLE"):
            _out(rc=1, err="Access denied: serve config denied\n")
        st = _load()
        text = _status_json(st) if "--json" in args else _status_text(st)
        _takeover(st)
        _out(text)
    if args[:1] in (["serve"], ["funnel"]):
        _serve(args[0], args[1:])
    _out(rc=1, err="fake tailscale: unhandled %r\n" % (args,))


# The verbs the helper answers with the tailscale CLI as root (privileged.tool_argv renders them).
ROOT_VERBS = ("tailscale-serve", "tailscale-serve-off", "tailscale-serve-status", "tailscale-ssh")


def as_helper(ts, priv, record=None):
    """A stand-in for system_ops._run_verb: the helper's answer to the Tailscale verbs, as root.

    `ts` is tailscale_integration, `priv` privileged. Each verb in ROOT_VERBS runs its own tool
    argv (priv.tool_argv, which validates the arguments as the helper does) through ts._run_ts,
    so through this fake on PATH, marked as root by AS_ROOT_ARG in that call's own argv. Every
    other verb is refused. `record`, a list, gets (verb, args) for each call.
    """
    def _run_verb(verb, args=(), timeout=30, merge_stderr=True, **_kw):
        if record is not None:
            record.append((verb, list(args)))
        try:
            argv = priv.tool_argv(verb, list(args)) if verb in ROOT_VERBS else []
        except priv.VerbError:
            # What the real _run_verb answers for arguments the verb refuses (review 1016b: it
            # raised here, so a check could not drive the caller's refusal branch).
            return "", "invalid argument", -1
        if not argv:
            return "", "refused by the fake helper", 1
        # Not FAKE_TS_AS_ROOT in os.environ (review 1016c): that marked every tailscale call the
        # whole process made meanwhile, a worker's unprivileged write included, as root, and the
        # closing "the panel's account changed nothing" check could not see it.
        out, err, rc = ts._run_ts([AS_ROOT_ARG] + list(argv[1:]), timeout=timeout)
        if merge_stderr and err:
            return (out + "\n" + err).strip(), "", rc
        return out, err, rc
    return _run_verb


if __name__ == "__main__":
    main(sys.argv[1:])
