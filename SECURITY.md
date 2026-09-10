# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull
requests, or discussions.** A public report tips off attackers before a fix is out.

Instead, report privately through GitHub's built-in private vulnerability reporting
(already enabled on this repo):

1. Open the [**Security** tab](https://github.com/FMSMITH91/linuxgsm-panel/security).
2. Click **"Report a vulnerability"**.
3. Describe the issue.

The report stays private between you and the maintainer until a fix is ready. You can
expect an initial response within a few days.

When you can, please include:

- the version you're running (see the `VERSION` file, or the panel's footer),
- a description of the issue and its impact,
- steps to reproduce (or a proof of concept), and
- any suggested fix.

Coordinated disclosure is appreciated: please give a reasonable window to release a fix
before any public write-up.

## Supported versions

The panel is a rolling release — fixes land on `main` and are picked up by re-running the
installer, which updates in place (with a health check and automatic rollback). Security
fixes are applied to the **latest** version only, so please update before reporting.

| Version | Supported |
| --- | --- |
| Latest `main` / newest release | ✅ |
| Anything older | ❌ — please update first |

## Deploying securely

The panel manages game-server hosts over SSH, so treat it as sensitive infrastructure:

- Keep it behind **Tailscale** (or a reverse proxy with a real certificate) rather than
  exposing the panel port to the public internet. See [docs/https.md](docs/https.md).
- Keep **two-factor authentication** enabled on admin accounts.
- Keep the install **up to date** — re-running the installer applies the latest fixes.

## Known trust-model limitation: the panel has root on its own host

When the installer is run as **root**, it creates a dedicated service user and grants it
`ALL=(ALL) NOPASSWD:ALL` in `/etc/sudoers.d/linuxgsm-panel` — **full, unrestricted,
passwordless root**. The panel itself does not run as root, but it can become root at any
time without a password.

The practical consequence, stated plainly: **there is no privilege boundary between "the
web panel is compromised" and "the host is root-owned."** Any remote-code-execution or
command-injection flaw in the panel is immediately unconditional root on that machine.

This is not narrowable by editing the sudoers file. The panel escalates local work as
`sudo bash -c '<command>'`, and a sudoers rule that permits `/bin/bash` is exactly as
powerful as `NOPASSWD:ALL` — a "scoped" list containing bash would read as narrower while
granting identical power. A real reduction needs a privileged helper: a single script
granted sudo, accepting a fixed set of verbs, with every privileged call routed through it.

**That work has started, and is not finished.** `tools/panel-helper` is that script. It is
installed root-owned at `/usr/local/lib/linuxgsm-panel/panel-helper`, deliberately outside
the panel's own checkout — the checkout belongs to the panel user and `git pull` rewrites it
on every self-update, so a helper living there would be panel-writable by design. It takes a
verb and already-separated arguments, re-validates every argument against its own table, and
execs a fixed argument vector. There is no shell in it, and the only program it can run is
one it names: `bash` does not resolve.

Converted so far: **`ufw`, `fail2ban-client`, `systemctl`, `apt`/`dpkg`, the log reads
(`journalctl` / `tail`), and cron plus user management** — 43 verbs.

**A correction to the numbers previously reported here.** Earlier revisions of this section
said the panel had "113" privileged call sites and tracked them down to 42. That counted only
`run_command(..., sudo=True)`. There is a second escalation route — a helper named `_sudo_sh`
that builds `sudo bash -c '<pipeline>'` itself and then passes `sudo=False`, so it is invisible
to a search for `sudo=True`. It had 18 call sites the whole time. The real starting figure was
**131 root-escalating sites, not 113**.

Both routes are now counted by a test that ratchets: the ceilings may be lowered as call sites
convert and never raised, so a new escalation written as a shell string fails the build instead
of going unnoticed. Current state:

| route | sites remaining |
|---|---|
| `run_command(..., sudo=True)` | 4 |
| `_sudo_sh(...)` | **0 — the route is gone** |
| **root total** | **4** (from 131) |

`_sudo_sh()` built `sudo bash -c '<pipeline>'` itself and passed `sudo=False`, which is why a
search for `sudo=True` never saw it and why its 18 call sites went uncounted for half this work.
It has no callers left and the function itself has been deleted, so that route cannot come back by
accident.

**Two of the four that remain cannot be narrowed by a verb at all** — they are the downloaded-script
installers named below. The other two are large read-only shell programs that gather host state (the
LinuxGSM server discovery scan and the per-server metrics probe): both are reads, both have their
interpolated values validated upstream, and converting either means reimplementing a working
multi-stage scan inside the helper. They are the least valuable and highest risk of what is left,
which is why they are last.

(Those counts exclude six calls that ARE the verb layer's own transport — the `run_command` /
`_run_local` / `_run` at the end of `run_privileged`, `write_root_file`, `write_content_cron` and
`_run_verb`, which pass
a command built from the verb table rather than composed at a call site. Earlier revisions counted
them, overstating the remaining work. A test pins the exclusion at exactly those six, so it cannot
quietly widen and make the number flattering.)

Separately there are ~46 `sudo -u <gameuser>` sites. Those run as the game user rather than
root, so they are a smaller problem — but they still depend on the same unrestricted grant,
and they are not yet counted in the conversion.

Two of those verb families are worth describing, because the narrowing is in the argument
types rather than in the command names:

- The systemd verbs take a unit from an **exhaustive list** (`ssh`, `sshd`, `fail2ban`,
  `whoopsie`, `cups`, `modemmanager`). Those are the only services the panel ever touches, so
  a unit-name *pattern* would only buy the ability to control units nobody asked it to.
- The write verb takes a **destination name** and the content on **stdin**. Locally the helper
  does the write itself in Python — the content is never an argument, and the path is looked up,
  so `write-file /etc/shadow` fails on the *name*, not on a filter.
- **The sshd port change** is the one sequence whose failure mode is "you can no longer reach the
  machine", so every step of it is a verb: snapshot the drop-in, write the new one, run `sshd -t`
  against the whole config, restart, confirm the port is actually listening, and restore the
  snapshot on any failure. A test asserts the drop-in may be written *only* while that entire
  sequence exists, and the rollback is exercised against a sandboxed filesystem rather than by
  inspecting the commands: a host that had no drop-in ends with none, and a host that had one gets
  it back byte for byte.
- **The GMod shared-content box** shares nothing until access is granted: `serverfiles` is created
  private (`0700`) and the group bits are added by the grant verb, where the shell form created it
  group-readable from the moment it existed. It builds every path from a validated user name plus a
  validated game or script identifier. Three of its verbs end in `rm -rf` running as root, so the caller
  passes *names* and the helper assembles the paths — `content_path()` re-checks the assembled
  result, and is tested directly rather than only through the verbs, because the verbs' own
  validators would otherwise reject every probe before it got that far.
- **The detached OS-update job** was `setsid bash -c '<seven statements>' &` — truncate, header,
  `export`, `apt-get update`, `full-upgrade` with four `-o` flags, `autoremove`, and a sentinel
  carrying the exit code. It took no caller input at all, which is what lets it be a zero-argument
  verb rather than a command the panel composes.
- **Tailscale's join** took the auth key, the advertised routes and the tags straight from the
  request and shell-quoted them into a root command. They are validated arguments now: routes are
  *parsed* as networks, each tag must be `tag:name`, and the auth key is charset-checked and never
  echoed back — not even in a rejection, since the value is a secret. The interactive login flow's
  poll log also moved from `/tmp` to `/run`: in `/tmp` any local user could pre-create the file the
  root poll then reads.
- **The sshd hardening** set four directives with `sed -i 's/^#\?Key.*/Key value/'` in a joined
  root shell. Both halves are closed sets now: the panel may set exactly those four directives, to
  exactly the values it hardens them to. `PermitRootLogin yes` is individually well-formed and
  still refused, which is a property a per-argument check cannot express.
- **The fail2ban top-IPs report** was a five-stage `zcat | awk | grep | awk | sort | head` running
  as root, with the cutoff date and the row limit interpolated into it. The verb does the read half
  only — a fixed log glob, gzip handled in Python — and the tallying is Python. Both halves are
  asserted against real plain and gzipped logs rather than by comparing command strings.
- **The deferred reboot** was `( sleep 2 ; reboot ) &` — a subshell, a background job and a
  redirect. The helper double-forks instead: the grandchild detaches, waits, and execs the reboot
  binary. It returns immediately, which is the whole reason the subshell existed.
- The log verbs take a **source name**, never a path or a unit: `log-tail auth`, not
  `tail /var/log/auth.log`. The table turns the name into the path, so reading `/etc/shadow`
  through the helper is not something a filter rejects — it is not expressible.
- `apt-install` is the one verb taking a variable-length list. Every package name is
  charset-checked individually, and the list has a floor and a ceiling — so a name cannot be
  an option (`--reinstall`), and the list cannot be made arbitrarily long. dpkg's conflict
  answers (`--force-confdef`, `--force-confold`) are fixed in the helper rather than passed
  in, so an unattended upgrade can never be talked into clobbering a config file you edited.

**Two operations cannot be narrowed, and are named rather than left unremarked.** The VPS
bootstrap installs Node.js by piping NodeSource's setup script into a root shell, and installs
Tailscale the same way. That IS the operation in both cases: a verb could pin the URL, but only by
giving the helper the ability to execute a downloaded script — exactly the capability its tool
allowlist exists to deny. Wrapping either would move the risk, not reduce it. If that trade is not
one you want, those two bootstrap steps are the thing to change, not the helper.

Still to convert that go through `echo … | base64 -d >`, and the two multi-line shell
scripts (the detached OS-update runner and the NodeSource installer).

**Until that list is empty the grant stays `NOPASSWD:ALL` and nothing above has reduced your
exposure.** A privilege boundary with a hole in it is not a boundary, and it would be worse
than useless to describe it as one. Two holes remain by construction: call sites that still
compose shell strings, and a fallback in `run_privileged()` that uses the old path when the
helper is not installed (an upgraded host has the new code before it has the helper). Both go
away in the same change that narrows the sudoers line.

What you can do today:

- **If you only manage remote servers from this panel**, delete
  `/etc/sudoers.d/linuxgsm-panel`. The panel keeps working; the grant disappears. Only
  local-host management (panel-host OS updates, its firewall, its game-server users)
  stops working.
- **If you do manage the local host**, treat the panel host as you would any machine
  where a network service can become root: keep it off the public internet, keep 2FA on,
  and keep it updated.

Installs run as a **normal user** (the non-root path) get no sudoers entry at all and are
not affected.

Thank you for helping keep the project and its users safe.
