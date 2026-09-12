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

When the installer is run as **root** it creates a dedicated service user and grants it
passwordless sudo. **What that grant permits now depends on whether the root-owned helper
pieces are installed**, and the installer tells you which one it wrote:

| condition | grant |
|---|---|
| helper + root-owned `db_maintenance.py` + root-owned installer all present | `ALL=(root) NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper` |
| any of them missing | `ALL=(ALL) NOPASSWD:ALL` — unchanged, and the panel falls back to the pre-helper path |

For most of this project's life it was unconditionally the second row, and this document said
so in these words: *there is no privilege boundary between "the web panel is compromised" and
"the host is root-owned."* On an install with the narrow grant that is no longer true. On one
without it, it still is — **re-run `install.sh` as root to get the narrow grant**.

Why it could not simply be edited into place earlier: the panel escalated local work as
`sudo bash -c '<command>'`, and a sudoers rule permitting `/bin/bash` is exactly as powerful as
`NOPASSWD:ALL`. The same is true of `systemd-run` and of the `tailscale` binary — each runs
whatever you hand it. A "scoped" list containing any of them reads as narrower while granting
identical power. Every one of those was a call site; every one is a verb now, and none appears
in the narrow grant.

**The helper.** `tools/panel-helper` is that script. It is
installed root-owned at `/usr/local/lib/linuxgsm-panel/panel-helper`, deliberately outside
the panel's own checkout — the checkout belongs to the panel user and `git pull` rewrites it
on every self-update, so a helper living there would be panel-writable by design. It takes a
verb and already-separated arguments, re-validates every argument against its own table, and
execs a fixed argument vector. There is no shell in it, and the only program it can run is
one it names: `bash` does not resolve.

Converted so far: **`ufw`, `fail2ban-client`, `systemctl`, `apt`/`dpkg`, the log reads
(`journalctl` / `tail`), cron and user management, the sshd port change, the deferred reboot,
Ubuntu Pro, the host controls, the GMod shared-content box, the fail2ban activity report, the
detached OS update, Tailscale's join, the panel's own restore/self-update and the VPS hardening
steps** — 88 verbs. (`tests/unit_test.py` asserts this number against `privileged.verbs()`, so it
cannot drift from the table again.)

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
  `whoopsie`, `cups`, `modemmanager`, `unattended-upgrades`). Those are the only services the panel
  ever touches, so a unit-name *pattern* would only buy the ability to control units nobody asked it
  to. The panel's OWN unit is deliberately not in that list — it is reachable through exactly one
  verb, `panel-restart`, which takes a bounded delay and nothing else.
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
- **The file browser's downloads** are the one place a caller-chosen *path* crosses the boundary —
  everywhere else a path is assembled from a validated identifier. It could not be an identifier
  here: these files are named by mod authors, map packers and Windows tooling, so a charset filter
  would refuse real files the browser is already listing. So the argument is checked for SHAPE
  (non-empty, relative, no `..` component, no NUL or newline, bounded length) and the containment
  question is answered where it can be answered honestly. The helper looks the home directory up
  from the **passwd entry**, never from the caller; then it forks, drops supplementary groups, gid
  and uid to the **game user**, and only then resolves the path with `realpath` and opens it. Both
  halves of that order matter: a check before the drop is a check against a path nobody will open,
  and a read as *root* would turn a download button into "hand me any file on the box" — a
  privilege increase out of a change meant to reduce privilege. The panel passes the canonical
  relative path rather than the string it received, and refuses the home directory itself. The
  folder download is Python's `tarfile` writing to the pipe, not the `tar` binary: an archiver that
  takes a path and reads whatever it finds is a general file-reader under another name, and the
  helper resolves only the tools its verbs name. Symlinks are stored as links, never followed.
  Over **SSH** the path is not in the command at all: a download there is parsed twice — once
  assembling the local `ssh` argv, again by the remote shell — and two-level quoting is where this
  class of bug lives, so the remote command is FIXED TEXT and the relative path arrives on stdin as
  data. A hostile filename and a benign one produce byte-identical commands, which is what the test
  asserts; the containment check rides in that fixed text and judges the resolved path on the host.
- The log verbs take a **source name**, never a path or a unit: `log-tail auth`, not
  `tail /var/log/auth.log`. The table turns the name into the path, so reading `/etc/shadow`
  through the helper is not something a filter rejects — it is not expressible.
- `apt-install` is the one verb taking a variable-length list. Every package name is
  charset-checked individually, and the list has a floor and a ceiling — so a name cannot be
  an option (`--reinstall`), and the list cannot be made arbitrarily long. dpkg's conflict
  answers (`--force-confdef`, `--force-confold`) are fixed in the helper rather than passed
  in, so an unattended upgrade can never be talked into clobbering a config file you edited.

Those two installer steps are also now **unreachable on the panel's own host**: the routes that
run them (VPS bootstrap, Tailscale install, Tailscale join) refuse the local host outright. The
remotes page had always hidden them for it; the routes had not, so a direct POST could aim a full
VPS preparation — including a reboot — at the machine the panel runs on.

**Two operations cannot be narrowed, and are named rather than left unremarked.** The VPS
bootstrap installs Node.js by piping NodeSource's setup script into a root shell, and installs
Tailscale the same way. That IS the operation in both cases: a verb could pin the URL, but only by
giving the helper the ability to execute a downloaded script — exactly the capability its tool
allowlist exists to deny. Wrapping either would move the risk, not reduce it. If that trade is not
one you want, those two bootstrap steps are the thing to change, not the helper.

**Every one of those is converted, and the grant has narrowed.** On an install where the three
root-owned pieces are present, `/etc/sudoers.d/linuxgsm-panel` contains one line:

```
<panel-user> ALL=(root) NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper
```

Nothing else. In particular **not** `/bin/bash`, `/bin/sh`, `systemd-run`, the `tailscale`
binary, or `sudo -u` — each of those runs whatever argv you hand it, so permitting any one of
them would be `NOPASSWD:ALL` wearing a disguise. Each was a call site once; each is a verb now.

Three conditions bound that claim, and all are enforced rather than asserted:

* **The grant only narrows when all three root-owned pieces landed** — the helper, the
  root-owned `db_maintenance.py`, and the root-owned installer. A host running new code that
  has not had `install.sh` re-run as root keeps the wide grant, because it still falls back to
  `sudo bash -c '<verb rendered as text>'` and narrowing under that would break every
  privileged action rather than secure anything. The installer prints which grant it wrote.

* **Root no longer executes anything out of the panel's checkout.** `PANEL_DIR` is owned by the
  service user and rewritten by `git pull` on every self-update, so a boundary that let root run
  files from there would have been decorative — the panel could take root by writing to its own
  files. The offline DB repair and the self-update now run root-owned copies placed only by
  `install.sh`, never by a verb. This mattered more than the sudoers line itself: narrowing
  without it would have produced something that looked locked down and was not.

* **The installed helper has to stay in step with the panel's code.** It lives outside the
  checkout, so the panel cannot refresh it — only `install.sh` can, as root. The verb table grows
  most releases, and a helper left behind answers a new verb with `unknown verb` and rc 2, with no
  fallback: the feature behind it simply stops working, silently. `install.sh` therefore refreshes
  the helper (and `db_maintenance.py`, `panel.conf` and its own root-owned copy) on the **update**
  path as well as a fresh install, and re-evaluates the sudoers grant there — which is also the
  only way a host that first installed before the helper existed ever gets narrowed. The panel's
  Diagnostics card compares the two verb tables and says which verbs are missing if they differ.

The remaining `sudo` call sites in the source are the pre-helper fallbacks described above. They
are counted by a ratchet in the test suite (`direct ['sudo', ...] sites`) that can fall but never
rise, so the boundary cannot quietly erode.

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
