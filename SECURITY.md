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
| `run_command(..., sudo=True)` | 31 |
| `_sudo_sh(...)` | 16 |
| **root total** | **47** (from 131) |

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
  so `write-file /etc/shadow` fails on the *name*, not on a filter. The sshd drop-in is
  deliberately absent from that table, and a test asserts it stays absent.
- The log verbs take a **source name**, never a path or a unit: `log-tail auth`, not
  `tail /var/log/auth.log`. The table turns the name into the path, so reading `/etc/shadow`
  through the helper is not something a filter rejects — it is not expressible.
- `apt-install` is the one verb taking a variable-length list. Every package name is
  charset-checked individually, and the list has a floor and a ceiling — so a name cannot be
  an option (`--reinstall`), and the list cannot be made arbitrarily long. dpkg's conflict
  answers (`--force-confdef`, `--force-confold`) are fixed in the helper rather than passed
  in, so an unattended upgrade can never be talked into clobbering a config file you edited.

Still to convert: the remaining file writes (the sshd drop-in and the per-user content cron) that go through `echo … | base64 -d >`, the two multi-line shell
scripts (the detached OS-update runner and the NodeSource installer), and the **deferred
reboot** — `( sleep 2 ; reboot ) &`, deliberately left for its own change, because getting a
reboot verb wrong is the most expensive mistake available here.

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
