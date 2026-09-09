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

Converted so far: **the `ufw` family** — 14 verbs covering every firewall read and write the
panel performs. Still to convert: `apt`/`dpkg`, `systemctl`, `fail2ban-client`, `journalctl`,
cron, user management, and the reboot path.

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
