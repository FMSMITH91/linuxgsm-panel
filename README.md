# LinuxGSM Panel 🎮

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/FMSMITH91/linuxgsm-panel/badge)](https://scorecard.dev/viewer/?uri=github.com/FMSMITH91/linuxgsm-panel) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/b179bcf8d27941bb9ad20839ea2fe4b7)](https://app.codacy.com/gh/FMSMITH91/linuxgsm-panel/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

[![CI](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/ci.yml) [![CodeQL](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/codeql.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/codeql.yml) [![Security scan](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/security.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/security.yml) [![Lighthouse](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/lighthouse.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/lighthouse.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)

> ## ⚠️ Disclaimer — please read first
>
> - **Not an official LinuxGSM product.** An independent, third-party web panel — not affiliated with, endorsed by, or connected to [LinuxGSM](https://linuxgsm.com). "LinuxGSM" is the separate open-source project this panel automates; trademarks belong to their owners.
> - **Created and modified almost entirely by AI.** Read the code and test it before trusting it with real servers or credentials.
> - **Provided "as is", with no warranty — use at your own risk.** See [Security](#security).

A self-hosted web panel for managing **LinuxGSM** game servers across remote VPS machines, with role-based access control — super admins, server admins, and moderators.

## What you need

> ⚠️ **Ubuntu 22.04 or 24.04 LTS** — the supported releases (CI runs both). Other distros may work but aren't supported.

- **A host running Ubuntu 22.04 / 24.04 LTS** for the panel. The installer sets up Python 3.10+, a virtualenv, and dependencies.
- **One or more game-server machines (Ubuntu 22.04 / 24.04 LTS) reachable over SSH** (key, password, or Tailscale SSH). The panel host can also manage itself.
- **LinuxGSM** on those machines, or let the panel install it.
- *Optional:* **[Tailscale](https://tailscale.com)** for private HTTPS access with no open ports.

## Quick Install

One command installs the panel; re-running it later updates in place:

```bash
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
```

- Fresh install brings the OS up to date (`apt full-upgrade`), installs the panel, and reboots. Updates are panel-only unless OS updates are pending. Skip OS upgrades with `PANEL_NO_UPGRADE=1`.
- Run as a normal user → a `systemd --user` service. Run as **root** → a dedicated non-login service user; the panel never runs as root.
- Serves HTTPS with a built-in self-signed certificate, and offers a trusted Tailscale Serve certificate in the setup wizard.

**Then open `https://your-server:5000`** — accept the one-time self-signed-cert warning (**Advanced → Proceed**), and the setup wizard takes it from there. *(`http://` won't load — the panel speaks TLS.)*

### Safe, self-healing updates

Re-running the command performs a verified update: it snapshots code **and** database, pulls the new version, restarts, and health-checks that the panel comes back — rolling back automatically if it doesn't. The command is idempotent. The in-panel *update-available* badge only lights up for changes that affect the running panel.

A `git clone` followed by `bash install.sh` does the same, and re-running `bash install.sh` updates.

### Uninstalling

The uninstaller removes **only the panel** — its service, files, data, sudoers entry, and (root install) the `lgsmpanel` user. Game servers are left intact.

```bash
# root/system install
sudo bash ~lgsmpanel/linuxgsm-panel/uninstall.sh

# per-user install
bash ~/linuxgsm-panel/uninstall.sh
```

Type `yes` to confirm, or add `--yes` to skip the prompt.

## Features

### Game servers
- **📦 Install any LinuxGSM game** — one-click install of any LinuxGSM-compatible server (Garry's Mod, Minecraft, CS2/CS:Source, TF2, ARMA 3, Rust, and 130+ more). Installs LinuxGSM itself and opens every port the game needs.
- **🖥️ Live console & stats** — real-time WebSocket console, send commands to the game, and per-game CPU/RAM/uptime tiles with a live resource graph.
- **👥 Live player counts** — current / max players per server on the dashboard and Game Servers page, plus a total-online tile, refreshed in the background (gamedig, with a game-console and LinuxGSM-query fallback).
- **🛑 Player-aware control** — start, stop, restart, update, validate, monitor, and other LinuxGSM commands. Restart and stop check who's online and offer to wait until the server is empty; a host reboot warns if any of its servers has players.
- **🧩 Mods & addons** — browse, install, and remove LinuxGSM-supported mods (SourceMod, MetaMod, Oxide, ULX, and game-specific ones). A pending change restarts the server once it's empty.
- **📣 Alerts** — configure LinuxGSM's alerts (Discord, Telegram, email, Pushover, Pushbullet, Slack, Gotify, IFTTT) per server, with a test button.
- **🌐 FastDL** — generate a Source-engine FastDL directory for supported games.
- **⏰ Scheduled tasks (cron)** — manage a server's cron jobs with last-run status and a "run now" button, plus autostart-on-boot and daily-restart-when-empty toggles.
- **🗂️ Files & config** — grouped LinuxGSM settings, the game's own config file, and a file browser with drag-and-drop upload, in-browser editing, and delete guards.

### Backups
- **💾 Panel backups** — one-click and daily backups of the database, settings, and encryption keys, with retention, download, and restore.
- **🎮 Game-server backups** — LinuxGSM full backups per server, on-demand or scheduled, with per-backup download and delete. Player-aware: a busy server is queued and backed up once it empties.
- **📅 Per-server schedules** — a global default (daily / weekly / fortnightly / monthly + keep-count) that each server can override or turn off.
- **📊 Disk-aware** — shows free disk, estimates retention usage, warns before it's tight, frees space when needed, and won't start a backup that can't fit.

### Access, security & hosts
- **🔐 Multi-user RBAC** — Super Admin, Server Admin, Moderator, Viewer. Groups define per-action permissions and per-server access; users inherit the combined set, enforced server-side on every endpoint.
- **🛡️ Moderation & custom commands** — grant fine-grained moderation (**kick / ban / announce**, individually) per group and per server. Super admins can define reusable **custom console commands** with an optional, charset-validated argument, and grant specific ones to specific groups.
- **🔗 Tailscale** — auto-detect status, one-click private Serve (tailnet-only, free tier), MagicDNS URL, SSH-over-tailnet, and peer reachability checking. Public Funnel is an optional, warned toggle.
- **🔌 Multiple remotes** — manage servers across many machines via SSH key, password, or Tailscale SSH, with host-key pinning.
- **🖧 Host management** — one page for the panel host and every remote: hardware/OS specs, live per-core resources, OS updates, UFW firewall (open ports and a separate blocked-IPs view), power controls, Ubuntu Pro (ESM + Livepatch), SSH lockdown, and lockout-safe changes to a host's SSH port/bind address and the panel's own web port/bind.
- **🚫 Brute-force protection** — a fail2ban-backed Security page with per-jail logs and the top offenders over the last 7 days, one-click UFW blocking of an IP on all ports, and an optional rolling auto-block that firewall-bans the worst offenders and releases each once it goes quiet. Tailscale peers are never blocked, so the auto-block can't lock you out of your own tailnet.
- **🩺 Diagnostics & self-heal** — verify file integrity against the installed version and restore altered files, generate a debug report, and run self-healing updates.
- **🔒 Secure by default** — HTTPS out of the box, optional TOTP two-factor with backup codes, revocable sessions, CSRF protection, security headers, and bcrypt-hashed passwords.

### Everything else
- **🪶 Light on small VPSes** — runs at low CPU/IO priority, prefers RAM over swap, and caches repeated work.
- **🌍 Multi-language** — English, Spanish, and French, with a saved per-user preference; untranslated strings fall back to English.
- **📋 Audit logging** — every action logged with user, IP, target, and timestamp.
- **⚡ Setup wizard** — first-run site config, admin creation, and remote connection; auto-configures Tailscale Serve if detected.
- **🔌 REST API** — JSON API for server status, console, and commands.

## Screenshots

> ℹ️ IPs, hostnames, and account details are redacted with placeholders (`203.0.113.10`, `example.ts.net`, `admin@example.com`).

**Dashboard** — every game server across every host.

![Dashboard](docs/screenshots/01-dashboard.png)

**Live console & per-game stats**

![Game server console](docs/screenshots/02-console.png)

**Host manager** — the same page for the panel host and every remote.

![Host manager](docs/screenshots/03-host-manager.png)

**Firewall** — UFW rules in clean columns, with one-click game ports.

![Firewall](docs/screenshots/04-firewall.png)

**Files & config**

![Files & config](docs/screenshots/05-files.png)

**Granular permissions**

![Groups & permissions](docs/screenshots/06-permissions.png)

## Configuration

Stored in `data/config.json` after the setup wizard runs. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `site_title` | LinuxGSM Panel | Display name for the panel |
| `site_domain` | (empty) | Public domain, for reverse proxy setup |
| `port` | 5000 | Web server port |
| `bind_host` | 0.0.0.0 | Bind address (use `127.0.0.1` behind nginx) |
| `session_lifetime_hours` | 8 | Idle session timeout (sliding) |
| `remember_days` | 3 | "Remember me" cookie lifetime |
| `ssh_timeout` | 10 | SSH connection timeout in seconds |

## Permission Groups

| Permission | Description |
|------------|-------------|
| `view_servers` | See server status on dashboard |
| `view_console` | View live console output |
| `send_command` | Send commands to game server console |
| `moderate_server` | Moderate players — kick, ban & announce (umbrella for the three below) |
| `kick_player` | Kick players from a server |
| `ban_player` | Ban players from a server |
| `say_server` | Announce a message in-game |
| `restart_server` | Restart game servers |
| `start_server` | Start game servers |
| `stop_server` | Stop game servers |
| `update_server` | Update game servers |
| `install_server` | Install new game servers |
| `uninstall_server` | Uninstall/decommission servers |
| `manage_servers` | Add/remove game server definitions |
| `manage_remotes` | Add/edit/delete remote VPS nodes |
| `manage_users` | Manage user accounts |
| `manage_groups` | Manage groups and permissions |
| `view_logs` | View audit logs |
| `super_admin` | Full system administrator access |

### Suggested Group Setup

- **Super Admin** — all permissions (auto-granted via `is_superadmin`, no group needed)
- **Admins** — `view_servers`, `view_console`, `send_command`, `start_server`, `stop_server`, `restart_server`, `update_server`, `manage_servers`
- **Moderators** — `view_servers`, `view_console`, and `kick_player` / `ban_player` / `say_server` on specific servers
- **Viewers** — `view_servers` only

## API

A JSON API for integration. HTTPS by default, so use `https://` (add `-k` to `curl` for the self-signed cert), or `http://` only when a proxy/Tailscale terminates TLS in front of it. Every call needs an authenticated session cookie.

```bash
# List servers
curl http://localhost:5000/api/servers

# Get server status
curl http://localhost:5000/api/server/1

# Get console output
curl http://localhost:5000/api/console/1

# Send command (POST)
curl -X POST http://localhost:5000/api/command/1 \
  -H "Content-Type: application/json" \
  -d '{"command":"status"}'
```

## Production Deployment

### Behind Nginx

```nginx
server {
    listen 443 ssl;
    server_name panel.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }
}
```

Set `"trust_proxy": true` and `"bind_host": "127.0.0.1"` in `data/config.json`: the panel serves plain HTTP to the proxy (which terminates TLS) and trusts its `X-Forwarded-*` headers. See [docs/https.md](docs/https.md).

### With Tailscale (recommended)

Auto-detected during the setup wizard; also managed from the `/tailscale` page.

```bash
# From the web UI: /tailscale → "Enable Serve"
# Or the CLI:
tailscale serve --bg --https 443 http://127.0.0.1:5000

# Public (Tailscale Funnel):
tailscale funnel --bg --https 443 http://127.0.0.1:5000
```

### With systemd (default)

```bash
systemctl --user enable --now linuxgsm-panel
```

## Security

- **HTTPS by default** — a built-in self-signed certificate out of the box; use Tailscale Serve or a reverse proxy for a trusted certificate. See [docs/https.md](docs/https.md).
- **Passwords** — bcrypt-hashed; new passwords require length, mixed case, a number, and a symbol; logins are rate-limited.
- **Two-factor (TOTP)** — optional per account, with one-time backup codes shown (and downloadable) once at setup; super admins without 2FA get a reminder.
- **Password change** — from the Account page (current password, plus a 2FA code when enabled); super admins can reset anyone's from the Users page.
- **Sessions** — signed, `HttpOnly`, `SameSite=Lax`, `Secure`-over-HTTPS cookies with a sliding idle timeout and a capped "remember me". Logout, password change, or "sign out everywhere" invalidates every session and remember cookie server-side; sessions are bound to client IP + User-Agent.
- **Encryption at rest** — SSH credentials, email addresses, and 2FA secrets are Fernet/AES-encrypted in `data/panel.db`, with the key in `data/cred_key`; passwords and 2FA backup codes are bcrypt-hashed. `data/` is `chmod 700` and the database, keys, and config inside are `chmod 600`.
- **SSH host-key pinning** — records each host's key on first connect and refuses to connect if it changes; re-trust a reinstalled host with one click. Tailscale SSH stores no credentials.
- **Brute-force defense** — fail2ban integration with an optional rolling UFW auto-block of repeat offenders over a 7-day window; Tailscale peers are exempt so the auto-block can't cut off tailnet access.
- **RBAC enforced server-side** on every route, scoped per host, and covered by automated tests.
- **CSRF protection, a strict Content-Security-Policy, and security headers** (HSTS over HTTPS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) on every response.
- **Input validation** on anything that becomes a shell/OS operation; audit logging records the acting user, real client IP, target, and result.
- **Locked out?** Reset a forgotten password, recover 2FA, or restore an admin from a shell on the panel host — see [Recovery](#recovery).
- Super admins bypass all permission checks — use that role sparingly.

> Run the panel behind Tailscale (tailnet-only, no open ports) rather than exposing it to the public internet, and never commit `data/` — it holds `panel.db`, `secret_key`, `cred_key`, and `config.json` (already in `.gitignore`).

### Recovery

One command, from anywhere on the panel host — it finds your install and runs as the panel's own user:

```bash
sudo linuxgsm-panel-recover                          # reset the sole superadmin's password
sudo linuxgsm-panel-recover reset-password <user>    # a specific user
sudo linuxgsm-panel-recover disable-2fa <user>       # lost your authenticator
sudo linuxgsm-panel-recover create-admin <user>      # or: promote / activate <user>
sudo linuxgsm-panel-recover list-users
```

It talks straight to `data/panel.db`, so it works even when you can't log in; a password reset revokes existing sessions. Run `sudo linuxgsm-panel-recover --help` for the full list.

Older install without the command? The one-liner does the same:

```bash
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/recover.sh | sudo bash
# with an action:   curl -fsSL .../recover.sh | sudo bash -s -- disable-2fa alice
```

## Development

```bash
git clone https://github.com/FMSMITH91/linuxgsm-panel.git
cd linuxgsm-panel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Tests

```bash
bash tools/run-tests.sh    # compile, flake8, unit + smoke tests, shellcheck
```

CI runs the same suite on every push and pull request, plus CodeQL, Bandit, Semgrep, a dependency
audit, and coverage-guided fuzzing of the untrusted-input parsers (`tests/fuzz/`).

## Contributing

Bug reports, feature ideas, and pull requests are welcome — this is a solo, AI-assisted project, so
extra eyes genuinely help.

- **Found a bug or have an idea?** Open an [issue](https://github.com/FMSMITH91/linuxgsm-panel/issues).
- **Security vulnerability?** Please report it privately — see [SECURITY.md](SECURITY.md), not a public issue.
- **Submitting a change?** Fork, create a branch, and open a pull request against `main`. Run
  `bash tools/run-tests.sh` before pushing and keep the CI checks green, and match the style of the
  surrounding code.

## License

MIT
