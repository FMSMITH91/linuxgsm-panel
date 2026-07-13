# LinuxGSM Panel 🎮

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/FMSMITH91/linuxgsm-panel/badge)](https://scorecard.dev/viewer/?uri=github.com/FMSMITH91/linuxgsm-panel) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/b179bcf8d27941bb9ad20839ea2fe4b7)](https://app.codacy.com/gh/FMSMITH91/linuxgsm-panel/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

[![CI](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/ci.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/ci.yml) [![CodeQL](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/codeql.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/codeql.yml) [![Security scan](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/security.yml/badge.svg)](https://github.com/FMSMITH91/linuxgsm-panel/actions/workflows/security.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)

A self-hosted web panel for managing **[LinuxGSM](https://linuxgsm.com)** game servers across one or more Ubuntu machines, with role-based access for super admins, server admins, and moderators.

> ## ⚠️ Disclaimer — please read first
>
> - **Not an official LinuxGSM product** — an independent third-party panel, not affiliated with or endorsed by LinuxGSM. Trademarks belong to their owners.
> - **Created and modified almost entirely by AI.** Read the code and test it before trusting it with real servers or credentials.
> - **Provided "as is", no warranty — use at your own risk.** See [Security](#security).

## Requirements

- A host running **Ubuntu 22.04 or 24.04 LTS** for the panel (CI tests both; other distros may work but aren't supported).
- One or more game-server machines on the same, reachable over SSH (key, password, or Tailscale SSH). The panel host can also manage itself.
- **LinuxGSM** on those machines, or let the panel install it.
- *Optional:* **[Tailscale](https://tailscale.com)** for private HTTPS with no open ports.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
```

**What the installer does** — one command, unattended:

1. Installs the prerequisites it needs (`python3-venv`, `pip`, `git`, `curl`).
2. Patches the OS with `apt full-upgrade` — skip with `PANEL_NO_UPGRADE=1 bash install.sh`.
3. Clones the repo, builds a Python virtualenv, and installs the panel's dependencies.
4. Picks a free port (5000 by default) and records it in `data/config.json`.
5. Sets up the service — **and never runs the panel as root**:
   - **As a normal user** → a `systemd --user` service with linger, so it survives logout/reboot.
   - **As root** → creates a dedicated non-login **`lgsmpanel`** user, runs a *system* service as that user, and adds a *scoped* passwordless-sudo entry so it can manage the local host (create game-server users, `apt`, `ufw`…). Also installs the `linuxgsm-panel-recover` command. Remove the sudoers entry if this panel only ever manages *remote* servers.
6. Serves HTTPS with a built-in self-signed cert (a trusted Tailscale Serve cert is offered in the wizard), then **reboots**.

Then finish in the browser: open **`https://your-server:5000`** (`http://` won't load — it's TLS-only), accept the one-time cert warning (**Advanced → Proceed**), and the **setup wizard** creates your first super admin.

### Updating

- **In the panel:** *Panel Server → Update*. This is **CI-gated** — it only moves to a commit whose checks have all passed — and runs detached so it survives its own restart. Also available via the Telegram/Discord `/update` command.
- **From the shell:** re-run the same command (or `bash install.sh` from the checkout). A manual re-run pulls the branch tip directly (not CI-gated), so do it when you know the tip is good.

Either way the update is the same and safe: it **snapshots the code *and* database**, pulls, reinstalls deps, restarts, **health-checks** that the panel actually came back, and **auto-rolls-back** (code + DB) if it didn't — so a broken release can't leave you with a dead panel.

## Uninstall

```bash
sudo bash ~lgsmpanel/linuxgsm-panel/uninstall.sh   # root / system install
bash ~/linuxgsm-panel/uninstall.sh                 # per-user install
#   add --yes to skip the "type yes to confirm" prompt
```

**Removes everything the installer created:** the systemd service, the panel files and its `data/` (accounts, config, encryption keys), and — for a root install — the sudoers entry, the `linuxgsm-panel-recover` command, the panel's own UFW port rule, its Tailscale Serve binding, and the dedicated `lgsmpanel` user.

**Leaves your game servers completely alone.** Their Linux users, home directories, LinuxGSM installs, `@reboot` autostart crontabs, and game-port firewall rules are never touched — so every server keeps running exactly as before once the panel is gone.

## Features

**Game servers**
- One-click install of any LinuxGSM game (Garry's Mod, Minecraft, CS2/CS:Source, TF2, ARMA 3, Rust, and 130+ more), including LinuxGSM itself and the ports it needs.
- Real-time WebSocket console, command sending, per-game CPU/RAM/uptime tiles, and live current/max player counts (gamedig, with console + LinuxGSM-query fallbacks).
- Player-aware control — start/stop/restart/update/validate and more; restart, stop, backups, mod changes, and host reboots can wait until a server is empty.
- Mods & addons (SourceMod, MetaMod, Oxide, ULX…), FastDL generation, per-server cron with autostart and daily-restart-when-empty, and a config/file browser with upload and in-browser editing.
- **Garry's Mod content mounting** — install Counter-Strike: Source and other Source-engine games' content (via LinuxGSM) so GMod maps and props render instead of showing missing-texture errors. One shared copy per host, mounted read-only into each GMod server, with per-server enable/disable, one-click uninstall, a free-disk readout, and a weekly content auto-update cron.
- Per-server LinuxGSM alerts (Discord, Telegram, email, Pushover, Slack, Gotify…).

**Backups**
- One-click and scheduled backups of the panel (DB, settings, keys) and of each game server (LinuxGSM full backups), with retention, download, and restore.
- Per-server schedules override a global default; player-aware (busy servers queue) and disk-aware (won't start a backup that can't fit).

**Access, security & hosts**
- Multi-user RBAC (Super Admin / Server Admin / Moderator / Viewer) — groups set per-action permissions and per-server access, enforced server-side on every route.
- Fine-grained moderation (**kick / ban / announce** individually) and superadmin-defined **custom console commands** with a charset-validated argument, granted per group.
- One host page for the panel and every remote: specs, live per-core resources, OS updates, UFW firewall, power controls, Ubuntu Pro, SSH lockdown, and lockout-safe port/bind changes.
- **Brute-force defense** — fail2ban integration with per-jail logs, top offenders, one-click UFW blocking, and an optional rolling **auto-block** that firewalls every IP over a failed-attempt threshold (default 20 / 7 days) and releases it once its count drops back below. A whitelist (IP/CIDR) and your Tailscale peers are never banned or blocked.
- **Proactive admin alerts** to Telegram/Discord for 18 events — server down, host unreachable, disk low, sustained high CPU/RAM load, brute-force, backup failed, update available, cert expiring, and more — with tunable thresholds (disk %, CPU-load %, memory %, and how long load must stay high before it pages you).
- **Two-way command bot** (Telegram *or* Discord) — drive the panel from chat: `/status`, `/servers`, `/hosts`, `/players <name>`, `/update`, and `/start` / `/stop` / `/restart <name>`. Opt-in and locked to the configured chat/channel.
- Tailscale integration (private Serve, MagicDNS, SSH-over-tailnet), multiple SSH remotes with host-key pinning, diagnostics with file-integrity self-heal, and audit logging.

**Also** — a superadmin **Settings** page (branding: site name, accent colour, login tagline; default UI language; session & security tuning), all applied live; HTTPS by default, TOTP 2FA with backup codes, revocable sessions, CSRF + strict CSP; light on small VPSes; multi-language (English, Spanish, French); and a first-run setup wizard.

## Screenshots

> IPs, hostnames, and accounts are placeholders (`203.0.113.10`, `example.ts.net`, `admin@example.com`).

| | |
|---|---|
| **Dashboard** — every server across every host | **Live console & per-game stats** |
| ![Dashboard](docs/screenshots/01-dashboard.png) | ![Console](docs/screenshots/02-console.png) |
| **Host manager** — panel host and every remote | **Firewall** — UFW rules, one-click game ports |
| ![Host manager](docs/screenshots/03-host-manager.png) | ![Firewall](docs/screenshots/04-firewall.png) |
| **Files & config** | **Granular permissions** |
| ![Files](docs/screenshots/05-files.png) | ![Permissions](docs/screenshots/06-permissions.png) |

## Configuration

Stored in `data/config.json` after the setup wizard. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `port` | 5000 | Web server port |
| `bind_host` | 0.0.0.0 | Bind address (`127.0.0.1` behind a proxy) |
| `trust_proxy` | false | Trust `X-Forwarded-*` from a reverse proxy |
| `session_lifetime_hours` | 8 | Idle session timeout (sliding) |
| `remember_days` | 3 | "Remember me" cookie lifetime |
| `ssh_timeout` | 10 | SSH connection timeout (seconds) |

Branding (site name, accent colour, login tagline), the default UI language for new users, the session timeouts and protection level, and the brute-force auto-block threshold are editable in-app at **Administration → Settings** (superadmin) and apply live. Network keys (`port`, `bind_host`, `trust_proxy`) stay in `config.json` since changing them can't safely be done from the web.

## Permissions

Groups grant any mix of these, scoped to specific servers/hosts. `super_admin` bypasses all checks.

| Permission | Grants |
|------------|--------|
| `view_servers` / `view_console` / `view_logs` | See status / console / audit logs |
| `send_command` | Send raw console commands |
| `moderate_server` | Umbrella for `kick_player` + `ban_player` + `say_server` (also grantable individually) |
| `start_server` / `stop_server` / `restart_server` / `update_server` | Power & update controls |
| `install_server` / `uninstall_server` / `manage_servers` | Add, remove, and define game servers |
| `manage_remotes` / `manage_users` / `manage_groups` | Manage hosts / users / groups |
| `super_admin` | Full administrator access |

**Typical groups:** *Admins* — view + power + `manage_servers`; *Moderators* — view + `kick/ban/say` on specific servers; *Viewers* — `view_servers` only. Super Admin is auto-granted via `is_superadmin` (no group needed).

## Production deployment

Run behind **Tailscale** (recommended — tailnet-only, no open ports; auto-detected in the wizard or managed at `/tailscale`) or a **reverse proxy**. With a proxy, set `"trust_proxy": true` and `"bind_host": "127.0.0.1"` so the panel serves HTTP to the proxy that terminates TLS. See [docs/https.md](docs/https.md).

```bash
# Tailscale Serve (private) — or `tailscale funnel` for public
tailscale serve --bg --https 443 http://127.0.0.1:5000
```

```nginx
# Reverse proxy — the WebSocket console needs the upgrade headers
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 86400;
}
```

## Security

- **HTTPS by default** (self-signed out of the box; Tailscale Serve or a proxy for a trusted cert).
- **Passwords** bcrypt-hashed with a length/case/number/symbol policy; logins are rate-limited.
- **Two-factor (TOTP)** optional per account, with one-time backup codes; super admins without it are reminded.
- **Sessions** — signed `HttpOnly` `SameSite=Lax` `Secure`-over-HTTPS cookies with a sliding idle timeout and a capped "remember me". "Sign out everywhere" revokes every session server-side.
- **Encryption at rest** — SSH credentials, emails, and 2FA secrets are Fernet-encrypted in `data/panel.db` (key in `data/cred_key`); `data/` is `chmod 700`, secrets inside `chmod 600`.
- **SSH host-key pinning** — refuses to connect if a host's key changes; re-trust a reinstalled host in one click.
- **RBAC enforced server-side** on every route, scoped per host, covered by automated tests.
- **CSRF protection, a strict CSP, and security headers** (HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) on every response; input validation on anything that becomes an OS operation.

> Prefer running behind Tailscale over exposing the panel to the internet, and never commit `data/` (it holds `panel.db`, `secret_key`, `cred_key`, `config.json` — already in `.gitignore`).

### Recovery

Locked out? One command on the panel host talks straight to `data/panel.db`, so it works even when you can't log in (a password reset revokes existing sessions):

```bash
sudo linuxgsm-panel-recover                          # reset the sole superadmin's password
sudo linuxgsm-panel-recover reset-password <user>
sudo linuxgsm-panel-recover disable-2fa <user>       # lost your authenticator
sudo linuxgsm-panel-recover create-admin <user>      # or: promote / activate <user>
```

Run `--help` for the full list. On an older install without the command, use the one-liner:

```bash
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/recover.sh | sudo bash
```

## Development

```bash
git clone https://github.com/FMSMITH91/linuxgsm-panel.git && cd linuxgsm-panel
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py

bash tools/run-tests.sh    # compile, flake8, unit + smoke tests, shellcheck
```

CI runs the same suite on every push and PR, plus CodeQL, Bandit, Semgrep, a dependency audit, and coverage-guided fuzzing (`tests/fuzz/`).

## Contributing

Issues and pull requests are welcome — this is a solo, AI-assisted project, so extra eyes genuinely help. Report security issues privately via [SECURITY.md](SECURITY.md), not a public issue. For code, fork and open a PR against `main`, run `bash tools/run-tests.sh` first, and keep CI green.

## License

MIT
