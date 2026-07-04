# LinuxGSM Panel 🎮

> ## ⚠️ Disclaimer — please read first
>
> - **This is NOT an official LinuxGSM product or website.** It is an independent, third‑party web panel and is **not affiliated with, sponsored by, endorsed by, or connected to [LinuxGSM](https://linuxgsm.com) or its creator/maintainers** in any way. "LinuxGSM" is the name of the separate open‑source project this panel automates; all rights and trademarks belong to their respective owners.
> - **This panel was created and modified almost entirely by AI.** Treat it accordingly — read the code yourself and test it before trusting it with real servers or credentials.
> - **Use entirely at your own risk.** Provided "as is", with no warranty of any kind. See [Security](#security) for important notes (including how remote SSH credentials are stored).

A self-hosted web panel for managing **LinuxGSM** game servers on remote VPS machines. Full role-based access control with granular permissions — super admins, server admins, and moderators.

> **🔒 Built-in Tailscale integration** — auto-detects your Tailscale status, one-click **private** Serve
> setup (tailnet-only, free on the Personal plan), MagicDNS URL discovery, and peer reachability checking
> for your remote nodes.

## Features

- **🔐 Multi-user RBAC** — Super Admin, Server Admin, Moderator, Viewer. Define groups with granular permissions (view, send commands, restart, install, uninstall, manage users, etc.)
- **🖥️ Live Console** — Real-time WebSocket streaming of game server console output. Send commands directly to the running game.
- **🔗 Tailscale Native** — Auto-detect Tailscale status, one-click private Serve setup (tailnet-only, free tier), MagicDNS URL, peer connectivity checker, auto-setup on first run. (Public Funnel exposure is an optional, clearly-warned advanced toggle.)
- **🔌 Multiple Remote VPS** — Manage game servers across many machines via SSH key or password auth. Built-in Tailscale peer reachability check before adding remotes.
- **📦 Install Game Servers** — Install any LinuxGSM-compatible game server with one click (Garry's Mod, Minecraft, CS:Source, TF2, ARMA 3, Rust, etc.)
- **🛑 Full Control** — Start, stop, restart, update, monitor — all from the web UI.
- **📋 Audit Logging** — Every action is logged with user, IP, target, and timestamp.
- **⚡ Setup Wizard** — First-run wizard guides you through site config, admin creation, and remote VPS connection. Auto-configures Tailscale Serve if detected.
- **🔌 REST API** — Full JSON API for server status, console, and commands.

## Screenshots

> ℹ️ IP addresses, hostnames, and account details in these screenshots are **redacted** with
> placeholder values (`203.0.113.10`, `example.ts.net`, `admin@example.com`).

**Dashboard** — every game server across every host, at a glance.

![Dashboard](docs/screenshots/01-dashboard.png)

**Live console & per-game stats** — real-time WebSocket console streaming, per-game CPU/RAM/uptime tiles, and a live resource graph.

![Game server console](docs/screenshots/02-console.png)

**Host manager** — the *same* page for the panel host and every remote: hardware/OS specs, live per-core resources, OS updates, firewall, power, Ubuntu Pro (free ESM + Livepatch), and one-click panel self-updates.

![Host manager](docs/screenshots/03-host-manager.png)

**Firewall** — raw UFW rules parsed into clean columns with IPv4/IPv6 merged, plus one-click opening of every port a game needs.

![Firewall](docs/screenshots/04-firewall.png)

**Files & config** — grouped LinuxGSM settings, the game's own config file, and a full file browser with drag-and-drop upload, in-browser editing, and delete guards that protect files LinuxGSM/the game needs.

![Files & config](docs/screenshots/05-files.png)

**Granular permissions** — groups bundle per-action permissions with per-server access; a user inherits the combined set. Enforcement is server-side on every endpoint.

![Groups & permissions](docs/screenshots/06-permissions.png)

## Quick Install

One command installs the panel — and re-running the **same command** later updates it in place:

```bash
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
```

- Run as a normal user → installs under that user as a `systemd --user` service.
- Run as **root** → the panel is **not** run as root; the installer creates a dedicated non-login service user and runs it as a system service.
- Auto-detects Tailscale and offers HTTPS via Tailscale Serve during the setup wizard.

### Safe, self-healing updates

Re-running the command on an existing install performs a **verified update**: it snapshots the current code **and** database, pulls the new version, restarts the service, and **health-checks** that the panel actually comes back up. If it doesn't, it **automatically rolls back** to the previous version — code and database — so a bad release can't leave you with a dead panel. The command is idempotent; run it as often as you like.

```bash
# Later, to update (same command — installs or updates):
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
```

Prefer a checkout? `git clone` then `bash install.sh` does exactly the same thing, and `bash install.sh` again updates it.

Or install manually:

```bash
# Create environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
python app.py
```

Open `http://your-server:5000` — the setup wizard will guide you through configuration.

## Configuration

Configuration is stored in `data/config.json` after the setup wizard runs. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `site_title` | LinuxGSM Panel | Display name for the panel |
| `site_domain` | (empty) | Public domain, for reverse proxy setup |
| `port` | 5000 | Web server port |
| `bind_host` | 0.0.0.0 | Bind address (use `127.0.0.1` behind nginx) |
| `session_lifetime_hours` | 24 | Login session duration |
| `ssh_timeout` | 10 | SSH connection timeout in seconds |

## Permission Groups

The panel uses a flexible group-based permission system:

| Permission | Description |
|------------|-------------|
| `view_servers` | See server status on dashboard |
| `view_console` | View live console output |
| `send_command` | Send commands to game server console |
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

- **Super Admin** — All permissions (auto-granted via `is_superadmin` flag, no group needed)
- **Admins** — `view_servers`, `view_console`, `send_command`, `start_server`, `stop_server`, `restart_server`, `update_server`, `manage_servers`
- **Moderators** — `view_servers`, `view_console`, `send_command` (on specific servers)
- **Viewers** — `view_servers` only

## API

The panel provides a JSON API for integration:

```bash
# List servers (requires auth cookie)
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

### With Tailscale (Recommended)

If Tailscale is installed, the panel auto-detects it during the setup wizard. You can also manage Tailscale Serve from the web UI at `/tailscale`.

```bash
# One-click setup from the web UI:
# Navigate to /tailscale and click "Enable Serve"
# Or use the CLI directly:
tailscale serve --bg --https 443 http://127.0.0.1:5000

# Make it public (Tailscale Funnel):
tailscale funnel --bg --https 443 http://127.0.0.1:5000
```

**Tailscale features in the panel:**
- **Auto-detection** — Status, IPs, MagicDNS, peer count shown on the Tailscale page
- **One-click Serve/Funnel** — Enable/disable from the UI without touching the CLI
- **Peer Reachability Check** — Ping any host on the tailnet before adding it as a remote VPS
- **Auto-setup** — If Tailscale is running during first-time setup, Serve is configured automatically
- **MagicDNS URL** — Shown in the dashboard, startup logs, and setup completion page
- **Peer List** — See all connected devices with hostname, IP, OS, and status

### With systemd (installed by default)

```bash
systemctl --user enable --now linuxgsm-panel
```

## Requirements

- Python 3.9+
- SSH access to target VPS (key or password)
- LinuxGSM installed on target (or the panel will install it)
- Remote VPS: Linux (Ubuntu/Debian/CentOS)

## Security

- Passwords are **bcrypt-hashed**; new passwords require length plus mixed case, a number and a symbol, and logins are rate-limited.
- **Secrets are encrypted at rest** — remote SSH credentials and other sensitive fields are stored encrypted in `data/panel.db` (key in `data/cred_key`). The session key and these files are kept owner-only (`chmod 600`).
- Sessions use signed, `HttpOnly`, `SameSite=Lax` cookies (`Secure` when served over HTTPS).
- **Role-based access control is enforced server-side on every route** — not just hidden in the UI. Server access is scoped per host, and an automated test verifies the enforcement.
- Remote access uses Paramiko (SSH key/password) or the system `ssh` client for Tailscale SSH — with Tailscale SSH there are **no stored credentials at all** (recommended).
- Input that becomes shell/OS operations is strictly validated; audit logging records the acting user, real client IP, target, and result of sensitive actions.
- Super admins bypass all permission checks — use that role sparingly.

> **Operational note:** run the panel behind Tailscale (tailnet-only, no open ports) rather than exposing it to the public internet, and never commit `data/` to version control — it holds `panel.db`, `secret_key`, `cred_key`, and `config.json` (already in `.gitignore`).

## Development

```bash
git clone https://github.com/FMSMITH91/linuxgsm-panel.git
cd linuxgsm-panel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## License

MIT
