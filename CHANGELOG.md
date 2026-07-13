# Changelog

All notable, user-facing changes to the LinuxGSM Panel. The project is pre-1.0 and alpha — see the
README disclaimer. Versioning is loosely [semantic](https://semver.org). Note: the panel's in-app
"update available" check compares git commits, so you always get the newest CI-verified commit
regardless of this file — this changelog is for humans.

## [0.9.0-alpha] — 2026-07-13

### Added
- **Per-device session management** — the account page now lists every device/browser signed in to
  your account (device, IP, last-active) and lets you revoke them **individually**, not just all at
  once. Logging out now signs out only the current device; "Sign out everywhere" still clears them all.
- **Garry's Mod content mounting** — install Counter-Strike: Source and other Source-engine games'
  content via LinuxGSM so GMod maps and props render instead of missing-texture errors. One shared
  copy per host, mounted read-only into each GMod server with per-server enable/disable, one-click
  uninstall, a free-disk readout, and a weekly content auto-update cron (16 installable games).
- **Two-way Discord command bot** over the Gateway — alongside the Telegram bot; `!status`,
  `!servers`, `!players <name>`, `!update`, and `!start` / `!stop` / `!restart <name>`, locked to the
  configured channel.
- **Settings page** (superadmin) — branding (site name, accent colour, login tagline), the default UI
  language for new users, and session/security tuning (idle timeout, remember-me, session-protection
  level, auto-block threshold), all applied live.
- **Configurable alert thresholds** — disk %, CPU-load %, and memory % — plus **sustained-duration
  high-load alerts** that page only after load stays over the line for a set number of minutes.
- **Metrics + player history charts** (24h / 7d) on the server page, live-updating.
- **Weekly auto-update of npm + gamedig** (the player-query tools) on every host.
- **"Jail" column** on the login-security top-offenders table.

### Changed
- **Every scheduled task is now editable and deletable**, including the LinuxGSM/panel-installed ones.
- **Mods merged into a single Install/Remove list**; installing a mod no longer auto-restarts the
  server — you're prompted to restart when ready.
- **GMod content installs via LinuxGSM** (not raw SteamCMD), so it gets validation and the weekly
  update cron for free.
- **Group-by-host** on the Game Servers list now shows one card per host.
- Removed the global **notifications master switch** — a channel's own enable toggle is the on/off.
- **start/stop/restart run in the background** so the button never hangs; remaining per-server SSH in
  request handlers was parallelised.
- **Account page** — two-column layout on desktop; the API-access (personal token) card was removed.

### Fixed
- **PaperMC / Velocity / Waterfall** now report player count + max (queried via gamedig on the real port).
- **Minecraft/Paper console** no longer shows terminal control-code noise (JLine ANSI + prompt lines).
- **Sidebar active-state** is correct under a URL mount prefix (e.g. `/lgsm` via Tailscale Serve).
- **Import** auto-caches each server's LinuxGSM command list, so "Supported Commands" isn't blank.
- Remote **public-IP resolution** moved off the request path — an unreachable host no longer hangs a page.
- **Self-update snapshot** no longer aborts on a root-owned unreadable file (e.g. a Tailscale cert key).
- The panel no longer binds to loopback unless Tailscale Serve is actually configured to proxy it.

## [0.8.0-alpha] — 2026-07-11

First tracked release. The `VERSION` file had drifted from the git tags (last tag `v0.7.15-alpha`),
so this re-baselines it and starts the changelog. Notable changes since then:

### Added
- **Telegram command bot** — drive the panel from Telegram: `/update`, `/status`, `/servers`,
  `/hosts`, `/players <name>`, and `/start` / `/stop` / `/restart <name>`, with a `/` autocomplete
  menu. Opt-in and locked to the configured chat.
- **Global ban list** — ban a SteamID once and it applies to every Source/GoldSrc server across all
  hosts, via each server's own native ban list.
- **Proactive admin alerts** to Telegram/Discord for 18 events (server down, host unreachable, disk
  low, high load, brute-force, backup failed, update available, cert expiring, and more), plus a
  per-server "notify when empty" one-shot.
- **In-game server names** on the dashboard and Game Servers list (from gamedig, with a console
  fallback for servers that don't answer Steam queries).
- **Sort + group-by-host** on the Game Servers list, and click-to-sort columns on the dashboard.
- **Security whitelist** (IP/CIDR) that is never fail2ban-banned or UFW auto-blocked — on the panel
  host and every remote.
- REST **API tokens** (Bearer auth).

### Changed
- **Auto-block** now firewalls IPs by failed-attempt count over a rolling 7-day window (not a fixed
  top-20), and pushes the whitelist into remote hosts' fail2ban too.
- **Installs and bootstraps no longer reboot a host that has running game servers** — they reboot
  only when an update requires it, never out from under players.
- Player-count polling runs **concurrently**, so a pass no longer scales with the number of servers.
- Config writes go through a lock-safe read-modify-write, so concurrent writers can't lose changes.
- README rewritten and shortened.

### Fixed
- A failed gamedig query now reads as **unknown**, not a bogus `0` players.
- Server controls are disabled while a server is installing or uninstalling.
- Cleared the CodeQL full-SSRF finding on the Discord webhook sink (constant host + validated
  id/token).
- The Telegram `/update` completion check compares the **git commit**, not the static VERSION.

[0.9.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.9.0-alpha
[0.8.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.8.0-alpha
