# Changelog

All notable, user-facing changes to the LinuxGSM Panel. The project is pre-1.0 and alpha — see the
README disclaimer. Versioning is loosely [semantic](https://semver.org). Note: the panel's in-app
"update available" check compares git commits, so you always get the newest CI-verified commit
regardless of this file — this changelog is for humans.

## [Unreleased]

### Fixed
- **Six endpoints answered HTTP 500 when a remote host was simply unreachable.** A host that is
  powered off, rebooting, or behind a broken link is a normal condition for a panel that manages
  remote machines — not a fault in the panel. `live`, `pro-status`, `uptime`, `firewall`,
  `check-updates` and `tailscale-check` all raised straight through, so opening a host's Manage page
  while it was down filled the browser console with 500s, and any alerting on the panel's own 5xx
  rate fired for someone else's downtime. `live-stats` already answered `200` with an error field
  and explained why in a comment; its siblings never followed. They do now, keyed on the
  `ConnectionError` that `ssh_manager` raises specifically for unreachable — anything that is *not*
  a connection failure still returns 500, deliberately, because those are the panel's own bugs.
- **Four buttons on the Remote Servers page did nothing.** `manage_remotes.html` loaded its script
  from inside the content block, which `base.html` renders *before* `panel.js`. The top-level
  `pollWhenVisible(...)` call in `manage_remotes.js` therefore threw `ReferenceError` while the file
  was still evaluating, and every top-level statement after it was skipped — including the delegated
  click handler wiring **Tailscale check, Tailscale bootstrap, Install Tailscale and Delete remote**.
  Function *declarations* are hoisted, so the page looked normal and the only symptom was one line in
  the browser console. The live-stats auto-refresh on that page never started either. Both page
  scripts now load from `{% block scripts %}`, and a template gate fails the build if any page loads
  a script before `panel.js` again.
- **A failed swap-file setup still wrote a swap entry to `/etc/fstab`.** The shell form was
  `fallocate && chmod && mkswap && swapon && grep -q … || echo … >> /etc/fstab`, and `&&`/`||` are
  left-associative with equal precedence — so the append ran whenever *any* earlier step failed,
  not only when the grep found nothing. A host that ran out of space got an fstab entry pointing at
  a file that was never formatted.
- **A parser could crash on a superscript digit.** `str.isdigit()` is true for characters like `¹`
  that `int()` refuses, and the panel used that pairing in 35 places — including the query port read
  from a game server's own config, and the session-cookie user loader. Found by the fuzzer, fixed
  everywhere with `isdecimal()`, which is exactly the predicate `int()` accepts.
- **A dead constant in `ssh_manager` turned main red.** `_OS_UPDATE_LOG` stopped being used when the
  detached OS-update job moved into the privileged helper — the helper writes that log and hands it
  back through the `os-update-log` verb, so the panel never names the path any more. The alias, and
  a comment still claiming the runner "writes to it by name", are gone. The reason it reached main
  at all is the more useful half: the local orphaned-constant gate counted a *test* reference as
  proof a name was alive, and the only thing left mentioning this one was its own parity test. The
  gate now requires a reference from production code and says so when a name is test-only.
- **The "main has open code-scanning alerts" gate raced CodeQL and reported the wrong answer.** It
  ran on the same push as the analysis rather than after it, so a commit that *fixed* an alert
  failed the gate, and — worse — a commit that *introduced* one passed it, with the alert then
  blamed on whatever landed next. It now runs when CodeQL completes.

### Security
- **A missing `data/config.json` reopened four unauthenticated setup endpoints.** The setup wizard's
  Tailscale endpoints (`/api/setup/tailscale/{status,install,up,serve}`) have no login — during a
  fresh install there is no user yet — so they are safe only for as long as their "setup is still
  open" test is. That test was `is_setup_complete()`, which is *DB row AND config flag*, and the
  config half fails open: `load_config()` returns `DEFAULT_CONFIG` (where `setup_complete` is
  `False`) on any `JSONDecodeError`/`OSError`. On a fully configured panel, a `config.json` that was
  deleted, truncated by a full disk, or hand-edited into invalid JSON therefore unlocked all four to
  anyone who could reach the port: `install` runs the Tailscale installer as root, `up` returns an
  auth URL that joins **the panel's host** to the caller's tailnet with SSH enabled, and `serve`
  rewrites `bind_host` and `site_domain`. They now use the same DB-row-only lock the wizard itself
  has used since the equivalent hole was closed there — the reasoning was already written down in
  `setup_wizard()`, just never applied to these four. A lost config file should degrade the panel,
  not hand it over.
- **Three VPS-preparation actions could be aimed at the panel's own host.** The remotes page hides
  *Prepare* and *Tailscale* for the local host, but the API routes behind them accepted a POST
  carrying its id — so anyone with "manage remotes" could apt full-upgrade the panel's own machine,
  rewrite its `sshd_config`, pipe an installer into a root shell, and reboot it out from under the
  request. The routes refuse the local host now, with a JSON 400 that says why.
- **The privileged helper has landed, and the firewall now goes through it.** The panel escalates
  local work as `sudo bash -c '<command>'`, which is why its sudoers grant could never be narrowed:
  permitting `/bin/bash` *is* `NOPASSWD:ALL`. `tools/panel-helper` is a root-owned script that takes
  a verb and separated arguments, re-validates each one, and runs a fixed command — no shell, and
  `bash` is not a program it can reach. The `ufw`, `fail2ban-client`, `systemctl` and `apt`/`dpkg`
  families now use it, plus the log reads, user/cron management and the root-owned config writes —
  77 verbs, including the sshd port change, the deferred reboot, Ubuntu Pro, the host controls, the
  GMod shared-content box, the fail2ban activity report and the VPS hardening steps. Root-escalating call
  sites that still build a shell string are down from 131 to 4, and the `_sudo_sh` escalation
  route is gone entirely, and a ratcheting test now counts
  BOTH escalation routes (an earlier count missed `_sudo_sh`, which had 18 sites of its own). **This does not reduce your exposure yet**: the grant stays `NOPASSWD:ALL` until
  every privileged call site is converted, because a boundary with a hole in it is not a boundary.
  See SECURITY.md.

### Fixed
- **The panel could not hear its own deprecation warnings.** A filter installed at import time
  silenced every `DeprecationWarning` in the process, permanently — and did not silence the one it
  named, because eventlet's banner is not a `DeprecationWarning` at all, so it printed on every start
  regardless. Running the panel under `-W always::DeprecationWarning` heard nothing. Now only
  eventlet's banner is silenced, and `-W` / `PYTHONWARNINGS` work again.
- **`datetime.utcnow()`, which Python has scheduled for removal, is gone** from all 22 call sites
  (including twelve database column defaults). Stored timestamps are unchanged — still naive UTC, to
  the microsecond — they now come from `clock.utcnow()`.

## [0.10.0-alpha] — 2026-09-09

Two months of work that had accumulated on `main` unreleased. The headline items are OS-update
visibility, Ubuntu 26.04 support, a mobile pass, and a run of security fixes.

### Added
- **OS updates, surfaced in the panel** — a login banner listing hosts with packages waiting, and a
  per-host card filled from the daily sweep's answer rather than by running `apt` on page load.
  Security updates are called out separately from ordinary ones.
- **OS-update alerts to Telegram/Discord** when a host first has updates waiting, on the transition
  rather than daily, so it stays an alert instead of noise you filter out.
- **Ubuntu 26.04 support.** CI now runs the suite on 22.04, 24.04 and 26.04, each paired with the
  Python that release actually ships (3.10 / 3.12 / 3.14). 22.04 and 24.04 remain supported.
- **Overwrite prompt on file upload** — dropping a file whose name already exists asks first, showing
  the size and modified date of both the file on the server and the one being uploaded, with a
  tickbox per file. Unticked files are skipped.
- **Start / Stop / Restart on Files & Config**, which previously told you to restart the server
  without offering a way to do it, plus its missing History tab.

### Changed
- **The mobile layout reclaims most of the first screen.** Measured at 375x812, page content used to
  begin below the fold; the two-factor reminder alone took 30% of the viewport. It is now a single
  strip, the server table's action buttons stay pinned in view instead of sitting off-screen behind
  a horizontal scroll, and tab strips scroll rather than wrapping their labels onto three lines.
- **Host status says what it means.** "Offline" described both a host the panel cannot reach and a
  stopped game server, in the same red, on the same screen. Hosts now read Reachable / Unreachable,
  and a host that has not been checked yet reads "Checking…" rather than asserting it is unreachable.
- **The dashboard tiles add up.** Servers that were installing or failed appeared in no tile, so the
  numbers visibly disagreed with the total.
- **Accessibility**: every form label is now associated with its input, modal close buttons have
  accessible names, and controls that fell under WCAG 2.2 AA's 24px target size were raised.
- The **Autostart switch follows the crontab** instead of a database column that could go stale.
- The **users page renders one edit modal** rather than one per user.

### Fixed
- **The OS-update alert never actually ran.** It was the one database-touching background task
  without a Flask app context, so every tick raised and was swallowed at debug level.
- **A failed `apt` check no longer reads as "System is up to date."** apt produces no output when it
  fails, which is exactly what a clean host produces; the check's exit status is now carried through
  to the UI and the alert.
- **Deleted hosts and servers no longer leave state behind.** SQLite reuses a deleted row's id, so a
  newly added server could inherit "already alerted" flags — and, worse, the previous server's player
  capacity — from the one that used to hold that id.
- The **pending-restart banner** now accounts for the daily-restart schedule.
- Console output rendering: Minecraft commands no longer display as `ssasay  hi` or `>=>`.

### Security
- **Cross-site scripting from a compromised remote host.** A host's own output — its Tailscale login
  URL and IP — was rendered into the panel admin's browser unescaped in several places.
- **Symlink escape in the file browser.** The path check was lexical and could not see symlinks,
  because the path lives on the remote machine; every file operation now resolves the path where it
  actually is before acting on it.
- **TOTP codes are single-use.** A code stays valid for about 90 seconds, so one observed once could
  be replayed for the rest of that window.
- **Session fixation.** The authenticated session is now established on a clean session rather than
  inheriting whatever the pre-login one carried.
- **The setup wizard is locked by database state**, not by a config flag. An unreadable `config.json`
  reopened the unauthenticated wizard on a configured install, where it could rewrite the panel's
  bind address and port.
- **Failed API-token authentication is throttled.** `/login` had a brute-force limit; the bearer-token
  path — the panel's other way in — had none.
- **Chat-bot actions are attributable.** A `/restart` or `/update` from Telegram or Discord was logged
  as a "system" action, with nothing recording that a chat message caused it or who sent it.
- **A panel restore no longer leaves the database and both encryption keys in `/tmp`** after it runs.
- Shell identifiers are re-validated where they are used, not only when assigned, and are length-bounded.
- `SECURITY.md` now documents an important limitation honestly: a root install grants the panel's
  service user unrestricted passwordless sudo, so there is currently no privilege boundary between a
  compromised panel and a rooted host. It explains why this cannot be narrowed by editing sudoers
  alone, and that remote-only installs can remove the grant entirely.

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
