# Changelog

All notable, user-facing changes to the LinuxGSM Panel. The project is alpha — see the README
disclaimer. Each commit on `main` is a release, named by its date in UTC, written YYYY.M.D
(`2026.9.26`) and shown with the short commit. "Since 0.10.0-alpha" lists everything released that
way; the numbered sections below it (0.8.0 to 0.10.0) are from before. The panel's update check
compares git commits, not this file.

<!-- Every release repeats the same Added / Changed / Fixed / Security headings, as Keep a
     Changelog lays them out, so MD024 is asked only to keep two SIBLING headings apart. -->
<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

## [Since 0.10.0-alpha]

### Added

- **Scheduled world resets for Paper and Minecraft Bedrock.** The world reset on the Schedule tab
  now also works for Paper and Bedrock servers: the server is stopped and backed up, its world is
  deleted and it makes a new one, while plugins, ops, the allowlist, permissions and server settings
  are kept. The panel deletes only a folder that holds a real Minecraft world, and refuses settings
  that would point the server at a different world folder.

- **Scheduled world resets for Minecraft and Factorio.** The wipe card on the Schedule tab can reset
  a Minecraft Java or Factorio world on a schedule. The server is stopped, backed up with LinuxGSM,
  its world is deleted, Factorio gets a new map made the way LinuxGSM's install makes it, and the
  server is started again. Ops, the whitelist, bans, mods and server settings are kept. A server
  that was stopped stays stopped, and the panel refuses rather than delete a world it cannot
  identify.

- **Separate permissions for a server's files and its backups.** Groups can be given View game
  server files and Change game server files instead of the whole Manage servers permission, and a
  game server's backups can be downloaded or deleted by groups given Download or Delete backup
  archives. Groups that could manage servers keep the file permissions after the update, so nobody
  gains or loses access. View game server files includes the passwords those files hold.

- **Network traffic and history charts on the host page.** Each host's received and sent traffic
  is recorded with its CPU, RAM and disk history, and the server page's History tab charts it. The
  host page's Overview tab has a History card with CPU, RAM, disk and network over the last 24
  hours or 7 days.
- **A form for the game's own config file.** Files & Config's game config card has a Form view
  beside the raw editor, for key=value, .ini, Source and idTech cfg, 7 Days to Die XML and JSON
  files. Each setting is a field with the file's comments as help, passwords are hidden until shown,
  and a save changes only the values you edited. Minecraft's server.properties and the other
  non-.cfg config files LinuxGSM reports now open there too.
- **Start checks the port first.** Starting a stopped server from the panel checks that its port is
  free. If another server on the host is running on it, or something else listens there, the panel
  says so and offers "Start anyway". If the host can't be read, the server starts as before.
- **A port changed on the Settings tab is followed.** Saved while the server is stopped, the panel
  watches the new port at once. Saved while it runs, the new port takes effect at the next start or
  restart from the panel. Games that keep their port in their own config file still follow it when
  the panel restarts or on Sync ports.
- **Scheduled restarts, stops and updates can warn players first.** On the Schedule tab, a
  restart, stop or update can send up to five chat warnings before it runs, for example 5 and 1
  minutes before. It is offered for Source, GoldSrc, idTech3 and Minecraft servers. The first
  warning goes out at the scheduled time, and the form shows when the action itself happens.
- **Steam Workshop items and collections on the server page.** Arma 3, DayZ, Squad and the other
  games whose LinuxGSM config has a Workshop list get an ordered list of items and collections, with
  titles from Steam and a Download now button. Garry's Mod and CS:GO get their collection, and
  Project Zomboid gets its Workshop items and Mod IDs, with the Mod IDs in already-downloaded items
  offered as one-tap adds.
- **Plugins for PaperMC servers.** A PaperMC server's page has a Plugins card: search Modrinth for
  Paper, Spigot and Bukkit plugins built for the server's Minecraft version, and install one in a
  click. The panel downloads the file itself and checks it against Modrinth's checksum before it
  reaches the server. Installed plugins can be disabled, enabled again or removed; changes take
  effect on the next start.
- **Minecraft operators, whitelist and bans on the server page.** A Minecraft Java or PaperMC
  server's page has a Player Lists card. It shows the server's operators, whitelist and banned
  players and addresses, and changes them through the server console while the server is running.
  Names, addresses and reasons are checked before anything is sent, every change is in the audit
  log, and the card says when the server did not apply a change (a name that is no Minecraft
  account, for one).
- **Updates no longer skip a release the next one depends on.** A panel that is several releases
  behind first installs any release listed in `panel/install/update-stops`, then the newest one on
  its next update. The Update card offers each in turn. If your panel's updates keep rolling back
  to the same version, the README's Updating section has the one command that fixes it.
- **See what an update brings before you install it.** When an update is available, the
  Maintenance tab's Update card lists the changelog entries it adds, the same ones "What's new"
  shows afterwards; tap one to read it. The commits are still there, folded underneath.
- **Install the panel on a phone's home screen.** A phone's browser now offers "Install" or "Add to
  Home screen", and the panel then opens in its own window, also under a Tailscale Serve path.
- **A light theme.** The Account page's "Language and theme" card offers System (the default),
  Dark and Light, saved to the account so it follows you to every device. The console and the host
  terminal stay dark in both.
- **"What's new" after the panel updates.** The first time you open the panel after an update,
  a small window lists the changelog entries added since you last looked.
- **The console remembers the commands you sent.** Up and Down in the command box bring back the
  last 50 commands sent to that server from this browser.
- **Quick commands under the console.** For Source, Quake 3 engine and Minecraft servers, one-tap
  buttons send common commands such as `status` or `list`. Only people who may send console
  commands see them.
- **The script log and the game's own log on the server page.** A menu beside "Live Console" shows
  the last 300 lines of LinuxGSM's script log or of the game's newest log file. It needs the file
  browser's permission, and says so when a log cannot be read.
- **The LinuxGSM settings form explains each setting.** Each field on Files & Config → Config shows
  LinuxGSM's own help, a docs link where LinuxGSM names one, and which file the value comes from.
  The file editor now refuses to save an instance's `_default.cfg`, which LinuxGSM overwrites.
- **Game pictures and search on the Install page.** Every game is a tile with its icon, full name
  and script name, with a search box. Icons come from linuxgsm.com but are checked and kept under
  `data/`, so your browser only loads them from the panel.
- **Scheduled wipes for Rust.** A Rust server's Schedule tab can run a map or full wipe on a
  schedule in your timezone. A LinuxGSM backup is taken first (if it fails, nothing is wiped), and
  a run that did not wipe sends an alert.

- **Each server's page shows which LinuxGSM release it runs.** It appears under the game's own
  version, with "· v26.5.0 available" when LinuxGSM has a newer release; update-lgsm in the
  Maintenance menu updates it.
- **An opt-in debug log.** With `"debug_log": true` in `data/config.json` (and a restart), the
  panel writes detailed DEBUG messages to `data/debug.log`, readable only by the panel's account and
  capped at 20 MB. It is off by default.

- **The Telegram and Discord bots show "typing…" while a command is working.** Any command that
  takes longer than a moment shows the bot typing until it replies (up to two minutes).

- **Updates install only signed releases.** The installer now moves the panel only to a commit
  that also carries a signature made with the release key; anything else, or anything it cannot
  verify, is held with "Not updated: held at …" and why. The update card offers only a signed
  commit whose checks passed. A lost key is recovered by running the installer by hand with
  `PANEL_ALLOW_UNSIGNED_UPDATE=1`, which the panel itself can never pass.
- **Firewall settings and port blocks on the Network tab.** A row above the rules shows and changes
  UFW's default policies and logging level and turns the firewall on or off, each asking first. A
  change that would lock you out (cutting SSH or the panel's own way to the host) is refused, saying
  what is missing. Add a rule gains a **Block** mode for a port or range, put above rules that open
  it; SSH's ports, the panel's web port and the ports Tailscale uses cannot be blocked. **Open** can
  keep a port to IPv4 or IPv6 only, and **Blocked IPs** takes a range, refusing one that covers
  Tailscale's addresses, the whitelist, your own address or the panel's. Every change is audited,
  and on the panel's own host all of it is superadmin-only.
- **LinuxGSM v26.4.0 support.** LinuxGSM 26.4 can warn players in-game before a stop
  (`warnplayerstimer`) and, with `stoponlyifnoplayers` on, put off a stop, restart, update or backup
  while players are online. The panel now works with both:
  - *Only stop when empty* and *Warn players first* (0–60 minutes) in LinuxGSM Settings, on servers
    running 26.4 or later.
  - Stop, Restart, Update, Backup, queued actions and host reboots wait for the warning.
  - Work LinuxGSM puts off is reported as postponed, never as finished or failed.
  - The panel's scheduled backups no longer run alongside LinuxGSM's postponed backup.
  - Reboots still stop every server cleanly and warn players once, and Cancel calls off LinuxGSM's
    countdown.
  - workshop-update is in the Maintenance menu where LinuxGSM offers it.
  - A Team Fortress 2 server whose `startparameters` lacks `-norestart` shows a notice to add it.
- **A one-click fix for Project Zomboid's default admin password.** A new install gets a random
  admin password instead of LinuxGSM's `CHANGE_ME`, and a server still on `CHANGE_ME` shows a
  warning with a **Set a random admin password** button.
- **A note for CS:GO servers about LinuxGSM's App ID switch.** From LinuxGSM v26.3.0 a Game Server
  Login Token made for App ID 730 stops working; the Config tab says so, and how to keep the old
  behaviour, on a server with a token set that runs as another App ID.

- **A Refresh list button for LinuxGSM's game list.** A superadmin can press **Refresh list** on the
  install page to fetch the list straight away instead of waiting for the weekly refresh.
- **New file and New folder in the file browser.** Two buttons beside Upload make an empty file or
  folder where you are, following Rename's naming rules. Nothing existing is replaced, protected
  LinuxGSM names are refused, and every attempt is in the audit log.
- **Rename a file or folder in the file browser.** Every row that can be deleted has a Rename
  (pencil) control; a refused name shows its reason under the field. An existing name is never
  replaced, protected LinuxGSM paths and the live console's logs cannot be renamed, and every
  request is in the audit log.
- **Clean host reboots: running game servers are stopped first and come back after.** Every reboot
  the panel makes now stops running game servers with LinuxGSM's graceful `stop` first, then brings
  back exactly the ones that were running: Autostart servers by LinuxGSM's monitor, the rest by the
  panel (a setting turns that off). A `host_reboot` notification summarises it, and a reboot that
  did not happen is undone and you are told.
- **With players on, the reboot asks.** The dialog lists who is on each server and offers **Wait:
  reboot when everyone has left** or **Reboot now**. A forced reboot warns players in-game where the
  game can show a message, and work a reboot would cut off refuses "now".
- **The wait is visible and bounded.** A pending wait shows on the host's Power card and banner
  with a Cancel button, and gives up after 24 hours (`reboot_wait_max_hours`, 0 for no limit).
- **A terminal in the browser, for the panel's own host and for every remote.** It needs the new
  `use_terminal` permission and host access, and on the panel's own host it is superadmin-only.
  Sessions are audited (never what was typed) and close after 15 minutes idle; on a remote the shell
  runs as the account the panel connects with, often root. On the panel host `sudo` refuses unless
  `PANEL_TERMINAL_SUDO=1 ./install.sh` grants it with a password required (give the account one
  with `sudo passwd lgsmpanel`).
- **The install picker knows which games LinuxGSM caps at an older Ubuntu.** Battlefield 1942,
  Battlefield: Vietnam, BATTALION: Legacy and Onset are greyed out and refused up front when the
  selected host's Ubuntu is newer than they support, instead of failing after a long download.
- **A failed install says why, and offers what you can do about it.** The reason is kept and shown
  above that host's table with **Retry install**, **Edit its config** and **Remove**. Once the
  config is fixed and Update pressed, the server is adopted when its files land.
- **Game servers can be uninstalled from the dashboard.** Every row has Uninstall for anyone allowed
  to, enabled by typing the server's account name, since it deletes the server, its files and
  backups.
- **Install progress is shown where the server is.** The dashboard shows a progress row beneath the
  installing server, and Install a Server says the install carries on if you leave.
- **The update card's list of changes links each commit and PR**, to the repository this checkout
  tracks, so a fork links to the fork.
- **The sidebar footer links to the panel's repository, and its commit SHA to that exact commit**,
  so what is actually deployed is one click away.
- **Console history can have real timestamps, not just lines you watched arrive.** The Live Console
  offers to turn on LinuxGSM's `logtimestamp`, so every line arrives dated, shown in your timezone.
  It takes effect at the server's next start.
- **Each console line now carries the time the panel saw it**, in your own timezone, with a "Times"
  toggle in the Live Console header. Lines loaded from the log when the page opens have no known
  time, so their gutter stays blank.
- **Three remaining timestamps now render in your timezone too** — ban dates, invite expiry and
  Tailscale peer last-seen, which showed UTC with nothing saying so.
- **LinuxGSM's colour now survives into the console.** `[  OK  ]` green, `[ FAIL ]` red,
  `[ INFO ]` blue, and a game's own console colour too; other escape codes are still removed.
- **The installed game version is shown on the server detail page**, from the game's own query
  reply or SteamCMD's build id, with the source in the hover text. A game with neither shows a dash.
- **Download the console log** from the Live Console header — the full LinuxGSM log file. It needs
  the file browser's permission.
- **Line numbers in the file editor.** The editor no longer soft-wraps (long lines scroll
  sideways), and dragging its bottom edge makes it taller.
- **Drag and drop now takes folders, and actually works.** Dropped folders upload with their
  subfolders, and the whole File Browser card is the target, so a near miss no longer navigates the
  tab to the dropped file.
- **An "Upload folder" button**, for when dragging between the desktop and the browser misbehaves
  (common on Wayland).
- **Downloads in the file browser** — on every row of Files & Config and in the editor header. A
  file downloads as-is at any size, and a folder as a `.tar.gz` after asking. Reads happen as the
  game user, never as root.

### Changed

- **Test checks that read what they name.** Several suite checks could pass without exercising the
  code they describe. They now read it, and each one was shown to fail when that code is broken. The
  JS coverage job also runs for a change to the runner it serves the panel under.

- **The files the installer reads now live in `panel/install/`.** `app.py`, `manage.py`,
  `db_maintenance.py`, `recover.sh`, `uninstall.sh`, `VERSION`, `release-signers` and the
  requirements files moved there from the top of the repository. On a per-user install, run
  `./venv/bin/python panel/install/manage.py` and `bash ~/linuxgsm-panel/panel/install/uninstall.sh`.
  `sudo linuxgsm-panel-recover` and the root-owned copies in `/usr/local/lib/linuxgsm-panel/` work as
  before. A panel updates to this release only from the previous one or later.
- **The Maintenance tab names the release you run.** When the panel is up to date, the Update card
  says which release that is, by its date and commit: "You're up to date: release 2026.11.7
  (a1b2c3d)."
- **The Install page draws before its game icons load.** The search box and the game list appear
  sooner on a slow connection.

- **The bots show "typing…" the moment they receive a command, and stop as they answer.** It also
  shows while a command waits behind another, and is cleared before the reply is posted.

- **Less scrolling, on a phone and on a desktop.** Page alerts are one line each, Files & Config
  shows one section at a time, the server page leads with the live console, and long help and lists
  are folded. Nothing was removed.

- **Less scrolling on a host page's Network and Security tabs.** Open and Restrict are one **Add a
  rule** card, and long lists show their first few with **Show all**. A card that cannot load now
  says whether the panel did not answer, answered with an error, or wants you to sign in again.
- **A Network tab on every host page.** The firewall moved from its own page to the host page's new
  **Network** tab, together with the Connection & SSH card. Old links to the Firewall page still
  work.
- **The host page, tidied for a phone.** All five tabs fit a phone screen. **Blocked IPs** moved to
  the **Security** tab beside the fail2ban bans, and the auto-block threshold is now changed only
  beside the Auto-block switch there.

- **Two more CI scanners: zizmor on the workflows, and Harden-Runner in every job but deploy.**
  CI only; nothing on a panel changes.
  - *zizmor* audits the GitHub Actions workflows on every pull request, push to main and weekly.
  - *Harden-Runner* runs in audit mode: no allow-list, but it routes each job's DNS through its own
    proxy, blocks hosts on StepSecurity's global blocklist, and prints what it saw into the job's
    public log. The deploy job does not run it.
- **A reboot request with no mode and players on now answers 409 instead of rebooting.**
  The caller must ask again with `{"mode": "now"}` or `{"mode": "when_empty"}`; an unknown mode is a
  400.
- **Host reboots from a bootstrap or install.sh never reboot a host with game servers on it.** They
  leave the reboot-needed banner and say to reboot from the host's Power card.
- **While a host is being rebooted, actions on its servers wait.** Starts, stops, updates, installs
  and similar actions for that host are refused until the reboot is sent, and the panel holds its
  offline and online alerts for what it took down. Afterwards it alerts if a server it reported as
  running is still down.
- The panel host's helper now runs LinuxGSM as `./<script>` from the game home instead of by its
  absolute path, so LinuxGSM's own monitor can see a start or stop the panel is running there and
  backs off instead of starting a second copy.
- **The panel makes far fewer privileged calls, so the host's journal stops being mostly its sudo
  lines.** Background checks skip work they did not need, modelled at about 9 calls a minute down
  to 2 for three servers. On a host without daily restart, a restart banner from a crontab the panel
  does not manage can now appear up to 10 minutes late.
- **A console tab left in the background stops costing the host a privileged read every two
  seconds.** After 30 seconds hidden it leaves the live console; coming back fills in what was
  written meanwhile (up to 2,000 lines) and says where output is missing.
- **The debug report says what is wrong, covers far more of the panel, and is safer to post.** It
  opens with **At a glance**, every problem found with failures first, and covers many more areas.
  Names, addresses and paths are replaced with tokens, and it asks you to review it before posting.
  - The panel host's Security card says "Could not read fail2ban on this host" instead of "no
    jails".
  - Generating the report no longer freezes the whole panel.
  - A new **Host credentials** check says whether stored credentials decrypt.
- **The version is now the date of the commit the panel runs.** It reads like `2026.9.26` (the
  commit's UTC date), always beside the short commit, and comes from git; the hand-kept 0.x numbers
  stop at 0.10.0-alpha. The one update that brings this in shows as `v$Format:%ct$`.
- **Deleting a host says what stays on it.** The confirmation now says gamedig and its weekly root
  cron stay on the host. README's "Removing a host" section gives the commands to remove them, and
  when not to.
- **`LICENSE` is the plain MIT text**, so GitHub and OpenSSF Scorecard detect it as MIT. The terms
  are unchanged; the extra notice is in the README's disclaimer.
- **Imported game servers get Autostart turned on, as a fresh install already does.** So an imported
  server comes back after a host reboot. Only for games with `monitor` on an account the helper
  enrolled; it never starts a stopped server, and servers already in the panel are not changed.
- **The installer refuses a Python older than 3.10 by name** before apt runs, instead of failing
  inside pip with "No matching distribution found".
- **A queued restart that LinuxGSM finishes with a non-zero exit is cleared after one attempt**, and
  audited with its exit line, instead of retried up to three times. A restart that got no answer is
  still retried.
- **A panel bound to a public address with Tailscale Serve set up keeps serving its own HTTPS**, and
  Serve is pointed at it with `https+insecure`. Loopback and unset binds are unchanged.
- **The update card answers one question: is there something to install?** It shows only "Update
  available" or "You're up to date". An update is offered only when the newest commit that passed CI
  changes a file the panel runs; docs, CI, test or tooling commits arrive with the next real update.
- **The 2FA reset in Users → Edit is always visible**, disabled with a reason when the account has
  no 2FA to reset. It used to be hidden unless 2FA was on.
- **Backup retention is typed, not picked from a list.** All three retention settings are number
  fields; empty a per-server box to use the default. The limits (1-30 backups, 1-365 days) are
  unchanged, and an out-of-range value now says what was kept: "Saved — 100 is out of range,
  kept 30".
- **The pure helper layer moved out of `app.py`** into `panel/core/`. No route or behaviour changed.
- **The application modules now live in a `panel/` package.** Nothing a user sees changes. `app.py`,
  `manage.py` and `db_maintenance.py` stay at the root, where the systemd unit, `recover.sh` and the
  installer address them by path.
- **LinuxGSM's data files are no longer committed here.** The game list and each game's apt packages
  are fetched from LinuxGSM and cached under `data/` (refreshed weekly), so new games appear without
  a panel release. A failed refresh keeps the last copy; with none, the install page offers Retry.
- **Uploads are roughly an order of magnitude faster**, most of all for folders of many small files:
  a small file takes one SSH round trip instead of three, and up to four upload at once. A failure
  part-way no longer leaves a half-written file where the original was.
- **`ssh_manager`'s shell quoting is now `shlex.quote`** rather than a hand-rolled version. The two
  are equivalent, so no command changes.

### Fixed

- **A Minecraft world reset reads LinuxGSM's start settings the way LinuxGSM does.** A reset refuses
  start parameters that use shell quoting, a setting written twice, or other forms LinuxGSM would
  read differently from the panel, so it can no longer delete a folder the server is not using.

- **A scheduled Stop on the panel's own host no longer pages "went offline unexpectedly".** The
  monitor now reads LinuxGSM's monitoring lock as the game account there, so a stop LinuxGSM made is
  recognised. A crash still pages.

- **The debug report counts servers held back from a manual full backup.** Servers a scheduled wipe
  or a queued stop or restart held are counted, so a run where every server was held no longer reads
  "0 backed up, 0 failed, 0 skipped".

- **A port saved during a restart is followed.** When a second game port was saved while a Start or
  Restart ran, the panel kept watching the old port. It now watches the port the restart used, and
  the newer port takes effect at the next restart.

- **A change that worked no longer reports "request failed".** A Minecraft list change, a Workshop
  save, a plugin install or change, a config form save or a new Project Zomboid admin password could
  be reported as failed when only its audit log entry could not be written. The reply now says the
  change was made and that the log entry is missing.

- **Chart legends follow the panel's language.** The live CPU chart on a server's page is
  translated, and History charts switch language at their next refresh.

- **Backup codes and port ranges can be typed on a phone.** The account page's code fields and the
  firewall's Block field no longer open a digits-only keypad.

- **"Installing" and "Configuring" are translated.** A server's status while it installs now reads
  in French and Spanish like its other states.

- **SSH port move keeps the panel connected.** On a host where a firewall rule for one interface or
  source may block the new port and the panel's own connection could not be read, the move now stops
  instead of going ahead and losing the panel's access.

- **Host network traffic counts each byte once.** The host page's traffic chart and history no
  longer add bonds, bridges, VLANs, VM taps and VPN tunnels on top of the network card they run
  over.

- **A Start, Stop, Restart or update that fails because the host can't be reached is in the audit
  log.** On a host reached over direct SSH, a background action whose connection failed left no
  outcome row. It is now recorded as failed with the reason, as on Tailscale and local hosts.

- **"Back up game servers now" names servers a scheduled wipe was holding.** A server skipped
  because its scheduled wipe or a queued stop or restart was running is no longer reported as
  "skipped (players online)". In "disconnect players" mode it is queued to back up afterwards.

- **Switching back to main respects required update stops.** The switch now installs, and names, the
  release no update may skip, as the installer does. While that release isn't signed or verified
  yet, the switch is refused and nothing is changed.

- **The debug report explains a required update stop.** The Updates section shows when the offered
  version is a required stop and which release follows it, or which stop is holding the update and
  why.

- **An interrupted uninstall can be finished with the same command.** The root-owned copy of the
  uninstaller is now removed last, so `sudo bash /usr/local/lib/linuxgsm-panel/uninstall.sh` is
  still there to run again if the uninstall stops part-way.

- **Project Zomboid Mod IDs with brackets or quotes save.** The Workshop card refused real Mod IDs
  such as `Arsenal(26)GunFighter[MAIN MOD 2.0]`, and one in the server's list made every save fail.
  Only what would break the Mods= line (`;`, `=` and line breaks) is refused now.

- **A port saved while a server ran moves only after a restart that happened.** A restart LinuxGSM
  postponed for players, or one that failed, no longer leaves the panel watching a port the running
  game does not use. A port saved while a start is under way waits for the next start. A new install
  is also no longer given that saved port.

- **A scheduled Stop no longer pages "Server offline".** A server stopped by LinuxGSM's own stop (a
  Schedule tab Stop with player warnings, a cron line) is recorded as stopped without an alert. A
  crash still alerts.

- **Game config form: long or unusual files and number-looking fields.** The form reads any config
  in linear time, a file that is not UTF-8 opens in the raw editor only so a save cannot damage it,
  and a field that holds digits (a seed, a password) accepts text.

- **Start anyway from the command palette, and translated chart legends.** A palette Start refused
  for a busy port now offers Start anyway; the history charts' CPU, RAM, Disk and Players legends
  follow the page language; the Remove plugin dialog shows its icon.

- **Saving a scheduled wipe no longer cancels the wipe that is waiting.** Unticking "wait until the
  server is empty" to force a wipe that was waiting for players now runs it on the next check.
  Rescheduling or turning off a waiting wipe is recorded in the audit log.

- **A dropped connection during a scheduled wipe no longer repeats the wipe.** If the link to a host
  drops while LinuxGSM is wiping, the panel stops and alerts you to check the server. It no longer
  runs the wipe again every 5 minutes.

- **A wipe whose server needed a forced stop is no longer reported as failed.** When a Rust server
  ignores the normal quit and LinuxGSM has to force it to stop, a wipe that completed is now
  recorded as done.

- **Clean reboots wait for LinuxGSM wipes and mod installs.** A wipe, mods install or removal,
  FastDL build or similar command started outside the panel (cron or the terminal) now blocks a
  reboot instead of being cut off. A cron wipe is no longer reported as a crash.

- **Overdue-backup alerts are sent when LinuxGSM's alert settings were never filled in.** A LinuxGSM
  alert channel switched on but left at its default address (for example `email@example.com`) no
  longer stops the panel from sending its own alert.

- **Nothing else runs on a server during its scheduled wipe.** Backups, queued restarts and stops,
  the server page's actions, chat bot commands, mod installs and "Run now" wait or are refused while
  a scheduled wipe runs. The wipe waits for any of them that is already running.

- **SSH port move reads public SSH past LAN-address rules.** A firewall rule for one LAN or
  Tailscale address listed above the public SSH rule no longer makes public SSH look off, which
  refused the move.

- **SSH port move stops when the panel's own connection can't be read.** On a host where SSH is
  public over only one of IPv4/IPv6 and the panel could not read its own connection, the move now
  stops instead of opening only one family and cutting the panel off.

- **The console keeps the server's last lines across a restart's re-read.** When the console re-read
  its log just before a restart started a new one, the game's final lines could vanish from the
  page. They now stay, once, before the new log.

- **The console says when the start of a new log is not shown.** After a restart, lines kept from
  the previous log could sit directly above the end of the new one as if nothing were between them.
  A notice now marks the missing part.

- **Scheduled Tasks no longer fails on a malformed cron log line.** One odd line in the host's cron
  journal could stop the Scheduled Tasks card from loading.

- **A server's description can no longer change its online status.** A description containing words
  like "status: stopped" could make a running server show as offline.

- **The command palette finds sections and actions in Spanish and French.** Typing the words shown
  on a translated page now finds them; the English words still work.

- **Re-running the uninstaller after it stopped part-way finishes the job.** It no longer says there
  is nothing to remove while the panel's account, sudo grants or system files are still on the host.

- **Updating by hand no longer moves a panel on another branch back to main behind its back.** The
  installer stops first and shows the command to update that branch, or tells you to switch the
  panel back to main.

- **Diagnostics no longer reports the event-loop watch as "never completed a pass" in its first
  second.**

- **The console no longer starts every line a quarter of the way across a phone screen.** The
  column for line times takes no space until a line with a time is on screen, and on phones it is
  narrower when it does.

- **A wipe whose server fails to start afterwards counts as done.** LinuxGSM exits with an error
  when the restart after a wipe fails, so the wipe was recorded as not run and alerted, although the
  files were gone. "Wipe not required" also no longer leaves a crash unalerted for a few minutes.

- **Firewall changes on a host saved by name check what the name resolves to.** A host with an IPv6
  address but no IPv6 DNS record was refused "Default incoming: deny" and "Enable firewall" with "No
  rule lets SSH in", although an IPv4 SSH rule let the panel in.

- **Blocking an address from the panel host works in more setups.** Blocks are no longer refused on
  a host with IPv6 switched off, or from a browser reaching the panel through a reverse proxy on the
  host itself with `trust_proxy` on.

- **The console keeps old-log lines that arrive while it re-reads the log.** Lines that landed
  during a re-read after Clear, or during Load older, were wiped when the log rotated; a command
  sent after Load older also kept its echo across a Restart.

- **FastDL no longer guesses when it cannot read the LinuxGSM version.** If the version read failed,
  FastDL answered LinuxGSM v26.5.0's "Rebuild from scratch?" with yes, which deletes everything in
  the FastDL folder. It now refuses to run and says why.

- **Scheduled wipes follow cron's day rules, and turning one off stops it.** A custom schedule such
  as `*/2` in a day field now picks the same days cron does. Turning a wipe off or changing it while
  its pre-wipe backup runs now stops that wipe, and a running wipe counts as busy for reboots and
  restarts.

- **A host reboot is no longer undone by an update on a stopped server.** LinuxGSM maintenance
  running on a server the reboot does not stop now refuses the reboot up front, instead of the
  reboot stopping every server, waiting out its time limit and rolling back.

- **Switching the panel to another branch needs a signed release on it.** Since updates install only
  signed releases, a switch to a branch whose newest commit is not one is refused before anything is
  saved, so the panel no longer ends up following a branch it is not on.

- **More firewall changes refuse to cut the panel off.** Deleting a remote's only Tailscale rule, a
  default deny on a host the panel reaches by name with SSH open in only one address family,
  "Disable public SSH" on a Tailscale connection to a port other than 22, and a panel port move
  whose new port could not be opened are now refused.

- **The console keeps your commands and their output after Clear and Restart.** After Clear, a
  command you sent and the output before a Restart vanished when the console next re-read the log;
  Load older lost lines the same way. Both now keep every line.

- **Console history is kept per account and cleared when you sign out.** Command history was stored
  in the browser per server only, so another account on the same browser could see it.

- **The Mods tab says when a game has no mods.** It used to show "Loading mods…" for ever.

- **The Install page asks for only the game icons you can see.** It used to request the icons for
  nearly every game at once, and on a panel that had not saved them yet each one was fetched from
  linuxgsm.com in turn, so the page kept loading for many seconds. The icons for the tiles in view
  load first, and the rest load as you scroll or search the list.

- **An update is no longer held back by a failed Dependabot run on GitHub.** GitHub's own
  dependency-update job failing on the newest commit no longer stops the panel offering it.

- **Maintenance → details shows all of its output, not the first 600 characters.** LinuxGSM's
  `details` prints passwords unmasked, so they show only to users with Manage Servers; anyone else
  sees passwords and tokens as `********`. The audit log's copy is always masked.

- **The Telegram bot no longer goes quiet for half a minute at a time.** Where the IPv6 route to
  Telegram drops some connections, each address now gets 4 seconds to connect before the next is
  tried, instead of 30. Discord's live connection is unchanged.

- **A command the panel feeds input to can no longer hang the panel.** A program that exited without
  reading its input (the SSH key signature check, a write through the helper) could leave the panel
  spinning a CPU core at 100%.

- **LinuxGSM v26.5.0 compatibility.** On servers running LinuxGSM v26.5.0 or newer:
  - FastDL runs incrementally (the panel answers "Rebuild from scratch?" No), keeping files
    LinuxGSM did not write.
  - An update started while another runs is reported as "not run: an update is already running".
  - Backups are confirmed from LinuxGSM's script log when its "Completed:" line is missing.
  - New games get the right default install port (OpenRA: Red Alert, Luanti, FiveM, Battlefront
    Eternal); FiveM needs your own Cfx.re licence key. Half-Life and Counter-Strike WON2 get the
    in-game stop warning and no Update button.
  - Action Half-Life installs from before v26.5.0 are told to run force-update once, to move to the
    steam_legacy branch.

  On every LinuxGSM version:
  - Commands a LinuxGSM update adds (QuakeWorld's Update, for example) appear after update-lgsm
    and get their scheduled task.
  - Player counts work for games LinuxGSM queries with gamedig only (querymode 3: FiveM, SA-MP, MTA
    and others).
- **The Telegram bot no longer goes quiet for up to a minute after a dropped connection.** After a
  failed check it now checks again at once, notices a dead connection after 30 seconds, and only
  backs off (up to 15 seconds) while failures keep repeating.
- **Deleting a remote's SSH rule could cut the panel off from it.** The rule the panel's own
  connection gets in by is now protected, naming that address; if the address cannot be read, every
  SSH rule is kept.
- **Call of Duty, CoD 2, CoD: United Offensive and MoH: Allied Assault install on Ubuntu 26.04
  again.** The panel now refuses only what LinuxGSM refuses: BATTALION: Legacy and Onset above
  Ubuntu 20.04 or Debian 11 (greyed out for Debian 12 hosts too).
- **Players can join a new Satisfactory server behind the panel's firewall.** Install and "Open all
  ports" now also open the other player ports LinuxGSM lists (Satisfactory's 8888/tcp, and ports for
  ARK, Conan Exiles, Mordhau, The Isle, TeamSpeak 3 and MTA). MTA's download port also serves its
  web admin, so give MTA's admin accounts strong passwords.
- **LinuxGSM's monitor no longer restarts a server in the middle of the panel's nightly update.**
  This affected LinuxGSM before v26.4.0. The panel's cron lines now use a form every LinuxGSM
  version recognises; existing lines change over on their own, keeping their last run and result.
- **Valheim backups no longer disconnect players every hour.** A running crossplay Valheim server
  (LinuxGSM's default) cannot report players, so it skips its scheduled backup and says how to fix
  that. After a whole interval past due it is backed up anyway and says so; "wait until empty"
  backups do the same.
- **Existing Post Scriptum and SCP: Secret Laboratory ServerMod servers can be imported.** They are
  listed as retired with their replacement, and no longer get a weekly `update-lgsm` that can only
  fail.
- **New LinuxGSM games get the right default port.** Hytale, RuneScape: Dragonwilds, Conan Exiles,
  Soulmask, HumanitZ, Jedi Academy and 26 other games were offered 27015 and now get LinuxGSM's own
  default. Jedi Academy also gets the Players card's Kick and Say.
- **The Autostart switch reads a monitor line written by hand.** Forms such as `cd /home/<user>;
  ./<script> monitor` or LinuxGSM's short `m` now count as Autostart, and switching it off removes
  them.
- **LinuxGSM's short command names count as maintenance.** An update started as `./server u` (or
  `fu`, `b`, `v`, …) no longer reads as an unexpected outage, and a host reboot waits for it. A
  `start` failing with LinuxGSM's generic error is no longer reported as "already running".

- **A twenty-third full review on 2026-10-22: fixes.**
  - Adding a host, or moving a row, onto an address and SSH port another row already has is
    refused; existing rows naming the same machine are left as they are.
  - An SSH port move's undo retries steps the host did not confirm and names any still unconfirmed,
    with console commands to run if SSH may not be listening on any port.
  - A clean reboot can no longer overlap other changes to its host, and an SSH port move and
    Prepare & Secure no longer overlap.
  - Remote Servers keeps a host's last figures, marked stale, when a stats read fails.
  - NodeSource's signing key is written inside a private temporary folder, never a predictable
    path.

- **A twenty-second full review on 2026-10-22: fixes.**
  - Once sshd answers on the new port, nothing undoes an SSH port move; a later failure could undo
    it and lock you out. A move that cannot snapshot the current setting changes nothing.
  - An SSH port move refuses only over an unfinished earlier move, and names the files to fix.
  - The console no longer shows an update's lines twice.
  - A failed OpenSSF Scorecard run no longer holds back panel updates.
  - An uninstall and a clean reboot of its host no longer overlap.

- **A twenty-first full review on 2026-10-22: fixes.**
  - Undoing a failed SSH port move no longer deletes the SSH setting it just put back, which could
    lock you out.
  - After a port move, the Public SSH card's Limit and Allow no longer re-open a port you closed.
  - Full upgrades in host setup and the installer also keep a package apt would downgrade.
  - The login-attempt jail written at startup matches the one a whitelist edit writes.
  - Saving or uploading a file refuses a name where the console's log folders will go.

- **Installing OS updates no longer stops on a package apt would downgrade.** Where apt pinning
  prefers an older version, the panel keeps that package at its installed version for that run only,
  installs every real update and names the kept packages in the log. Panel host and remotes.

- **A twentieth full review on 2026-10-17: fixes.**
  - The Public SSH card follows the SSH ports sshd really serves after a port move, and its buttons
    act on all of them; every lock-out guard stays.
  - While a panel port change waits for its restart, everything meaning "now" uses the port the
    panel really serves.
  - The downloadable debug report no longer tells how the panel is privileged.
  - An SSH port move that loses its connection halfway is undone.
  - A previous OS update's leftovers no longer read as "Updates installed."
- **A nineteenth full review on 2026-10-17: fixes.**
  - The file browser refuses to delete a running game server's console log (or the folders above
    it), which silenced the live console until the next restart.
  - A panel-host reboot that cannot first stop the game servers is refused, not done anyway.
  - An upgrade someone started over SSH is reported as another update to wait for, not "watched".
  - An unreadable LinuxGSM config is never shown or saved as empty.
  - The downloadable debug report no longer says the panel runs as root or lists its groups.

- **An eighteenth full review on 2026-10-17: fixes.**
  - Changing a remote host's SSH port on stock Ubuntu 24.04 or 26.04 works.
  - A panel port change whose restart could not be scheduled puts the old port back in the
    firewall and the login-attempt jail.
  - Installing updates twice no longer starts a second upgrade.
  - Removing a hand-edited address from the security whitelist removes it.
  - The installer never stops at a hidden prompt, and the downloadable debug report no longer
    describes the panel's privileges.
- **A seventeenth full review on 2026-10-17: fixes.**
  - A game server's account can no longer stall the server scan: its installed-mods list is read
    only as an ordinary file of bounded size.
  - Garry's Mod content: when a host did not answer, the card, Remove and Apply now say it could
    not be read instead of treating it as "no content".
  - OS updates started through the older API routes run as the same background job as the OS
    Updates card; repairing the database is refused during a panel update or backup restore.
  - Every invite link that still works is listed and can be revoked; no new ones are made while
    100 still work.
  - The downloadable debug report no longer says whether passwordless sudo makes the panel root.
  - A leftover backup lock no longer stops pruning; a download of unreadable size no longer saves
    an empty file.
  - Smaller fixes to the Backups and Live cards, the Raw config editor, the host forms' credential
    box and `manage.py setup-token` behind a proxy; the weekly gamedig check no longer runs as root.

- **A sixteenth full review on 2026-10-16: fixes.**
  - Garry's Mod content never uses a panel-managed game server's account (Remove could delete that
    server's files); the panel's own content account is used. A host already mounting from such an
    account is left as it is, and Remove refuses and names the server.
  - Moving SSH back to port 22 opens it in the firewall again and checks the rule is there.
  - Turning public SSH off, or Close port 22, refuses a host the panel itself reaches on public
    port 22; move it to Tailscale SSH or its Tailscale address first.
  - A backup is no longer pruned while another backup is still being written.
  - The SSH port card shows the port sshd really listens on, for every host.
  - Smaller fixes to the console's audit warning, scheduled-task editing, the maintenance check on
    hosts needing a sudo password, the installer and uninstall.

- **OS updates respect Ubuntu's phased rollout.** Updates apt would not install yet are no longer
  forced in on remote hosts; they are listed separately on the OS Updates card and left out of the
  count and banner. The check no longer runs when the panel host's page loads.

- **A fifteenth full review on 2026-10-16: fixes.**
  - The Raw config editor can no longer blank a server's config after a failed re-read.
  - Moving SSH twice on a Tailscale-SSH host no longer drops the first move's port.
  - Update snapshots are pruned on per-user installs whose panel folder is a link; before, disk use
    only grew.
  - Smaller fixes to the panel port, UFW rules when moving SSH, Serve, the install page, a stale
    reboot banner and audit rows.
- **A fourteenth full review on 2026-10-16: fixes.**
  - Moving SSH on a Tailscale-SSH host is refused instead of losing the host.
  - Close Port and Unblock no longer say "closed" when nothing was removed, and a v4 rule beside a
    v6-only LIMIT no longer turns that LIMIT into a plain allow.
  - Errors no longer read as "nothing there" on a dozen pages (file lists, backups, logs and more).
  - Removing a server made on an existing account leaves that account alone; config saves keep the
    live console log intact.
- **A thirteenth full review on 2026-10-16: fixes.**
  - Close Port 22 really closes it: it removes every public rule for 22 (IPv4 and IPv6) and checks
    the firewall afterwards; before, a rate-limit rule kept 22 open.
  - Unblock no longer says "Unblocked" when another rule still blocks the address.
  - A host with Tailscale installed but stopped no longer aborts a fresh install.
  - An update that failed while writing new code restores the old code before restarting.
  - The root helper refuses a restore whose data folder was swapped for a link, and refuses to
    remove an account whose home is not its own.
- **A twelfth full review on 2026-10-15: fixes.** Its one high finding shipped on its own; see
  Security.
  - The update's snapshot clean-up refuses a linked `data/.backups`, so root can no longer be made
    to delete folders elsewhere.
  - IPv4 and IPv6 firewall rules are read separately: an IPv6 allow above the limit no longer reads
    as "rate limited".
  - The OS-updates banner shows again for delegated admins on the hosts they manage.
  - A host that is down or has a changed key says so instead of "Internal server error"; bracketed
    IPv6 addresses work in the setup wizard and Tailscale ping.
- **An eleventh full review on 2026-10-15: fixes.**
  - A remote whose SSH key changed shows its firewall as "Unknown", with the reason, not "Inactive".
  - "Rate limit" checks which rule really matches first, instead of claiming success when an
    earlier rule already opened the port.
  - A host saved as `[fd7a:…]` connects; other spellings of one address are read as one address.
  - On a host whose /home is a link, the file browser and config lookup work.
  - Delegated admins no longer see the panel host's update count, reboot state or pending packages,
    and two remote read pages now check the host permission.
- **A tenth full review on 2026-10-15: fixes.**
  - On a German or Dutch host with UFW on, a fresh install no longer reads the firewall as off and
    skips opening the panel's port; command output is read in English.
  - A remote stored by its tailnet IPv6 address is reachable again.
  - On a host whose sudoers checker is sudo-rs 0.2.2, the installer keeps the panel's sudo grant
    without the one line that version does not understand, instead of deleting it all.
  - A changed host key and a cut-off command are named for what they are.

- **A ninth full review on 2026-10-13: fixes.**
  - On a non-English host, memory, OS-update versions and an install's account switch read
    correctly.
  - Changing the firewall on an unreachable host says the host is unreachable.
  - Error pages, "❌" validation messages and page-written text follow the viewer's language.
  - A kick by name keeps the player's full name; an expired certificate no longer reads
    "0 day(s)"; a hand-edited port that is not a number no longer breaks a page.

- **An eighth full review on 2026-10-12: fixes.**
  - A ban by name on a Valve (Source/GoldSrc) server could reach a different player; fixed. Quake
    Live still gets no kick or ban.
  - A package installed for two architectures lists each row with its architecture.
  - More messages follow the viewer's language; IPv6 hosts are bracketed in login lines, connect
    addresses and links.
  - Several checks no longer read a failed command as a clean answer.

- **A seventh full review on 2026-10-12: fixes.**
  - The GMod Content card shows how an install or uninstall ended, failures included.
  - The console refuses a line holding a control character (a pasted Ctrl-C or Ctrl-Z), which
    interrupted or suspended the server.
  - Several pages fit a 375-pixel phone, and more text is translated for Spanish and French.
  - Optimise database no longer says "Optimized" when it was put off; after a reboot is called
    off, a server is not given up on while its host is silent or a LinuxGSM update holds its start.

- **Phones (375 px wide).** Pop-up messages, tables, long names and French labels now fit the
  screen with delete buttons in reach. Desktop pages are unchanged except the Open-a-port card.

- **A sixth full review on 2026-10-12: fixes.**
  - "Restore anyway" on a panel backup restore appears for Spanish and French viewers too.
  - Daily restart (when empty) uses the query type set on a server's page; such servers were
    restarted every day with players on.
  - Console lines are always typed as text, so `;` endings or `C-c` reach the game as written.
  - About 330 more messages are translated for Spanish and French.
  - Signing everyone out also clears their sessions from the session list.

- **A fifth full review on 2026-10-12: fixes.**
  - Console: panel lines after Clear no longer vanish, and commands starting with `-` are typed in.
  - CoD4X and Jedi Knight II servers show who is online; five more Valve games get the player
    tools. Ban is offered only where the console can ban by slot (Quake III, Enemy Territory and
    ET: Legacy now refuse it). Vampire Slayer and Vintage Story get their own default ports.
  - Close public panel port says why it cannot act when UFW is off or allows everything.
  - About 300 more messages are translated; resetting a user's password signs out their other
    sessions.

- **A fourth full review on 2026-10-12: fixes.**
  - Quake III and Return to Castle Wolfenstein servers show who is online; Quake III 1.32 and
    Enemy Territory no longer drop players with spaces in their names.
  - A rule opening the panel's port in a list or range is protected, and Close port refuses a rule
    shared with other ports.
  - More whole sentences are translated; the audit page escapes characters it cannot show.
- **A third full review on 2026-10-11: fixes.**
  - A scheduled backup keeps a whole archive despite LinuxGSM 26.3.0's spurious FAIL line, shown as
    a warning; only an empty or cut-off archive is removed.
  - Ten more switches accept only a real true or false, not the text `"false"`.
  - A Discord channel id or Telegram chat id entered as a number no longer stops the bots.
  - The player list no longer shows a stale status table; more page text is translated.
- **A second full review on 2026-10-11, rerun after the first one's fixes: fixes.**
  - A switch sent as the text `"false"` no longer counts as on: during VPS setup,
    `"reboot": "false"` rebooted the host. A backup passphrase sent as `null`, `false` or `0` no
    longer turns encryption off.
  - Saving the Alerts card no longer copies values from `secrets-*.cfg` into the plain instance
    config.
  - A staged Ubuntu rollout no longer limits the game list to the older release.
  - The players dialog and 147 more strings are translated for Spanish and French.
- **Findings from a full code review including the tests and CI (2026-10-11): fixes.**
  - Config reads include LinuxGSM's secrets files, and a save they would override is refused with
    that file's name. A remote GMod install mounts the games that did download.
  - Another server's `update` on the same account no longer mutes this server's offline alerts.
  - "Reboot when everyone has left" no longer loops when it cannot read a player count.
  - VPS setup names each failed step instead of saying "complete".
  - A backup restore and a self-update refuse to overlap; branch switching is refused during an
    update.
  - `manage.py` no longer starts the panel's background jobs beside the running service, and
    `create-admin` applies the web forms' name rules.
  - Adding a host as "Existing server — just scan" no longer shows a false error (Add again made a
    duplicate).

- **The Tailscale page no longer shows "12/31/1" as the last-seen time of every connected
  device.** Connected devices show a dash; offline ones keep their real last-seen time.
- **A game server the panel starts on its own host now writes its files group-writable again (664),
  as it does when LinuxGSM's cron or a login starts it.** The panel now uses the account's own
  session umask instead of the service's 0022. Remote hosts already did.
- **"Reboot now" no longer misses a LinuxGSM action that a newer one on the same server displaced.**
  Every action still running is counted, so a reboot no longer stops a server under an older
  update or validate.
- **The live console no longer shows a few lines twice when a server's page opens**, and no longer
  drops lines written while it loaded.
- **A backup that LinuxGSM reports as finished is "Backed up" only when its archive reads whole.**
  Otherwise it is "not confirmed" and every old backup is kept. A failed run's partial archive is
  removed only when it is certainly that run's and the run has ended.
- **The file browser's editor, the Config card's Raw tab and uploads refuse a LinuxGSM config that
  turns `logtimestamp` on**, which freezes the live console.
- **Findings from a full code review (2026-10-08): fixes.**
  - Batched player polls count people, not bots or reserved slots (a Bedrock server sent false
    "server emptied" alerts); a failed backup no longer deletes a good one; actions skip servers
    still installing.
  - After a dropped connection the console catches up from its place instead of repeating 250
    lines.
  - Symlinked folders (LinuxGSM's `log/server`, a moved `serverfiles`) open as folders; the Config
    form no longer offers `logtimestamp`.
  - The firewall lockout guard protects the port sshd really listens on; a bad timezone or
    over-long account name is refused before host setup starts.
  - Renaming the "Everyone" group no longer creates a second default group with console access.
  - The uninstaller removes a rate-limited (`LIMIT`) panel port rule and names the NodeSource
    repository it leaves in place.

- **The file browser fits a phone inside a folder with a long name, and its path shows a name's
  spaces.** Long folder names no longer push the page sideways; the upload buttons move to their
  own row on narrow screens, and each path folder is an easier tap target.
- **An imported server is stored on the port it really uses, read on its host.** 46 of LinuxGSM's
  140 games keep their port in the game's own config, so for those the import stored 27015, which
  can be another server's (on the test host, crashes went unpaged and player counts asked the
  wrong server).
  - Discovery reads LinuxGSM's config files in its own order, secrets included, as regular files
    of bounded size.
  - The import stores the port its own scan (or LinuxGSM's `details`) read; a server whose port
    cannot be read is not imported, with the reason. The host's SSH or panel port is refused.
  - A server on the same port as another on its host is still imported, with a note that they
    cannot run at once unless one uses only TCP and the other only UDP, or each has its own IP.
  - Servers imported before this have their port re-read a minute after each panel start and
    stored where it differs and the new port is free or the old one is certainly not the
    server's (audited as `port_resync`); otherwise it keeps its port until the next start. No
    firewall rule is opened: "Open all ports" does that.
  - An install re-reads the port after the first start and says when it could not confirm it.
- **The file browser lists every file under its real name, including one whose name ends in a
  space or holds a line break.** Before, Rename, Delete or Edit on such a row could act on a
  different file, such as the real `server.cfg`.
- **Bootstrap and install.sh rebooted hosts with game servers running.** Their check missed tmux's
  renamed server process; both now find running servers, and bootstrap also counts any server the
  panel last saw online.
- **The Power card said "Autostart servers come back on their own"** and the reboot banner's
  "Reboot now" skipped the player check the Power card made. Both open the same dialog now.
- **Every Stop from the panel paged "went offline unexpectedly" about four and a half minutes
  later** (since #346, on by default). A Stop from the panel, queued ones included, is now recorded
  as down at once with no alert. A Restart still pages if the server is down, or crashed again,
  when its three minutes are up.
- **An update's output no longer appears twice in the live console.**
- **An update that ran with no console open keeps its result.** Opening the console afterwards shows
  how it ended; a line notes any earlier lines left out and names the file on the host that holds
  them all.
- **Player counts work for Counter-Strike 1.6 and 2, TF2, HL2:DM, Left 4 Dead 2, Call of Duty 4
  and Minecraft Bedrock.** They now use gamedig 5's game names, so restart-when-empty can see these
  servers empty. Existing restart-check lines are rewritten by the daily cron upgrade.
- **A server whose query lists no player names is no longer counted as empty with people on it.**
  Counts now use the server's own player number, less bots, when that is larger than the name list,
  so restart-when-empty and queued stops no longer run with people on. Existing restart-check lines
  are rewritten by the daily cron upgrade.
- **Autostart shows what the server's crontab really has after an install.** It read On even when
  the install failed to write the monitor cron line; a server whose install never finished is set
  Off once by the upgrade.
- **The panel is published over Tailscale Serve at one address, and a leftover route to it no
  longer answers 502.** At each start the panel removes its own extra routes at other mounts on
  :443. Other apps' routes are left alone, and nothing is removed when Serve cannot be read.
- **The setup wizard no longer publishes the panel twice.** It now adopts a route that already
  reaches the panel, and no longer publishes at "/" over another app's route.
- **The Tailscale page can remove a leftover route on its own.** Each route to the panel it does not
  manage gets a Remove button, and Disable now removes every route to the panel.
- **The startup log, the setup-complete page and Recommended Access name the panel's own
  address.** They now give the route at the configured mount, and only while it works.
- **The debug report names a leftover Serve route and how to remove it.** Each one is listed with
  the exact `sudo tailscale serve --https=<port> --set-path=<mount> off` that removes it.
- **Uninstalling removes the panel's Tailscale Serve route.** It removes every route to the panel's
  port, and only those, and says what it could not.
- **An update says "this panel now serves HTTPS" only when that is new.** It gives the Serve address
  when there is one, and the public address only when the firewall does not close the port.
- **The README no longer gives a `tailscale serve` command to copy.** That command answered 502 on a
  panel serving its default HTTPS; use the wizard or the Tailscale page.
- **The debug report's journal sections cover the panel's own output, not its sudo calls.** It reads
  the panel's own lines over the last 24 hours and counts the last hour's sudo calls by what they
  did. A system install needs an updated helper for this.
- **A privileged command the panel gives up on no longer keeps running as root.** On a timeout the
  panel now sends SIGTERM, which sudo passes on, before SIGKILL, and the helper ends a read; a call
  that changes the host still runs to its end. An update installs the new helper.
- **Call of Duty servers show the capacity the game reports.** It showed the LinuxGSM config's
  number instead.
- **A running game the panel cannot query no longer runs LinuxGSM `details` every 45 seconds.**
  While the monitor sees it listening, its player count shows "unknown" without asking.
- **The debug report no longer calls a systemd unit an email address.** Names like
  `user@1000.service` and `package@1.2.3` are kept; addresses are still replaced.
- **The debug report's installer lines keep their paths and the commit they name.** Paths print
  shortened (`<data>/…`) instead of `/[redacted]`, and the commit as its first 12 characters.
- **The debug report's Privacy footer counts everything it replaced.** A new "Redacted" line counts
  emails, tokens, secrets and other replaced strings.
- **The debug report pseudonymises an account written before an address.** In `name@<address>` the
  account printed in clear; it is now an [account-N] token.
- **The debug report no longer says a self-update that completed DIED.** When install.sh's own
  ending is in the log with no error after it, the report gives that outcome.
- **The debug report prints Tailscale's health messages, not only how many there are.** Names,
  addresses, domains and certificate issuers are replaced as elsewhere in the report.
- **The debug report says "node key expiry disabled" for a node whose key does not expire.** It said
  "not recorded".
- **The debug report's update lines say what was actually checked.** It says when CI was not
  consulted, labels unverified commits as such, and prints "none" instead of `?`.
- **The debug report no longer says a background job never ran when it is not due yet.** It says
  when the first run is due.
- **With `trust_proxy` off, forwarded headers from a local account other than root are logged and
  counted.** They were already refused, but the debug report always said "none".
- **The Backups page and the debug report no longer read the "Back up game servers now" button's
  last run as the automatic schedule's.** The schedule's row now shows the newest automatic backup
  from the audit log, and the button's last run sits under the button.
- **"Back up game servers now" moves each server's schedule clock.** The hourly schedule no longer
  archives the same servers again, with another stop and restart. A skipped or failed server stays
  due.
- **A server that always has players on is no longer silently never backed up.** Once it is twice
  its interval overdue, that is audited and alerted once, and again only after it has been backed
  up. No player is ever disconnected for it.
- **A backup host that is down sends one alert, not one an hour.** Only the first failure of a
  streak alerts; the retries stay on the audit log.
- **A failing daily panel backup no longer stops the game-server backups.** Each step of the hourly
  pass runs on its own and logs a failure as a warning.
- **A direct-SSH host that never answers can no longer stop every backup.** Waiting for its reply is
  now bounded at five minutes, and the connection that did not answer is dropped.
- **A daily panel backup that cannot make its temp folder no longer leaves an empty "backup".** That
  0-byte file counted as the day's backup and could not be restored.
- **The debug report names the notification events that are off.** Not just a count.
- **Restarting or updating the panel no longer kills the game servers it started.** On a host with
  systemd, each server the panel starts on its own host now runs in a scope of its own, outside the
  panel's unit. On
  a root install the stop that installs this update still ends them once; LinuxGSM's monitor cron
  brings back those with autostart on.
- **Panel-started game servers run at the game priority, not the panel's.** A Start or Restart
  begins at nice -1 and maintenance actions at nice 0, as LinuxGSM's own cron runs them.
- **Repairing the database, restoring a backup and updating the panel no longer leave a root
  install's panel stopped.** They (and the OS update) now run as services of their own.
  **Updating a root install TO this version: do it from a shell, once** — `sudo bash install.sh` in
  the panel's checkout (`/home/lgsmpanel/linuxgsm-panel`), or the one-line install command. The
  Update button runs the old updater, which leaves the panel down until
  `sudo systemctl start linuxgsm-panel`. Later updates, and per-user installs, work from the button.
- **An OS update can now restart the panel (root installs on Ubuntu 24.04 and 26.04).** Consoles
  reconnect, the OS-update window keeps following the log, and game servers keep running.
- **Restoring a backup on a per-user install with the helper no longer swaps the files under the
  running panel.** It now restores through the install's own user manager.
- **The local web terminal's jobs outlive a panel restart.** A server, tmux or nohup job started
  there now survives a restart or self-update.
- **The debug report names game servers inside the panel's cgroup.** It warns what a panel stop does
  to them and splits the unit's memory into anon and file cache.
- **Uninstalling a server removes its account's crontab.** `userdel -r` left it behind.
- **Adding a tool's settings file to the repository is no longer offered as a panel update.**
- **Installing a game on a minimal host no longer fails at "Downloading LinuxGSM".** Dependencies,
  wget and curl among them, are now installed before LinuxGSM.
- **An update keeps the panel's systemd unit current, as it does everything else the installer
  put on the host.** A rollback puts the old one back.
- **The installer installs wget, cron and ufw when they are missing.** Installing ufw does not turn
  the firewall on; an update installs them too.
- **A docs, CI or test change no longer brings back "Panel update available" on Telegram or
  Discord.** The alert goes out once per change the panel runs.
- **A file the panel runs that was moved into `tools/` or `docs/` counts as a change.**
- **Checking a lost install asks the host once, not once per poll.** Each poll ran a full `du` of
  the game files; there is now one check per server at a time.
- **Retrying a failed install can no longer be overwritten by the background check.**
- **Security tab event times are shown in your own time zone correctly.** They were shifted by your
  UTC offset.
- **"Panel update available" is sent once per update, not after every restart.**
- **Malformed numbers no longer cause server errors.** A reboot delay or auto-block threshold of
  `Infinity`/`1e400` gets the normal "not a number" handling instead of a 500.
- **A scheduled-task change can no longer be lost or undone by another one.** Crontab changes for an
  account now run one at a time.
- **A failed crontab read no longer wipes the account's scheduled tasks.** Nothing is installed and
  the error is shown.
- **LinuxGSM config values with `$`, backticks, backslashes or quotes are saved as typed.** They
  were written unescaped into a file LinuxGSM runs as shell code, so `$(…)` ran as a command.
  References like `${port}` still work.
- **Broken downloads now fail instead of saving a truncated file.** Downloads that go quiet time
  out, and SSH commands have a connect timeout.
- **A locked database is no longer "repaired" into yesterday's backup.** Only real corruption
  triggers the startup self-heal; anything else stops startup with the error.
- **The self-heal keeps the newest writes of a corrupt database.** Its -wal and -shm are moved aside
  with it instead of deleted.
- **`manage.py` no longer runs the database self-heal** beside the live service.
- **The updater no longer repairs a database it could not read.** The update aborts and leaves the
  data alone.
- **A GitHub outage no longer stalls every page that shows the game list.** Other requests are
  served the copy already held.
- **The session and credential keys can no longer be read half-written** on a fresh install by a
  racing process.
- **Uninstalling removes the panel's sudo grants first,** right after the service stops, and deletes
  the `lgsmpanel-games` group.
- **A FIFO in place of the panel's `config.json` no longer hangs the installer or the uninstaller.**
- **The Tailscale login log is created fresh** (`O_EXCL|O_NOFOLLOW`, 0600) instead of being
  truncated through whatever sat at its path.
- **SECURITY.md describes the sudo grant install.sh actually writes,** including the helper's
  `Defaults!` line and the rules for which accounts may join the game-account group.
- **A sign-in that can't be recorded is refused instead of going through half-registered.** The
  session write is retried once, then the person is asked to try again.
- **One missed probe no longer pages you.** A host or server is declared down only after two failed
  checks in a row.
- **A burst of alerts arrives as one message instead of dozens.** Whatever piles up is sent as one
  message per channel.
- **Changing your password, or signing out everywhere from an older login, never leaves an untracked
  session.** If the new session record can't be written, the device is signed out.
- **`Infinity` in a JSON body no longer causes a server error** (bulk actions, tag sets, discovery
  import, firewall rules, the SSH port change, backup settings, and the console and terminal
  sockets).
- **Bad Garry's Mod content and config requests get a clear error** instead of a 500 or a silent
  mount.
- **Retry can't start an install into a server that is being uninstalled.**
- **Only one panel restore runs at a time.** Two concurrent restores could combine the database from
  one backup with the encryption key from another.
- **Rebooting the panel host no longer sends "server went offline" alerts.**
- **Blocking or unbanning an address on the panel host takes effect at once** in the panel's own ban
  check.
- **Clicking Update no longer risks aborting the update it started.** The progress card watches only
  the update log instead of re-checking for updates every 1.5 seconds.
- **Install and bootstrap progress stop polling once their row is gone.**
- **"Still working — reload the page to check." stays put** instead of being overwritten by a slow
  poll.
- **`Infinity` or `1e400` in a request no longer causes a server error** in firewall ports, terminal
  sizes, rule numbers and several other numeric inputs.
- **Opening a second terminal on the same connection now records that the first one closed.**
- **A failed port scan while setting up a Source server's extra ports is now logged.**
- **The panel host's own Firewall card could say "permission denied" with the helper installed.**
  On the panel's own host the rule list is now always read as root, through the helper where it is
  installed.
- **On a remote host, a fail2ban log just under the 8 MB read limit is counted again.** It had been
  treated as cut short, so auto-blocking on that host held still.
- **Storing a host's first SSH key pin no longer freezes the panel while the database is busy.** If
  the database is busy, that one connection is refused and the next one tries again.
- **On Python 3.13 and later (Ubuntu 26.04), a closed terminal could keep its slot until the panel
  restarted.** It went on counting against the per-user and total terminal limits. Python 3.10 to
  3.12 were not affected.
- **The daily gamedig pass could write to a host that had just been deleted.** Each host and server
  is now re-read just before it is acted on.
- **An older "daily restart when empty" line could restart the server with players on it.** Old
  lines restarted whenever the player query failed. The daily in-place upgrade now rewrites every
  shape the panel has written to today's line, keeping its schedule; a line an operator has edited
  only gets the PATH.
- **The panel's update card now says when an update stopped, or held, instead of spinning.** It
  shows the installer's own reason, or its hold line, and the buttons come back.
- **On a shallow checkout the update decided on less history than it then acted on.** An older
  verified pin could read as "not verified" and hold the host with a false warning. The update now
  unshallows the tracked branch before deciding.
- **"Daily restart when empty" never restarted on a host whose Node.js came from Ubuntu.** Under
  cron the check could not find gamedig, so it never counted a player. It now sets its own PATH, and
  existing lines are fixed by the in-place upgrade, which now runs daily for every game server.
- **Player counts and lists never worked on a fresh Ubuntu 24.04 or 26.04 install.** The installer
  and add-host bootstrap now install `npm` when needed, so gamedig gets installed. Also fixed on
  26.04 (sudo-rs): a Firewall-page refusal read as "The panel can't reach this host", and the
  install retry for a just-created account.
- **"1 RLock(s) were not greened" no longer prints on every start under Python 3.13+** (Ubuntu
  26.04).
- **After an in-place Ubuntu release upgrade the panel could not start, and re-running the installer
  did not fix it.** A venv whose Python changed is now rebuilt through the full update path, and
  `linuxgsm-panel-recover` names the problem. Minimal images get `tzdata` so time zones work.
- **The live console no longer re-appends old output after an update and a start.** The 30-second
  catch-up poll appended its whole window again under the live output; it now appends only while
  the live connection is down. **Load older** no longer wipes the console for a log it could not
  read.
- **The Tailscale page's Disable, and the SSH toggle, did the wrong thing.** Turning Tailscale SSH
  off reset every other Tailscale setting. Disable now removes the panel's own route and is refused
  while the panel is bound to loopback: bind `0.0.0.0` under System → Panel Server first.
- **The firewall's delete guard protects the rules that keep you in.** It failed open when the
  firewall could not be read, and a stale rule number could delete a different rule. "Remove rate
  limit" now rewrites LIMIT to ALLOW instead of closing the port. `force` still overrides the guard.
- **`uninstall.sh` removes what it installed, and only that.** A per-user uninstall no longer leaves
  its root cron, helper files or fail2ban jail behind, confirms the service stopped before deleting
  files, and no longer resets every Tailscale Serve mapping on the node. It warns that a surviving
  panel user still holds the SSH key to every managed host.
- **`install.sh` fails safe mid-update.** A truncated snapshot or an abort could leave the panel
  half-populated or down with no message. On a per-user install the firewall probe no longer runs
  without `sudo`, which left the panel's port closed.
- **"Is anyone on?" no longer answers "no" when it could not tell.** A failed player query counted
  as 0, so the "when empty" restart and reboot could hit a full server; only a counted 0 means empty
  now. Confirmations say when a count could not be read.
- **A server's status is what the game's port says, and a failed read no longer overwrites it.**
  "Online" now means the game's port is listening, so a crashed server no longer reads as online.
  Only a status that was actually read is stored, so failed reads no longer raise false offline or
  "empty" alerts.
- **Auto-blocking and the fail2ban watchers no longer act on reads that failed.** A failed read no
  longer releases every auto-block, floods ban notifications, or shows the Auto-block toggle as off.
  Expired blocks on a quiet remote host are released again.
- **An unreachable host no longer renders as idle and healthy.** A down host had shown "Reachable"
  with CPU, RAM and Disk at 0% and recorded zeros in the charts. It now shows as unknown or
  unreachable, live charts leave a gap, and the Reachable badge follows the monitor.
- **Database repair keeps the fullest copy.** It counts the rows in the rebuild and the backup,
  takes the fuller and says which; it had kept a 17-of-4,000-row rebuild over a full backup. The
  rebuild no longer discards salvaged rows at one bad page, and the pre-update database check now
  runs on a root install.
- **GMod shared content on a remote host is detected correctly.** The check always said the content
  was downloaded, so it never was, and update crons were written for scripts that did not exist. A
  content mount on a running server now says it needs a restart.
- **A failed read can no longer be saved back over a real config.** Config, port and alert edits,
  the Raw tab, the file editor and the Alerts card now report a failed read and change nothing,
  instead of saving an empty or partial file (or blank webhooks and tokens) over the real one.
- **A failed read no longer triggers something destructive.** Failed reads no longer delete backups
  to free space, re-download an installed server, unmount all GMod content, turn off Autostart and
  Daily restart, or wipe the stored command list that shows Start, Stop and Update.
- **"Nothing there" and "could not look" no longer render the same.** Folders, backups, the firewall
  and Public SSH cards, fail2ban, Ubuntu Pro, discovery and other checks now say they could not read
  instead of reporting empty, inactive or fine.
- **Actions that report success now check that they succeeded.** Unblock, firewall and port changes,
  reboots, full backups, "Run now" and global bans now report and audit what actually happened. The
  SteamCMD crash-dump sweep now runs on remote hosts.
- **An upload no longer overwrites a file because a check failed.** A failed existence check no
  longer reads as "nothing there", which had replaced files you asked not to overwrite.
- **On a phone, the dashboard's Actions column no longer covers the row.** Its buttons now wrap into
  two rows instead of covering the server name, status and players; desktop is unchanged.
- **The VPS bootstrap no longer acts on probes that never answered.** It no longer reboots, skips
  swap or skips the game account on a probe that did not answer. Filling in a remote's optional
  game-user field no longer runs every privileged command as that user instead of root.
- **Tailscale migration checks the new way in before closing the old one.** It now logs in over
  Tailscale before closing port 22 and blanking the stored credential, and names the real problem,
  including the `tailscale set --ssh` to run. "Allow Tailscale" no longer risks opening `wg0`
  instead.
- **A branch switch that failed to launch no longer changes the tracked branch.** The next ordinary
  Update no longer moves the checkout onto a branch it never switched to.
- **Backups honour a server's own retention, and "Back up now" counts.** "Back up now", the full
  backup and the wait-until-empty queue keep a server's retention override and move its schedule
  clock. A panel restore no longer goes ahead when its safety copy fails, unless you override it for
  a database too broken to copy.
- **Bans on imported Source servers survive a map change.** Bans from the Players panel and global
  bans now make sure each target server's config execs `banned_user.cfg` first.
- **Installs that worked were reported as failures, and one that could not work was reported
  online.** The first-boot wait is now about 90 seconds, a game that ignores the panel's port
  setting no longer takes another server's port, and SCP: Secret Laboratory now starts.
- **Left 4 Dead 2 installs.** The install applies LinuxGSM's documented `steamcmdforcewindows`
  workaround for SteamCMD's "Invalid platform" error once, and sets the option back even if the
  download fails.
- **SteamCMD stopped working for every game on a host once ten accounts had used it.** The panel now
  frees orphaned Steam crash-dump slots (never a live account's) on uninstall and before each
  install, so a wedged host heals on its next install. Failures a retry cannot fix stop the retry
  loop.
- **On an install hardened by `install.sh` run as root, the panel could not manage a single game
  server.** The narrow sudoers grant now also lets the panel become accounts in the
  `lgsmpanel-games` group, and only those. The installer applies this on every run, including one
  with nothing new to fetch.
- **Installing a game server failed at the dependency step on a hardened host, silently.** The step
  now works under the narrow grant, enables `multiverse` and reports what did not install. The OS
  update, reboot and "enable unattended upgrades" no longer refuse under it either.
- **The file editor saves exactly what it opened.** Saving without typing no longer converts CRLF
  line endings to LF or drops the trailing newline and leading blank lines, and a malformed read is
  treated as a failed read.
- **Changing the SSH port works on Ubuntu 22.10 and later.** The panel now writes an `ssh.socket`
  drop-in, since `sshd_config`'s `Port` is ignored there. A bind address that would lock you out is
  refused before anything changes.
- **The panel-login fail2ban jail never banned anyone on Debian or Ubuntu**, while the panel showed
  it Active. Those distributions read the journal by default, but the panel logs failed logins to a
  file; the jail now pins a file backend, and existing installs correct themselves on startup.
- **Commands with a lot of output, and helper verbs run outside systemd, no longer hang.** A long
  `journalctl`, a fail2ban log grep or a big update's output no longer hangs its request, and helper
  verbs started outside systemd no longer wait for stdin until "Command timed out".
- **Console lines are no longer cut at 80 columns, and the player list with them.** A Minecraft
  `list` reply no longer parses as one player, which fed the Players panel and the "when empty"
  checks. Load older now works.
- **Pages no longer offer controls their route refuses, and a few that did nothing now work.** Stop,
  Restart, Files & Config and superadmin-only controls are no longer shown to users who cannot use
  them. Clicking the pending-restart banner no longer aborts the page's requests, and Uninstall
  after an import works.
- **Browser fixes in the translated UI and the dashboard.** In Spanish or French the translator no
  longer rewrites server names, usernames or folders. The updates banner no longer dismisses itself,
  and "Show this panel again" works.
- **Bad requests and down hosts no longer answer 500.** API calls now get JSON errors: 400 for bad
  input and an "unreachable" answer for a down host. A `config.json` that is not an object no longer
  crashes every page, and one that does not parse is no longer overwritten with defaults.
- **Scheduled Tasks edit and delete work on a crontab whose first line is indented.** Delete no
  longer removes nothing while reporting success, and edit no longer leaves the job on two
  schedules. A `%` in a restart-pending job is no longer cut off.
- **Notifications that fail are logged, and a restart cannot replay a Telegram command.** A provider
  rejecting a message is now logged, and an hours-old Telegram `/stop` is no longer replayed after a
  restart. `/console` says when there is no session, and `/players` no longer reports a down server
  as empty.
- **The install page says why the game list is empty** — a DNS failure, an HTTP error, a response
  that was not a CSV, a read-only `data/`. Retry says whether it fetched fresh or used the cached
  copy.
- **Editing your own account can no longer leave the panel without a superadmin.** A demotion
  combined with a password reset or 2FA change was committed before the last-superadmin guard ran.
- **A new host or server no longer inherits a deleted one's state.** SQLite reuses a deleted row's
  id, so a new host or server could pick up the old one's auto-block opt-in, backup overrides,
  cached specs, job state, history and saved-layout place. All of it is now cleared with the row.
- **Downloading a game backup whose name contains a newline or a non-Latin-1 character** (an
  em-dash, CJK) no longer fails with a 500.
- **Console text is no longer struck through, bolded or italicised at random.** Extended-colour
  sequences, such as a Minecraft plugin's hex colours, were misread as formatting. They are now
  dropped whole, and a real code in the same sequence still applies.
- **The console no longer loses output, or cuts a line in half, during a busy burst.** Output past
  64KB per poll, as on every Garry's Mod start, was discarded and lines were cut at the boundary. A
  burst now drains over the next few polls, and a half-line waits to be completed.
- **The panel no longer offers to turn LinuxGSM's `logtimestamp` on**, and offers a way to turn it
  off. With it on, LinuxGSM's log capture is block-buffered, so a quiet server's console looks
  frozen. A log stamped by hand still reads correctly.
- **Console lines with a timestamp are no longer taller than lines without one.** Mixed stamped and
  unstamped lines had looked like ragged double-spacing.
- **Console timestamps now appear on a server that only polls, and an empty column says why.** Lines
  arriving through the 30-second poll are now stamped, not just websocket ones; only history from
  before the panel looked stays blank. While nothing is stamped, the console says "Times appear on
  lines as they arrive".
- **Schedules are now set in your own time, not the host's.** The daily restart time is entered in
  your timezone, with the host's time shown underneath. Where daylight-saving rules differ, the
  schedule is an hour out after the next changeover.
- **A long action's output no longer vanishes when you reload the page.** The panel keeps a bounded
  per-server backlog of what it pushed and replays it on the next console load, even when the host
  is unreachable.
- **"Watch the live console for progress" was not true of any long action.** Update, validate,
  backup, force-update, mods-update and fastdl now show their output in the live console as it is
  produced, between start and finish markers. The audit-log entry and chat bots' completion message
  are unchanged.
- **The Update button appeared for games that have no update command.** The server page no longer
  offers Update on a Call of Duty server; it asks the same check bulk actions use.
- **A game server could be installed on a port that does not exist.** Install now refuses ports out
  of range (such as `0`, `-5` or `99999`) and non-ASCII digits, and the range is enforced again
  where a port is stored.
- **The port picker could hand back a port that was already in use.** After 400 candidates it
  returned an occupied port, and could pass 65535; it now reports finding nothing and the install is
  refused with a message naming the problem.
- **Installing to a host that was switched off returned a 500.** The install form now says the host
  is down and writes no row.
- **The setup wizard could save a panel port that the panel cannot bind.** Step 1's port is now
  validated like the in-panel port change, so a typo like `0` or `99999` no longer leaves a panel
  that will not start.
- **Rotating a remote's SSH credential did not take effect.** Editing a host now drops its pooled
  SSH connection, so a new credential or address takes effect instead of the old connection staying
  in use.
- **A new game server could inherit a deleted one's status.** A new server could show a deleted
  one's failed backup or a GMod content install frozen at "running"; both are now cleared with the
  row.
- **An update that changed only the privileged helper raised no "update available" badge.** It does
  now; the badge is what tells you to re-run `install.sh` as root to refresh the helper.
- **The self-update's CI gate read only the first 100 checks on a commit.** A failure past the first
  page could have let a commit be offered as an update; it follows the pages now.
- **Every host was given Ubuntu 24.04's package list, whatever it was actually running.** The panel
  now fetches LinuxGSM's dependency list for each host's own release from `/etc/os-release`, so
  22.04 hosts no longer get packages that do not exist there. A distro LinuxGSM does not publish
  falls back to the default.
- **Start/Stop/Restart on Files & Config reported a failure right after reporting success.** The
  action had worked; a script error showed "Action failed — connection error". That toast now
  appears only for real upstream failures.
- **Ctrl+A in the console selected the whole page.** Click into the console and Ctrl/Cmd+A now
  selects only the console; elsewhere it is unchanged.
- **An unreachable host blanked the console on page load.** The console keeps what is on screen
  until a poll returns something.
- **Restart and Stop on the dashboard fired with no confirmation.** Both now confirm, naming the
  server and its connected player count when known, and bulk Restart now confirms like bulk Stop and
  Update. Start does not ask.
- **The live console kept throwing away its history.** It now keeps a scrollback of up to 5,000
  lines, adds only new lines on each poll, starts from 250 lines rather than 100, and has a Load
  older button for deeper history.
- **"Replace existing file" never replaced anything.** Ticking overwrite on an upload conflict, per
  file or replace-all for a folder, now replaces the file instead of reporting it already existed.
- **Running the installer the "other" way built a second panel instead of updating the first.**
  Running `install.sh` as root over a per-user install, or the reverse, now refuses instead of
  setting up a parallel panel, naming the install it found and how to update it.
- **Six endpoints answered HTTP 500 when a remote host was simply unreachable.** `live`,
  `pro-status`, `uptime`, `firewall`, `check-updates` and `tailscale-check` now answer 200 with an
  error field for an unreachable host; other failures still return 500.
- **Four buttons on the Remote Servers page did nothing.** Tailscale check, Tailscale bootstrap,
  Install Tailscale and Delete remote now work, and the page's live-stats auto-refresh starts.
- **A failed swap-file setup still wrote a swap entry to `/etc/fstab`.** A host that ran out of
  space got an fstab entry for a swap file that was never formatted.
- **A parser could crash on a superscript digit.** Characters like `¹`, in places such as a game
  config's query port or the session cookie, are now refused by the digit check instead of crashing
  the parse.
- **`tailscale0` was never actually allowed through UFW.** Every call failed before reaching UFW, so
  "Allow Tailscale Interface" answered 500 and the automatic allow after `tailscale up` and during
  Serve setup never ran.
- **The installer's update path never refreshed the root-owned helper.** Updates now refresh it and
  re-evaluate the sudoers grant, which had left hosts first installed before the helper on
  `NOPASSWD:ALL`. The Diagnostics card names verbs the installed helper lacks.
- **The "Repair database" button could never appear.** A duplicate id on the Manage page hid the
  wrong button and relabelled the wrong control.
- **Disabling Tailscale Serve on a sub-path mount did not disable it.** Disable reported success but
  left Serve running on a mount such as `/lgsm-panel`; it now uses the configured mount, which the
  Mount Point field also shows.
- **Changing the panel's port dropped the fail2ban whitelist.** Whitelisted IPs and CIDRs lost their
  panel-login exemption until the next boot re-applied it.

- **`datetime.utcnow()`, which Python has scheduled for removal, is gone** from all 22 call sites.
  Stored timestamps are unchanged.

### Security

- **Rate limiting no longer opens a port to the internet.** Limit on a port that was closed, or open
  only to the tailnet, one address or one interface, added a rule letting everyone in. It now
  refuses unless the port is already open to everyone, and says so.

- **Moving SSH on a host whose firewall is off no longer stores a public rule.** Where the
  firewall's saved rules keep SSH to the tailnet or one address, the move adds no rule open to
  everyone, which would have applied once the firewall was turned on.

- **The installer works as the panel's account inside the panel's files.** An update chose which
  account to work as from the panel folder's entry, which the panel's account could replace with a
  link on hosts that allow such links, and some steps then ran as root. They now run as the panel's
  account unless the folder is root's own.

- **A crafted server name can no longer stall the panel when Files & Config opens.** The config file
  line and the Server IP port are read from LinuxGSM's details output in linear time, however long a
  line the game's config makes.

- **A game config XML file with very many comments no longer stalls the panel.** The config form's
  comment walk now reads the file once.

- **SSH port moves never open SSH wider than it was.** Under a default-allow firewall, an SSH port
  move now stops when SSH is denied on one of the host's addresses, instead of letting the new port
  in there. A move also stops, changing nothing, when the firewall's rules could not be read, rather
  than opening the new port to everyone.

- **The player-query tool's XML parser is the fixed release.** gamedig, which the panel uses to
  count players, came with a version of its XML parser that could be made to spend a long time on a
  crafted reply. The panel's copy now uses the fixed version. Only Farming Simulator queries read
  XML.

- **Moving SSH never opens it wider than before.** An SSH port move no longer opens the new port on
  more addresses than SSH was open on. Where SSH is public on only one of the host's addresses, or
  blocked on one, the move stops and names the rule to add for the new port first. With UFW handling
  IPv6 but only an IPv4 SSH rule, the new port is opened over IPv4 only, and where UFW's settings
  can't be read the move stops instead of guessing.

- **Close port 22 checks the panel's Tailscale connection.** Close port 22 now refuses, as Disable
  public SSH already did, when the panel reaches the host over Tailscale on a port Tailscale SSH
  does not answer.

- **Blocking and rule deletes behind a local proxy keep you connected.** On the panel's host,
  blocking an address range is refused when it would cut an open connection to the panel's web
  ports, so an admin behind a proxy that sends no client address is not locked out. When the panel
  cannot tell how you reach it, the rules for its web ports can no longer be deleted from the
  Firewall card.

- **Dropping the panel host's sudo grant now sticks.** If you only manage remote servers, run the
  installer once with `PANEL_LOCAL_GRANT=0`: it removes the panel's sudo grants on its own host and
  records the choice, so later updates no longer put them back. If you had deleted the grant file by
  hand, the next update leaves it deleted. `PANEL_LOCAL_GRANT=1` restores it.

- **A proxy's address can no longer add a line to the panel's log.** The warning written when a
  forwarding header is not believed now replaces any line break in the address it names, so it
  cannot forge a log line.

- **Moving SSH to a new port keeps it off the internet.** On a host whose SSH is reachable only over
  Tailscale or one network interface, moving the SSH port opened the new port to everyone. Now the
  move adds nothing public there: a rule letting the panel in from its own address range is copied
  for the new port, an interface or Tailscale rule the panel can't copy stops the move and is named,
  and on the panel's own host nothing is added. A deny rule ahead of the new port refuses the move.

- **The panel host's auto-block spares signed-in admins.** A stale API token or a repeatedly
  throttled sign-in could build up enough fail2ban hits to have an admin's own address permanently
  blocked, cutting off the panel and SSH. Addresses of signed-in superadmins are now skipped, and
  when sessions cannot be read nothing new is blocked.

- **Auto-block never blocks the panel itself.** The hourly auto-block could add a permanent deny for
  the address the panel connects to a remote host from, or for the panel host's own addresses, after
  enough failed logins from them (a changed SSH key, or a shared home connection). The panel then
  could not reach that host to undo it. Those addresses are now skipped, and when they cannot be
  read nothing new is blocked that hour.

- **Blocking an address on the panel host refuses your own.** The panel host's Block now refuses an
  address or range that covers the one you are using, as a remote host's Block already did, and
  refuses while it cannot tell your address (behind a proxy the panel was not told to trust).

- **A fresh copy of the panel's code is checked against your release key.** When the panel's code
  folder is missing and the installer clones it again, the clone is now checked against the release
  key on hosts that keep the key only in the installer's own copy.

- **dnspython 2.9.0 on Ubuntu 24.04 and 26.04 (CVE-2026-114605).** Older dnspython can spend
  unbounded CPU on a crafted DNS reply. Ubuntu 22.04 stays on 2.8.0, which has no fix; the risk
  there is a busy panel, with nothing read or changed.

- **msgpack 1.2.3 in the CI dependency audit's own tools** (GHSA-j586-36cw-2gc2, a memory leak). It
  runs only in CI; nothing on a panel host uses it.

- **TeamSpeak 3's ServerQuery (its admin console) is no longer open to the internet.** Install and
  "Open all ports" no longer open it, and the panel removes, once per TeamSpeak 3 server, only the
  ServerQuery rules it opened itself, never ones you added or player ports. What it closed is in the
  audit log.

- **Test fixtures carry no real addresses.** A tailnet address and a public address copied from a
  live debug report were replaced with made-up or well-known ones, and the privacy check now refuses
  them.

- **The repository no longer names the maintainer's own hosts.** Test fixtures now use made-up host
  labels, tailnet names and addresses, and a check keeps them out.
- **Tailscale SSH on the panel's machine is your install-time choice.** The installer asks (default
  no); the panel turns Tailscale SSH on only if you chose it, and a machine already running it keeps
  it. Before, on a machine not yet on Tailscale, a compromised panel account could start a login
  with SSH on and let whoever opened it pick the tailnet.
- **Serve and Funnel publish only the panel's own port.** The root helper refuses any other port,
  and refuses Funnel while anything else is served on the same listener. Before, a compromised panel
  account could put any local service on the public internet through Funnel.

- **On the panel's own machine, the panel account no longer controls Tailscale.** It is no longer
  Tailscale's "operator"; Connect, Serve, route removal and Tailscale SSH go through the root
  helper, which will not move a joined machine to another tailnet. Connect on a machine that is
  logged in but down asks you to run `sudo tailscale up`. On a per-user install your own
  `tailscale serve` now needs sudo. Remote hosts are unchanged.
- **The downloadable debug report leaves out account security.** 2FA counts, invites, the setup
  token, firewall, fail2ban, Funnel, proxy and cookie settings and similar appear only on the report
  page in the panel, not in the file the issue form asks you to attach publicly.

- **The root helper no longer lets the panel account run commands as root through apt.** An
  `#include` in `/etc/apt/apt.conf.d/20auto-upgrades` could pull in a hook apt runs as root; the
  file now accepts only the four update settings the panel writes. Installs where the panel already
  runs as a root-capable user were not exposed.

- **CI's Semgrep job runs on an MCP SDK with no known advisory.** It now uses mcp 1.30.0 instead of
  semgrep's pinned 1.29.0 (GHSA-84m7-p3x7-pcfv). CI only.

- **A seventh full review on 2026-10-12: security.**
  - **Host terminal.** A host's label can no longer carry terminal escape sequences into the web
    terminal.
  - **HTTPS cookies.** The secure-cookie setting is read the same however it was written.

- **A sixth full review on 2026-10-12: security.**
  - **SSH lockout guard.** Removing an "Allow from source" rule could delete the only way in to SSH
    or the panel when the source was written in another form (`0.0.0.0/0`, a `/24`, `/32`).
  - **Root helper.** The restart-flag check no longer follows a symbolic link, and its update,
    restore, database-repair and OS-update jobs run only inside their own system unit.
  - **Accounts that can become root.** The panel no longer lists such an account's scheduled tasks.
- **A fifth full review on 2026-10-12: security.**
  - **SSH lockout guard.** Removing an allowed address or closing a port can no longer remove the
    only public way in to SSH; multicast, broadcast and portless rules no longer count as one.
  - **Audit log.** User names and LinuxGSM colour codes are escaped.
  - **The debug report** no longer prints part of a doas command's arguments.
- **A fourth full review on 2026-10-12: security.**
  - **SSH lockout guard.** Loopback, Docker-bridge and UDP-only rules no longer count as another way
    in, and rules are read in the order the firewall applies them.
  - **File browser.** New file and folder, rename and delete pass only the validated LinuxGSM script
    name to the host.
  - **The debug report** no longer prints secrets nested in JSON text, nor sudo arguments in the
    last case that still leaked them.
- **A third full review on 2026-10-11: security.**
  - **Tailscale Serve.** Turning Funnel on for the panel could publish (or unpublish) a file share
    or text page served by Tailscale.
  - **SSH lockout guards.** All-ports and UDP rules no longer count as SSH rules.
  - **The privileged helper.** Four more sudoers forms that withdraw a root grant are read as sudo
    reads them; content commands on a remote host run as the content account, not root.
  - **The debug report** no longer prints sudo arguments when the host's language is not English.
  - **The panel no longer says "tailnet-only"** when it could not read Serve, or during a pending
    port change.
- **A second full review on 2026-10-11: security.**
  - **Funnel for the panel no longer flips another app's Funnel** on the shared :443 listener; such
    a change is refused, and the pages say when another app's Funnel makes the panel public.
  - **Binding the panel to `::1` with Tailscale Serve set up**, which locked you out, is refused.
  - **SSH lockout guards.** Port lists, ranges and `FWD` rules are read correctly, and "Close port"
    no longer deletes a forwarding rule.
  - **Root-access check.** The installer's game-group line could cancel out a real root grant, and
    three other sudoers forms were misread.
  - **The debug report** prints only a fixed label for sudo lines it cannot parse in full.
  - **The installer** opened the panel's port past a UFW `DENY` written as a port range.
- **gamedig's dependency `http-cache-semantics` is 4.3.0, not 4.2.0.** Only the lockfile moved. This
  does **not** fix CVE-2026-93748 (the upstream fix was never merged); it stays unreachable here
  because gamedig never gives its HTTP client a cache.
- **Findings from a full code review including the tests and CI (2026-10-11): security.**
  - **The debug report could print a password**, such as `sudo mysql -p<password>` from a sudo
    command refused in the web terminal. It now shows a fixed label.
  - **Reinstalling opened the panel's port to the internet** when a UFW rule already limited it;
    existing rules for the port are now left alone.
  - **The firewall page let you delete the only public SSH rule**, because any Tailscale-interface
    allow counted as another way in.
  - **A loopback address written another way** (`0::1`) bypassed a lockout guard.
  - **The string `"false"` turned Tailscale Funnel on.**
  - **The helper treated sudoers files that sudo ignores as grants**, so a `.disabled` file made
    every game account read as root-capable.

- **Findings from a full code review (2026-10-08): security.**
  - **"Disable public SSH" on a remote host could lock you out**; the panel now reads the host's
    rules in order on its real Tailscale interface and answers "not safe" on any doubt.
  - **"Migrate to Tailscale SSH" needs a superadmin**; a delegated admin could point a host at
    another tailnet machine.
  - **Sign-in codes** now count against the per-account limit too; **file-browser reads** as a
    root-capable account are refused, as writes were.
  - **Panel-host details on the remote-host pages** are superadmin-only.
  - **The privileged helper** deletes a home folder only for an account it removed, without
    following a planted link.
  - **The uninstaller runs from a root-owned copy** in `/usr/local/lib/linuxgsm-panel/`, not from
    the panel's checkout, which the panel user can edit.
  - **The `curl … | bash` installer** uses the current folder only when it is its own tree.
  - **The Add Remote form hides the SSH password**, and the debug report masks configured secrets.

- **A stored server name is never put into the account check's shell text (GHSA-hh39-76g3-wxcx,
  reopened).** A name from an older database, a hand edit or a restore could run shell code on the
  host (as root on a remote with sudo enabled) when deleting, writing files or cron, or importing.
  Such names are now refused before the host is asked, and removing such a server now removes it
  from the panel without touching the host.
- **A failed firewall step during an install no longer opens SSH.** If the firewall step failed,
  the install's port re-read opened everything LinuxGSM reported, including port 22. It now holds
  back SSH, the panel's port and other servers' ports itself; when the firewall step failed it
  opens only the server's own port and finishes with a warning.
- **An action's message never carries an internal error's text.** Such text, which could name a
  path, now goes to the log.
- **A malformed stored server name can no longer mute that server's offline alerts.** A name like
  `x|.*` matched every maintenance process on the host; such names are not probed now.
- **The browser's Socket.IO client is 4.8.4, past two HIGH advisories in the parser it bundles.**
  GHSA-677m-j7p3-52f9 and GHSA-2m8v-j782-fhvr; the realistic worst case was a tab driven out of
  memory by a malicious or intercepted server. Browsers take the new client on their next page load.
- **Scanners can see the vendored browser libraries now.** `static/vendor/` now has a manifest and
  lockfile the dependency audit reads. A change to those manifests alone is not offered as an
  update.
- **gitleaks catches a Telegram bot token wherever it is written.** That includes the panel's own
  `config.json` shape and the Bot API URL.
- **A pull request can no longer allowlist its own leaked secret.** It is scanned with the base
  branch's gitleaks config and ignore file, so an exemption has to reach `main` on its own first.
- **SECURITY.md says how to check an install set up before the setup-token fix**
  (GHSA-cwmq-pvg9-jjfx): list the superadmins, confirm which tailnet the host is in and what it
  publishes, and read the sign-ins. Finishing setup did not undo either takeover.
- **CodeQL sees Socket.IO input and the commands the panel runs.** A model pack in
  `.github/codeql/extensions` makes socket input untrusted and the command text sent to hosts a
  command-injection sink.
- **CI's Semgrep job runs on a PyJWT with no known advisory.** Semgrep's lockfile now carries PyJWT
  2.15.1, past the 2.13 advisories (worst GHSA-ffc3-869f-jxw9). CI only: the panel does not use
  PyJWT.
- **Group forms reject ids that cannot be real ids.** An extremely long number no longer causes a
  server error, and non-ASCII digits are no longer read as ids.
- **Moving SSH to another port no longer deletes the firewall rule your current SSH depends on.**
  The panel now opens only a port no rule already lets in, removes only a rule it added, keeps a
  rate-limited SSH rule, and refuses a port a firewall rule blocks before changing anything.
- **Deleting a firewall rule by number can no longer hit a different rule.** Firewall changes on a
  host now run one at a time, so an auto-block deny cannot shift the numbers mid-delete.
- **A password-login host with no usable stored password no longer signs in with the panel's own SSH
  key.** It fails with a clear message. A key-login host uses only the key it names.
- **The file browser can no longer delete LinuxGSM's files through a symlinked folder.**
- **A backup code now works exactly once, even when two sign-ins race.**
- **Only real game accounts can join the panel's game-account group.** Before, the helper enrolled
  accounts such as `postgres`, `www-data` or a colleague's login. An account now needs an ordinary
  uid and groups and a LinuxGSM install or content tree in its home; the root check also reads doas
  and polkit and refuses more root-equivalent groups.
- **The privileged helper no longer takes its interpreter or environment from the caller.** It runs
  `/usr/bin/python3 -I` with a fixed minimal environment.
- **Root no longer reads files in the panel's directory through symlinks.** A `VERSION` symlink
  could hand a root-only file such as `/etc/shadow` to the panel through the update log.
- **Hard links can no longer steer root's chown or chmod** on hosts with `fs.protected_hardlinks=0`.
- **The self-update installer no longer runs inside the panel's checkout.**
- **Remote GMod content and mount operations run as the game account, not root.** A linked
  `mount.cfg` printed the remote host's `/etc/shadow` into the panel.
- **An update from a local checkout unpacks as the panel's user,** so directory links in the panel's
  tree can't redirect root's writes.
- **Update snapshots and rollbacks no longer run as root inside the panel's own files.** A planted
  link could redirect root's writes or copy a root-only file into a readable archive. These steps
  now run as the account that owns the panel directory; rollback works as before.
- **A stolen "remember me" cookie no longer works from someone else's machine.** Every per-device
  login is now checked against the address and browser noted at sign-in (IPv6 by its /64).
- **Old pre-upgrade login cookies now die with a password change or "sign out everywhere".**
- **A request body sent in chunks is read before the request is authorized, like any other.**
- **"Monitor" now needs the restart permission.** It restarts a crashed server, but a view-only
  user could run it; the maintenance menu now hides it from them.
- **An authenticator code can no longer sign in twice by racing itself.** This covers API-token
  mints too.
- **Chat bots now check who sent a command, not just which chat it came from.** Before, anyone in
  the Telegram group or Discord channel could stop servers, run `/update` and read the console. Add
  numeric user IDs under "Users who may run commands" on the Notifications page; `/status`,
  `/servers`, `/hosts`, `/connect` and `/help` stay open. **With the list empty nobody can run the
  rest**; the bot replies with the sender's ID.
- **The Discord bot no longer risks getting its token reset by reconnecting forever.** A refused
  token (4004) or Message Content intent (4014) now stops the bot and says why in the log and on the
  Notifications page, until the token or "Accept commands" changes (retrying every 6 hours).
- **A stolen remember cookie from before per-device sessions no longer works from another machine.**
  Under "strong" protection such a cookie is refused; sign in once more to get a per-device login.
  "basic" and off are unchanged.
- **Discovery import no longer adopts an account that is root on its host.** A delegated admin could
  import the host's sudo login and gain root through the file manager or cron. Import now refuses
  root-capable accounts, and imports nothing if the host can't be asked.
- **Uninstall never deletes a host's administrator account.** For a root-capable account, only the
  panel row is removed, with a warning.
- **Garry's Mod shared content needs access to the host.** An admin of one GMod server could remove
  content every GMod server on the host mounts.
- **Deleting a tag needs access to every server that carries it.** Tags are install-wide and drive
  alert routing.
- **Current-password and 2FA-code checks are throttled per account and audited.** This covers
  password change, 2FA on or off, minting an API token and deleting a host.
- **Tailscale peer check is superadmin-only.** It pinged arbitrary addresses from the panel host for
  any Manage Remotes holder.
- **The panel host's firewall can't be changed through the game-port routes by a delegated admin.**
- **An update whose checks could not be read is no longer installed.** When GitHub can't be read,
  nothing is offered and the update card says why. `ssh://git@ssh.github.com:443/…` origins are
  recognised.
- **An update isn't offered until its code-scanning check has run.** A code commit must carry CI,
  CodeQL and the alerts check.
- **Semgrep findings now block an update.**
- **Auto-deploy waits for the security checks, not only CI,** and refuses a commit that failed any
  of them.
- **Switching the panel back to main no longer skips the update checks.** It installs main's newest
  version that passed its checks. Other branches still install their newest commit, which the panel
  calls unverified code for testing.
- **File and cron writes are refused for a game account that can become root on its host.** This
  covers server rows imported earlier; if the host can't answer, nothing is written.
- **Only a superadmin can edit or delete the panel host's own entry.** Deleting it removed every
  game server on that machine from the panel.
- **A firewall rule is deleted by number only while it is still the rule that was checked.** A `ufw`
  command typed on the host in between can no longer cause a different rule to be deleted.
- **Telegram polling no longer follows redirects.** It followed them with the bot token in the URL;
  failures no longer log the URL.
- **Enabling 2FA spends its code the same way sign-in does.**
- **A delegated admin whose hosts include the panel's own no longer gets that host's controls.**
  Firewall, SSH, OS update, reboot, fail2ban and Ubuntu Pro actions under a host's Manage page now
  return 403 on the panel host for a non-superadmin; remote hosts are unchanged.
- **You can no longer reset your own password or 2FA from the Users page.** That form asks for
  neither your password nor a code; use your Account page. Resetting *another* account is unchanged.
- **The login throttle can no longer be raced or reset.** Attempts count the moment they start, and
  earlier failures stay counted after a successful sign-in.
- **The self-update no longer prunes old snapshots by splitting their names.** A folder name with a
  space could make root delete another path.
- **Editing an old Telegram message no longer runs its command again.**
- **The first-run wizard now needs a one-time setup token, so a stranger can no longer take a fresh
  install.** Before, anyone reaching the port before the first admin existed could become
  superadmin (root on the panel's host) and join the host to their tailnet. The installer prints the
  wizard link with its token; `manage.py setup-token` or `sudo linuxgsm-panel-recover setup-token`
  prints it again. An install that is already set up is unaffected.
- **The wizard's last page no longer calls a panel that is still public "Private tailnet".** The new
  bind applies only from the next start, so the page now says where the panel still answers and
  offers **Restart now**; nothing restarts on its own.
- **The setup wizard's own steps are on the audit log.** That includes creating the first
  superadmin, the bind settings, a host added, finishing, **Restart now** and the Tailscale Serve it
  sets up.
- **Tailscale migrate and finalize refuse the panel's own host**, like the other Tailscale actions
  on the Hosts page.
- **`trust_proxy` believes `X-Forwarded-For` only from the proxy.** Before, a client reaching the
  panel directly or any local account on its host could dodge the login throttle and steer fail2ban
  bans. **If your proxy is on another machine or in a Docker bridge network, add its address to
  `trusted_proxies` in `data/config.json`**; until then every client shares the proxy's login
  throttle, and the log says `ignoring X-Forwarded-For from <address>`.
- **An IPv6 zone id no longer passes as an address.** Text after `%` let a delegated admin with
  **Manage remotes** write lines into a remote host's root-owned sshd or `ssh.socket` drop-in, or
  pass text to `fail2ban-client` as root through **Unban**. A whitelist entry stored with a zone
  still exempts its address from the auto-block, but fail2ban skips it only once you remove it and
  re-add the address without the `%zone`.
- **A `"*"` in `socketio_cors_origins` is ignored.** It let a same-site page open the console and
  terminal as whoever visited it. If you had set it, set `site_domain` or list the exact origin.
- **Usernames and group names cannot carry control or format characters.** Such characters could
  act in the root-run recovery CLI; it now shows them as visible escapes, so older names are safe.
- **The chat bots' `!update` can no longer hold every self-update at "still being verified".**
  Chat-triggered checks are limited to ten an hour across both bots, so GitHub's rate limit is not
  spent.
- **The post-restart "update complete" message goes only to a channel that is still authorised.**
- **The terminal's input queue is counted, not re-summed on every keystroke**, and dropped input is
  reported once a second.
- **A delegated group admin can edit or delete only a group wholly within their reach.** An admin
  scoped to one host could give other tenants' accounts a shell, including through "Everyone". On an
  install with more than one tenant, a delegated admin can no longer edit "Everyone", or their own
  group if someone else in it reaches more than they do.
- **An invite no longer outlives its minter, or its expiry, while its form is in flight.** Holding
  the request body back while the minter was demoted, or the invite expired, could still create the
  account, superadmin included.
- **A signed-in request is authorized once its body has arrived, not before.** Before, a revoked
  token, deactivated account or removed permission still let an action run if its body was held
  back.
- **A delegated log viewer sees the rows about their own servers and hosts, chosen by id, not by
  name.** Matching by name let a viewer read another tenant's rows, including console commands with
  arguments. **On upgrade**, old rows get an id only where exactly one server or host has that name;
  the rest stay visible to whoever did the action and to superadmins.
- **A host's SSH key is pinned from the first connection, whichever part of the panel makes it.** A
  pin from a background check was never saved, so later connections trusted whatever answered.
- **Changing a host's SSH port checks that sshd is what answers on the new port.** Anything but
  root's sshd listening on the new port now reverts the move, and fail2ban's sshd jail follows the
  port once the move is confirmed. Two port changes for one host at once are refused. **Re-run
  `install.sh` to update the privileged helper**; an older helper keeps the move and says it could
  not confirm sshd.
- **The firewall touches only the rules a game server owns.** Uninstall and "Open all ports" no
  longer delete or replace another server's or an operator's rules, and no port is opened on SSH,
  the panel's web port or another server's reserved block. "Open all ports" now needs **Manage
  Remotes** for that host.
  - Uninstall removes only ALLOW rules tagged with the server's name (untagged ones only where no
    other server's block holds the port), retries if the rule numbers shift, and names any rule
    still on the server's ports that it left in place, such as a DENY, LIMIT or rate limit.
  - "Open all ports" no longer says a port is open while a DENY still blocks it.
  - An install holds back a port something else started using while it downloaded, and an
    unreadable port scan no longer counts as "every port is free".
- **Root `apt` installs only the packages LinuxGSM lists for the game.** A package is installed as
  root only when LinuxGSM's published dependency list for that game and distro names it (at the
  account's release or the current one), the panel's common set does, or it is `steamcmd`; anything
  else is refused and logged.
- **A refused SSH connection is now closed.** A connection that fails its host-key check, login or
  any other step, including from "Test connection", no longer leaves its thread and socket open.
- **A new server or host no longer inherits a deleted one's state when SQLite reuses its id.**
  Console backlog, jobs, cached OS-update lists and alert counts are dropped when a row is deleted
  or created, and a host bootstrap whose id was taken mid-run no longer writes onto the new host.
- **A deleted host, game server, user or group's id is no longer given to the next one, and work
  still running for a deleted row no longer lands on the row that took its id.** These tables now
  never reuse an id; an existing install's tables are rebuilt once at the first start after the
  update, keeping every row and id. Installs, actions, backups, monitoring, auto-block and open
  terminals no longer act on a row that took a deleted one's id.
- **Unbounded reads and rows are capped.**
  - The fail2ban log read stops at 8 MB; a tally cut short shows as unread.
  - Console backlog lines stay under 2048 characters and the backlog under 256 KB.
  - Audit columns are capped at their declared size, and the detail at 8 KB.
  - The Ubuntu Pro endpoint refuses an unknown service or action before running anything.
- **Changing the panel's own port audits what really happened.** It no longer records success when
  the firewall or fail2ban step failed, and a failed restart gets its own row.
- **A game server's account name can no longer carry a command** (GHSA-hh39-76g3-wxcx, reported
  by kta1kri). A server
  account or script name in the database (old database, hand edit, restored backup) could run a
  command as the panel's account or the SSH login. Such names are now refused before anything is
  sent, and a panel backup holding one, or a port stored as text, is refused. Also closed:
  - The live console's log reads now check the script name too.
  - The backup check can no longer be sidestepped by name case, triggers, views, computed columns
    or a failing integrity check.
  - The restart-when-empty cron line refuses a port that is not a number.
  - A Tailscale host's stored SSH login can no longer become an `ssh` option, and the host form
    refuses an address beginning with a dash.
- **pip itself is hash-locked.** The installer now installs pip from the hash-locked
  `requirements-bootstrap.txt` instead of whatever PyPI serves. An update pinned to an older commit
  without that file keeps the venv's existing pip.
- **The Codacy token is no longer readable by a workflow on any branch.** The coverage upload now
  runs in its own `codacy-coverage.yml` workflow from main's copy, in a `codacy` environment, and
  refuses a report declaring a DTD or entity. The three repository settings it needs are listed in
  that file's header.
- **The code-scanning gate judges main only for a run that was exactly main's.** A branch `Main` or
  a tag `main` is no longer judged as main.
- **A compromised panel can no longer send root back to an old commit, or choose the branch root
  installs from.** On a root install, root keeps a never-lowered source floor in
  `/usr/local/lib/linuxgsm-panel/.source-floor` and refuses older commits, as does the auto-deploy.
  A panel-started update takes root's pieces from main only; to test a branch as root, run
  `cd / && sudo PANEL_BRANCH=<branch> bash /usr/local/lib/linuxgsm-panel/install.sh`. Installs run
  as a normal user are unchanged.
- **A tag named like a branch can no longer stand in for it, and a commit main only reached
  through a merge no longer counts as main.** The installer and panel name main's branch in full,
  so a tag called `origin/main` or `main` is never used.
  - Only a commit on main's first-parent line is offered, accepted as a pin or deployed.
  - An update never moves a checkout backwards or sideways; a hold says "Not updated: held at …,
    because …". A pin the installer cannot verify is no longer replaced by main's tip.
  - The CI auto-deploy requires the ref name to be exactly `main` and logs in to Tailscale with
    OIDC instead of a stored secret.
- **The panel's Python dependencies are installed by hash.** `requirements.txt` is now a lockfile
  with the same 33 versions and their hashes; pip refuses any download that does not match.
  Packages already installed are kept.
- **Preparing a remote host no longer runs NodeSource's setup script as root.** Only the signing key
  is downloaded, trusted only with the pinned fingerprint, and nothing downloaded is executed.
  npm is installed only when Node.js 18+ is present.
- **gamedig is installed from a hash-locked lockfile, and root no longer fetches it every week.**
  gamedig 5.3.3 installs with `npm ci` into `/usr/local/lib/linuxgsm-panel/gamedig` on every host,
  and a failed download keeps the working copy. The weekly cron fetches nothing while it is in
  place.
- **A ban now closes what the banned address already had open.** Live consoles and host terminals
  opened before the ban are disconnected. Whitelisted addresses and tailnet peers are left alone.
- **API-token guessing reaches fail2ban.** Once the token throttle refuses an address (20 misses in
  5 minutes), further attempts are logged for the panel-login jail; individual misses are not.
- **The whitelist protects every jail on the panel's own host.** A whitelisted admin can no longer
  be banned from SSH on the panel's host. The drop-in is not created for an empty whitelist, so a
  `[DEFAULT] ignoreip` you set yourself is kept.
- **Tailscale peers are never banned from the panel login.** The panel's own login throttle still
  applies to them.
- **Values written into page scripts are JSON-escaped throughout**. None of the values that were
  HTML-escaped instead was exploitable.
- **A client banned for failed logins is refused when it arrives through Tailscale Funnel.** A
  proxied request from a client on fail2ban's or UFW's ban list gets a bare `403`; the whitelist and
  tailnet peers are never refused. On a dual-stack `::` bind, Serve and Funnel sessions may be
  signed out once after the update.
  `X-Forwarded-Prefix` is now believed only under `trust_proxy`, so a proxy on the same host that
  mounts the panel under a sub-path must set it (the documented nginx and Caddy setups do).
- **The game-account group cannot be used to reach root.** An account is enrolled only when it
  definitely cannot `sudo`; members of `docker`, `lxd` and `disk` are refused, and a sudoers rule
  for `ALL` users is refused with a message to narrow it.
- **A compromised panel account can no longer choose what root runs.** On a root install, root
  stages the helper, installer and recovery command from its own clone or an operator's root-owned
  tree, never the panel-owned checkout, and an unfamiliar `origin` withholds them and says so.
- **Secrets the panel cannot read, or should not expose.** With a mismatched `cred_key`, backups are
  refused rather than written unencrypted, and a host-key pin reads "unreadable (cred_key mismatch)"
  instead of accepting any key. The Ubuntu Pro token and Tailscale auth key travel on stdin.
- **SSH hardening takes effect on cloud images.** It is now written to `00-panel-hardening.conf`,
  which sshd reads first, so a cloud-init drop-in no longer overrides it.
- **The weekly root cron no longer upgrades npm**, and no longer installs from the registry: it
  re-runs the hash-locked gamedig install. On the panel host, NodeSource's repository is set up with
  its signing key pinned.
- **Auto-block cannot cut off your tailnet, or take over your own rules.** Tailnet addresses stay
  exempt when the Tailscale probe fails, and an operator's own `ufw deny` is no longer replaced or
  released. IPv6 offenders can now be blocked.
- **Hostile input can no longer freeze the panel.** Crafted `?next=` values, logins, silent or
  flooding remote hosts, hostile cron journal lines and costly backup headers can no longer stall
  it.
  Transitive Python dependencies are pinned too.
- **A delegated admin can no longer take over an account that reaches more than they do.** An admin
  may administer only accounts whose permissions and hosts are a subset of their own, and can add
  only password-auth hosts. Changing a host's address, user or auth needs the new password.
- **Delegated admins and viewers see only what they can reach.** Pages and APIs show only the hosts
  and servers within their grants, and a delegated viewer of the audit log sees only their own rows
  and those about servers and hosts they can access.
- **Session protection is enforced.** A session is bound to its client's address and User-Agent.
  Toggling a phone browser's "Request desktop site" signs you out; choose `basic` in Settings if
  that gets in the way.
- **The privileged helper no longer follows links, or accepts content the panel does not write.**
  Root no longer follows planted symlinks, and its file and cron writes accept only allowlisted
  content. These reach a host when `install.sh` runs as root.
- **A game server can no longer be pointed at an account that is not its own.** A server can no
  longer make root delete the panel's own home, an install can no longer take over an existing
  account (`root` included), and an import accepts only an account the scan found.
- **The login throttle can no longer be dodged by choosing a header.** The client address is now
  the last `X-Forwarded-For` hop, or `X-Real-IP` when there is none; the README's nginx example sets
  both headers. Behind a proxy the panel-login ban covers every port.
- **Session cookies and the console socket are tied to the right origin.** Cookies are `Secure`
  behind a reverse proxy. The console and terminal socket accept only the panel's own origin or
  `site_domain`, so a proxy that rewrites `Host` to loopback and forwards no host needs
  `site_domain` set.
- **The setup wizard cannot be finished, or reopened, by someone else.** Completing setup now
  requires a superadmin, the wizard no longer stays open once the admin account exists, and the
  bind address is checked.
- **Two-factor authentication is harder to get around.** Turning 2FA off needs a current or backup
  code, and generating an API token asks for the password (and a code with 2FA on). A password
  change or "sign out everywhere" now revokes API tokens.
- **Routes and sockets that did more than their permission allowed.**
  - A custom command's `argument_pattern` is enforced; patterns over 200 characters are refused.
  - `playerlist?console=1` needs console permission; the Tailscale install, up and serve endpoints
    and the install-wide whitelist and auto-block threshold need superadmin.
  - Opening a game port needs "manage remotes" and a port a game server on that host uses.
  - Console access is re-checked every poll, so a revoked viewer stops watching.
- **What players type can no longer steer moderation or Discord.** A player name can no longer get
  someone else banned or kicked, or blank the player list, and Discord replies no longer ping from
  player names or console text.
- **Stored values can no longer change where or how a command runs.** A host's `auth_method` is
  checked, so a forged `local` cannot send its commands to the panel's machine, and validators no
  longer accept a trailing newline.
- **`linuxgsm-panel-recover` picks the right install, or asks.** With more than one install it
  refuses and names them; pass `PANEL_DIR=` to choose. It prints which install it uses first.
- **Smaller hardening.** Fixed: unvalidated Tailscale Serve mounts, ssh control sockets in a shared
  `/tmp` directory, a remote host's `uptime` rendered as markup, forged host-discovery records, a
  delete guard that could climb out of `lgsm/`, and an unchecked game-user name in live metrics.
- **CSRF could be skipped by sending an `Authorization: Bearer` header.** A request carrying both
  that header and a session cookie no longer skips CSRF. It was not reachable from a browser.
- **A compromised remote host could inject markup into the panel.** Its `tailscale status --json`
  values, migrate addresses and live CPU figures are now escaped. The CSP kept it from running
  script.
- **`X-Forwarded-Prefix` was trusted from any client.** It is now believed only from loopback
  (where Tailscale Serve sits) or when `trust_proxy` is set.
- **The rolling database backup was left world-readable.** `data/panel.db.backup` and
  `panel.db.corrupt-*` copies, which hold every password hash and credential, are now locked down
  like the rest of `data/` (itself already `0700`).
- **The self-signed TLS private key was written at the process umask, then chmodded.** It is now
  created `0600`, so it is never readable in between.
- **The sudoers grant is no longer `NOPASSWD:ALL`.** Once all three root-owned pieces are present,
  `/etc/sudoers.d/linuxgsm-panel` permits only the privileged helper. A host running new code that
  has not had `install.sh` re-run as root keeps the wide grant; the installer prints which it wrote.
- **`tailscale up` on the panel's own host wrote root's output to `/tmp`.** It now writes to the
  root-owned `/run/panel-tailscale-up.log`, so a local user cannot redirect what root writes.
- **A missing `data/config.json` reopened four unauthenticated setup endpoints.** A deleted or
  corrupt config file on a configured panel unlocked the setup wizard's Tailscale endpoints to
  anyone who could reach the port. They now use the wizard's own database-only lock.
- **Three VPS-preparation actions could be aimed at the panel's own host.** The *Prepare* and
  *Tailscale* routes now refuse the local host with a JSON 400 that says why.
- **The privileged helper carries every local escalation.** Local root work goes through
  `tools/panel-helper`, which validates each argument and runs a fixed command with no shell. See
  SECURITY.md.

- **The panel could not hear its own deprecation warnings.** Only eventlet's banner is silenced
  now, so `-W` and `PYTHONWARNINGS` work again.

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

[Since 0.10.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/compare/v0.10.0-alpha...main
[0.10.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.10.0-alpha
[0.9.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.9.0-alpha
[0.8.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.8.0-alpha
