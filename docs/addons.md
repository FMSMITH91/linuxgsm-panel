# Add-ons

A game server's **Files & Config → Add-ons** tab (with `manage_addons`) installs admin tools that run beside the game.
Each runs in a **rootless Podman container as the server's own account**, and inside the container it runs as that
account's own user and group too, never as root there. There is no root daemon and no Docker socket. The container
has:

- no added capability and no new privileges;
- a read-only system, a 1 GB memory cap and a 512-process cap;
- the game's log folder mounted read-only;
- a web page, when the add-on has one, listening on `127.0.0.1` only; no port is opened for it. The card's
  **Open** shows it through the panel (see [Web pages](#web-pages)).

## The add-ons

- **IW4MAdmin** (Call of Duty 4 / CoD4x and World at War): the image its author publishes
  (`ghcr.io/raidmax/iw4madmin`), pinned by digest. Before the first start the panel writes its settings: this server
  on `127.0.0.1`, the RCON password from the server's config, and the game log. It keeps its own SQLite database in
  its folder, so it needs no Databases-tab database. Its anti-cheat and profanity plugins start off.
- **B3** (Call of Duty, United Offensive, Call of Duty 2, Call of Duty 4 / CoD4x, World at War, Soldier of
  Fortune 2, Wolfenstein: Enemy Territory, ET: Legacy and Quake 3 Arena): **legacy and opt-in.** It's built on the
  host from one pinned commit of FMSMITH91/big-brother-bot, with hash-pinned dependencies, and it needs one of the
  server's own databases from the Databases tab. On Soldier of Fortune 2, Enemy Territory and ET: Legacy B3 has no
  private messages: every reply is said in public chat.

- **BlueMap** (Minecraft Java: LinuxGSM's vanilla `mcserver` and Paper `pmcserver`): a live 3D map of the
  world on a web page, from the image its author publishes (`ghcr.io/bluemap-minecraft/bluemap`), pinned by
  digest (its `v5` tag). Not for LinuxGSM's Velocity and Waterfall proxies (they have no world) or Bedrock
  (BlueMap reads Java worlds only). See [BlueMap](#bluemap) below.

### B3 on Enemy Territory, ET: Legacy and Quake 3

An earlier B3 never recognised human players on these three: it asked the server about a player by slot number
(`dumpuser <slot>`), and these servers' `dumpuser` only takes a player's name, so no player was authenticated and B3
refused them every command. The pinned B3 asks by the player's name (colour codes removed), and a test on real
servers saw joining players recognised on all three, names with colour codes and spaces included. Two players with
the same name can't be told apart that way: B3 asks by slot for them, the server doesn't answer, and neither is
recognised until one renames.

- **Wolfenstein: Enemy Territory** (B3's `et` parser): RCON `rconpassword`, the log
  `serverfiles/etmain/etserver.log`. LinuxGSM's config sets `set g_logsync 0`, so the game buffers its log and B3
  sees joins, chat and kills late (a join in a test showed up only when the server stopped): change it to
  `set g_logsync 1` in `serverfiles/etmain/wetserver.cfg` and restart the server. LinuxGSM's start command passes
  no port, so the server must be running when you install, and the add-on reads the port it really listens on.
- **Quake 3 Arena** (B3's `q3` parser): RCON `rconpassword`, the log `~/.q3a/baseq3/games.log` (the game's default
  `g_log` under its home path). LinuxGSM's config doesn't set `g_logSync`, and the game's default is 0, so the log
  is buffered and B3 sees events late: add `set g_logsync 1` to `serverfiles/baseq3/q3server.cfg`. The server reads
  that config only after its first map has opened the log, so after each server start the log stays buffered until
  the map changes or restarts (`map_restart 0` over RCON).
- **ET: Legacy** (B3's `et` parser, as for Enemy Territory): RCON `rconpassword`. ET: Legacy writes a game log only
  when `g_log` names one, and LinuxGSM's config doesn't set it, so add it yourself: in the server's config
  (`serverfiles/etmain/etlserver.cfg`), put `set g_log "etserver.log"` **below** the line `exec legacy.cfg` (ET:
  Legacy's own `legacy.cfg` sets `g_log ""`, so a line above it is undone), then restart the server. The log is
  written to `serverfiles/legacy/`. The panel doesn't change your config: until the log is there, the install says
  what to set. Use a plain file name (no folder). If you rename the log later, B3 keeps reading the old one: change
  `game_log` in its `Data/b3.ini` to match and restart it. As on Enemy Territory, the server must be running when
  you install, so the add-on reads the port it really listens on. ET: Legacy's own `legacy.cfg` already sets
  `g_logSync "1"`, so its log is not buffered.

### More games for B3

Counter-Strike: Global Offensive and Insurgency are built in and switched off until each has been tested against
LinuxGSM's own server (until then the Add-ons tab doesn't offer B3 for them). A game that is switched on joins the
list above and the card's legacy warning.

- **Counter-Strike: Global Offensive** and **Insurgency** (B3's `csgo` and `insurgency` parsers): B3 needs
  SourceMod on the server (install Metamod: Source and SourceMod with LinuxGSM's `mods-install`), and reads
  `console.log`, which the server writes only when its start parameters (the LinuxGSM config's `startparameters`)
  include `-condebug`. RCON is `rcon_password` in the server's config, over TCP on the game port. The install
  says which of these is missing.

Not offered:

- **Arma 3**: B3's `arma3` parser gets everything over BattlEye RCon, whose password and port live in BattlEye's
  own config file. LinuxGSM's `arma3server` neither writes that file nor names its folder (`bepath` is empty), so
  nothing on the host says where B3 would reach it.
- **Chivalry: Medieval Warfare**: B3's `chiv` parser talks to the game's own RCON over TCP; LinuxGSM's
  `PCServer-UDKGame.ini` sets an admin password but no RCON port, so nothing on the host says where it listens.

### B3's settings

An installed B3 has a folded **B3 settings** section on its row: **Apply** rewrites only these, in
`b3.ini` and `conf/plugin_geolocation.ini`, and keeps every other edit you made there and in `conf/`.

- **Geolocation**, off by default:
  - **Offline: country.** B3 looks each player's country up in DB-IP's free "IP to Country Lite" database, in the
    add-on's `geoip` folder (read-only inside the container). No player address leaves the host. The panel's host
    downloads the database from db-ip.com once a month, checks it against the SHA1 that db-ip.com publishes (of the
    unpacked database), and keeps it for the month. Turn the download off in Settings → Outside services →
    *Country database for B3*; B3 then keeps the copy it has, the card says the download is off, and no update for
    a newer month is offered. Geolocation Off downloads nothing.
  - **Online: city.** Each joining player's IP address goes to ipwho.is, through a relay (the only service the
    container can reach for it).
- **Plugins**: B3's own plugins that work on these games. Admin is always on. Never offered: adv (an internet
  feed), censor, punkbuster, translator (Google's service), banlist and the ftpytail plugins (they fetch from other
  machines, which the container can't reach), and other games' plugins.

- **My own plugins**, off by default: B3 also loads plugins from the add-on's `Data/extplugins` folder. A plugin
  there is someone else's code: it runs inside B3's container with B3's database and RCON access, and the panel
  doesn't check it. Turning this on asks once more, then for the password like Install, and it is audited. The
  folder is mounted read-only (B3 can't change the code it loads), and the container keeps its other limits. To
  add a plugin:
  1. copy its `.py` file (or its folder) and its `.ini` into `Data/extplugins` in the add-on's folder
     (`~/panel-addons/b3/` in the server's home);
  2. add its line under `[plugins]` in `Data/b3.ini`, for example `myplugin: @conf/extplugins/plugin_myplugin.ini`;
  3. press **Apply**.

  Turned off again, the folder is no longer mounted and B3 looks in its own (empty) one; its files stay, and B3
  logs that it could not load a plugin still listed in `[plugins]`. Apply sets `external_plugins_dir` in `[b3]`.

- **Panel actions**, off by default: lets the B3 players section unban, kick and warn through B3 itself
  (see below). Apply writes `control_socket: @conf/b3.sock` in `[b3]`: B3 then opens a Unix socket in its folder
  (`Data/b3.sock`, mode 0600, and B3 checks that the caller is its own account); turned off, the line is removed and
  B3 opens none. No network port is opened.
- **Forget earlier names and IP addresses not seen for (days)**, empty by default (B3 keeps them for good): B3's
  `purge_aliases_days`. B3 deletes a player's earlier names and addresses (its `aliases` and `ipaliases` tables) not
  seen for that many days, at its start and every day at 04:17; each player's last name and address, and their
  penalties, are kept. A whole number from 1 to 3650. OWASP's Logging Cheat Sheet ("Disposal of logs") sets no
  number of days: keep personal data only as long as you need it (365 is an example).

**Apply** first has B3 check the new settings (`b3_run.py --check-config`, in the image that will run, with the new
files copied into a folder of their own and mounted read-only, in a container with no network): if B3 refuses them,
nothing is changed or restarted and the card shows B3's first `ERROR:` line. When only plugin settings changed (the
same `b3.ini`, geolocation mode and own-plugins folder), B3 reloads its plugins' settings without a restart (through
its control socket when Panel actions is on, else `SIGHUP`), and the card names any plugin that kept its previous
settings. Anything else, or a `b3.ini` edited by hand since B3 started, restarts it.

IP Geolocation by DB-IP (<https://db-ip.com>), licensed under CC BY 4.0.

### What B3's card shows

- **Health**, from the `health.json` B3 rewrites every `health_interval` seconds (60 by default): whether B3 is
  healthy (or its own reason why not), whether it reads the game log, whether RCON works, whether its database is
  connected, and the players on the server. A file older than two intervals while B3 runs reads "B3 is not
  answering". When the file can't be read, the card shows no health line rather than a guess.
- **Why it stopped**: B3's exit code in words (220 an error, 221 its own `!restart`, 222 an admin's `!die`, 223 an
  error while starting, 230 invalid settings, 231 the game log unreadable, 232 RCON, 233 the database unreachable at
  start). B3 isn't started again after 222 or 230 (`RestartPreventExitStatus`): no restart can mend those. After 233
  it is, every 30 seconds.
- **Its version**: what B3 says it runs (its release and commit), else the panel's pin, with the commit.
- **Alerts for its bans and kicks** (off by default, per server): when B3 bans, temporarily bans or kicks a player,
  the panel's alert channels (Settings → Notifications) say so, while their **B3 penalties** event is on. The
  panel reads what B3 added to its `events.jsonl` once a minute (one read as the game account, only for servers with
  the switch on, following B3's rotation to `events.jsonl.1`); what B3 wrote before the switch was turned on, or while
  the panel was down, isn't sent. Players' and admins' names are personal data: they are in an alert only when
  **Include details** is on in Notifications, and the panel never writes them to its own log. More than three in one
  minute come as one count.

### BlueMap

BlueMap's command-line build renders the world, keeps watching it for changes, and serves the map (`-r -u -w`).

- **Mojang's EULA.** BlueMap textures the map from Minecraft's client file of the world's version, which it
  may use only once you accept Mojang's EULA (<https://www.minecraft.net/eula>; BlueMap's own setting is
  `accept-download` in `core.conf`). The install shows the link and a box to tick; without it the install is
  refused, since BlueMap can't render anything without that file. The audit log records who accepted it and
  when (the install's entry), and so do the add-on's `addon.json` and a comment in its `core.conf`.
- **The client file.** The container reaches no network at all, so the panel fetches the file for it: the
  panel's host reads Mojang's version list (`piston-meta.mojang.com`, the version's details checked against
  the list's SHA-1), and the game's host downloads the client jar (`piston-data.mojang.com`, about 30 MB)
  into the add-on's `data` folder and checks the SHA-1 Mojang publishes for it. BlueMap then starts with
  that version (`-v`); its own attempt to reach Mojang fails, and it uses the file it was given.
- **The world, read-only.** The world is the folder `level-name` in `serverfiles/server.properties` names
  (`world` when unset). It is mounted read-only, and so are Paper's `<level-name>_nether` and
  `<level-name>_the_end` beside it when the server keeps them there (vanilla and current Paper keep the
  nether and the end inside the world). The map has three maps: Overworld, Nether (its ceiling cut away)
  and End. The `level-name` must be letters, digits and `. _ + -` (it goes into the unit file). The
  server must have been started once, so the world exists. A world moved elsewhere by start parameters
  or by Paper's `world-container` isn't found, and the install says so.
- **The game's version, and a game update.** The version is the one the server logged at its last start
  (`Starting minecraft server version …` in `serverfiles/logs/latest.log`). One BlueMap build reads worlds
  of Minecraft 1.13.2 to 26.3 (release 5.29). After you update the game to another version, the card shows
  **Update available**; Update fetches that version's client file and restarts BlueMap with it. A game
  version newer than the pinned BlueMap supports waits for the panel's next BlueMap pin (BlueMap's log says
  what it can't read).
- **The web page.** It listens on `127.0.0.1:<port>` on the game's host only; nothing is opened in any
  firewall. **Open** on the card shows the map through the panel (see [Web pages](#web-pages)), for users
  with *View add-on pages* or *Manage add-ons* (each given to no group by default). The page holds no
  personal data: BlueMap's command-line build has no connection to the game, so the map shows no players,
  and its web server keeps no access log. Its usage report (`metrics`) is off. Shown through the panel,
  the map keeps no settings between visits (BlueMap's own setting `useCookies` is turned off on the way,
  since the page can't use the browser's storage there).
- **Resource use.** Rendering is CPU and disk heavy. BlueMap renders with one thread (its own default),
  and the container runs at a lower CPU priority than the game (`Nice=10`) with the add-ons' 1 GB memory
  cap (Java gets 60% of it). The first render of a big world can take a long time; after it, only changed regions
  are rendered again. To render faster, raise `render-thread-count` in `config/core.conf` in the add-on's
  folder (`~/panel-addons/bluemap/`, at most the host's cores), then Stop and Start it on the card. The card
  shows how much disk the add-on's folder takes (the map, its settings and the client file).
- **Your edits.** The panel writes BlueMap's `core.conf`, `webserver.conf` and the three map files at
  install only: Update keeps your edits there. After a new BlueMap image, Update deletes `web/index.html`
  so the new version writes its own page (BlueMap's release notes ask for this).
- **Remove** deletes the add-on's whole folder: the rendered map, its settings and the client file. The
  world is never touched.

### Web pages

IW4MAdmin's webfront and BlueMap's map listen on the game host's `127.0.0.1` only. **Open** on the add-on's
card (shown while it is running) opens the page in a new tab, through the panel, from your phone as from a
desktop, for the panel's own host and for remote ones alike. No port is opened on any host or firewall, and
nothing changes in Tailscale.

- **Who.** *View add-on pages* (or *Manage add-ons*) and access to the server. With *View add-on pages*
  alone, the server's Add-ons tab lists only the installed add-ons that have a page, each with Open.
- **How it reaches the page.** Only `127.0.0.1:<port>` on that server's host, the port in the add-on's
  record when you pressed Open, checked to be in that server's range of add-on ports and listened on by the
  server's own account: a socket on the panel's own host, a forwarded channel on the panel's SSH
  connection to a remote host (`direct-tcpip`; the host's sshd must allow TCP forwarding, its default), or
  `ssh -W` for a Tailscale host. Never an address from the browser.
- **The link.** Open makes a link only for you, that server and that add-on (a random 256-bit value, kept
  by the panel only as its hash and never written to a log). It works while your sign-in does: signing
  out, a password change, "sign out everywhere", a removed permission or server access, or your session
  ending stops it on its next request (an open IW4MAdmin page within 30 seconds). It also ends after the
  panel's idle timeout without use, and at the panel's absolute sign-in limit after you opened it. The page
  sends no referrer. The address is in your browser's history; it is useless once it has ended.
- **Kept apart from the panel.** The page is the add-on's own HTML and script, so it runs in a sandbox
  (`Content-Security-Policy: sandbox allow-scripts allow-forms`, without `allow-same-origin`): the browser
  treats it as a site of its own, so it can't read the panel's cookies, storage or pages, and its requests
  carry no panel cookie. The panel's cookies, Authorization and forwarding headers are never passed to the
  add-on; the add-on's cookies (IW4MAdmin's own sign-in) are kept by the panel for that link and never
  reach your browser, and a `Clear-Site-Data` or framing header from it is dropped.
- **What it changes.** Addresses from the site's root in the page (IW4MAdmin's `<base href="/">`, its
  `/css/` and `/js/`) are put under the link's path, and a short script gives the page in-memory stand-ins
  for the browser storage a sandboxed page is refused. An address IW4MAdmin builds in its own script from
  the site's root can still miss; its pages and live updates use relative ones.
- **IW4MAdmin** takes one connection at a time (its own limit), so the panel sends it one request at a time;
  its live page uses a WebSocket, which the panel passes on (only for IW4MAdmin). Sign in to IW4MAdmin itself
  as before (its own accounts).
- **Opening is audited** (who, which server and add-on); so is a refused link (once per link).

### Updates

The card shows **Update available** when the panel's pinned version is newer than the installed one (a new
IW4MAdmin or BlueMap image digest or B3 commit), for an offline B3 when a newer month of the country database
is out, or for BlueMap when the game now runs another Minecraft version.
**Update** downloads or builds the new image, writes the unit again and restarts the add-on; its data, settings
and database are kept. It asks for the password like Install, and it is audited. A start, Apply or Update you ask
for clears the unit's start limit first (5 starts in 10 minutes, kept against a crash loop), so a run of changes
doesn't leave the add-on down; if systemd still refuses a start for that limit, the card says so. The panel's pins themselves are
proposed daily by Renovate (B3's fork `master`, IW4MAdmin's `latest` digest, BlueMap's `v5` digest).

### B3's players and penalties

An installed B3 has a **Players** button on its row. It opens a section that reads B3's own database (the one
from the Databases tab) and changes nothing:

- **Search** a player by the start of a name or of an earlier name (alias), by B3 id (`@12`), or by a whole GUID.
  Case and accents don't matter. Names are matched from their first letter: "nake" doesn't find "Snake".
- **Open** a player: B3 id, group, first and last seen, connections, aliases (up to 50), IP addresses (up to 50),
  and every warning, kick, ban and notice (up to 100) with its reason, the admin who gave it ("B3" for B3
  itself), when, how long, and whether it is active, expired or lifted.
- **Latest penalties** and **Bans only**: the newest warnings, kicks and bans first, 15 at a time (**Older** for the next 15); a search shows 15 players at a time too.
- **Unban**, **Kick** and **Warn**, on a player's view, while B3's **Panel actions** setting is on. B3 does them itself
  (its control socket), so its own records, its warnings' count and its in-game messages stay right. Unban lifts
  the player's active bans; Kick and Warn reach the player only while they are on the server: the panel finds their
  slot by the name B3 stored, in the game's own player list, and acts only when exactly one listed player has it.
  B3 answers which player it acted on, and the panel says so if the slot changed hands in between. A reason (at
  most 100 characters, no colour code) is optional except for a warning; B3 says it in the game.

Before anything else, every read checks the table layout B3 records in its `data` table (`b3_schema_version`):
only layout 1 is read; an older B3 that doesn't record it is asked to update first.

Who sees what: the section takes `manage_addons`, like the rest of the Add-ons tab. Unban also takes
`ban_player`, and Kick and Warn `kick_player` (or the `moderate_server` umbrella); each asks for the password when the
sign-in is older than the confirmation window, and each is in the audit log with the player's B3 id, the slot and
B3's answer, never the reason or a name. B3 records the panel user as the `actor` (`panel:<username>`) in its own
`b3.log` and `events.jsonl`. A player's IP addresses and
GUID are personal data, so they are shown only to someone who also holds `manage_databases` (who can already
read B3's tables in the Databases manager); for anyone else the panel doesn't read them, shows how many earlier
addresses there are, and searches a GUID only whole. Each search, player opened and penalties list is in the
audit log with the server: the player's B3 id and the kind of search, never the text searched for.

How it reads: the Databases manager's way, signed in as B3's database account, from where that database's other
commands run, in a read-only transaction: no port is opened, and the database refuses any write. Every
statement is fixed, with the search text as a bound value; a search uses only indexed columns, and every list is
capped. B3 makes its tables at its first start: until then the section says so.

The panel never changes B3's rows itself: that would leave B3's running state out of step. Its actions go through
B3.

## Network

An add-on reaches only the game's RCON port (UDP, or TCP for a Source game) and its database; BlueMap reaches
nothing at all. A database on another machine, and B3's geolocation,
go through relays on the host's loopback.

- **Ubuntu 26.04:** it reaches nothing else.
- **Ubuntu 24.04:** it can't reach the internet or other machines, but services listening on the host's own other
  addresses (such as its Tailscale address) stay reachable.

## Installing, checking, removing

Installing the first add-on on a host (Ubuntu 24.04 or newer):

- installs `podman`, `uidmap` and `passt` from Ubuntu;
- on the panel's own host, puts the server's account in the panel's game group (`lgsmpanel-games`) if it is not in
  it yet, with the same checks as any enrolment (an account that can reach root is refused);
- gives the account a range of subordinate ids if it has none;
- turns on lingering, so the account's user manager starts the add-on at boot.

A step that fails says why, with the host's own words after the panel's sentence (apt's, the helper's or
systemd's). An add-on that needs a database while the server has none free shows its Install button disabled,
with the reason beside it and an **Open Databases** button; when the host has no database server yet, the reason
says so, since the Databases tab sets one up first.

An install, Apply, Update or Start that stops again within 30 seconds is reported on the card and left stopped. The
card shows the lines it logged during that start: B3's `b3.log` if that start wrote to it, then the add-on's journal
from that start on (a B3 that stops while reading `b3.ini` says why only there). Install, Update, Apply (a settings change) and remove ask for the password when the sign-in is older than the
confirmation window.
Every install, start, stop and remove is audited.

Removing an add-on deletes its container, image, unit and files: for B3 that is its whole folder, its settings and
any plugin settings you edited included. Its database is kept. Removing the last one also
removes the account's Podman storage (its base images and Podman's own folders) and turns lingering off; the
account's own journal is kept. Uninstalling the server also deletes the account's user journal, and its tmux and
Java folders in `/tmp` (`/tmp/tmux-<uid>`, `/tmp/hsperfdata_<account>`), so an account later given the same user
id can't read the old add-ons' lines or inherit the old tmux socket folder. The add-on's folder is in the game account's home,
so the server's backups include it.

The add-on reads the RCON password the game itself reads: `rconpassword` for Call of Duty, United Offensive and
Soldier of Fortune 2, `rcon_password` for Call of Duty 2, 4 and World at War (the games with their own
section above say theirs).

The add-on reaches the game on the port the game really listens on, read from the server account's own listening
sockets at install, not only from the config (a game whose LinuxGSM start command passes no port, such as Enemy
Territory above, must be running when B3 is installed). LinuxGSM's default World at War config sets
`rconpassword`, which that game ignores; the install then asks you to rename it to `rcon_password` and restart
the server.

The game's log is found where the game writes it: `serverfiles` for Call of Duty 4 (LinuxGSM sets its home path
there), `~/.callofduty` for Call of Duty and United Offensive, `~/.callofduty2` for Call of Duty 2, `~/.codwaw`
for World at War and `~/.sof2/base/date` for Soldier of Fortune 2 (LinuxGSM's `g_log "date"`, which the game takes
as a file name).
