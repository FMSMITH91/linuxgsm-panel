# Add-ons

A game server's **Files & Config → Add-ons** tab (with `manage_addons`) installs admin tools that run beside the game.
Each runs in a **rootless Podman container as the server's own account**, and inside the container it runs as that
account's own user and group too, never as root there. There is no root daemon and no Docker socket. The container
has:

- no added capability and no new privileges;
- a read-only system, a 1 GB memory cap and a 512-process cap;
- the game's log folder mounted read-only;
- a web page, when the add-on has one, listening on `127.0.0.1` only. Reach it with an SSH tunnel
  (`ssh -L <port>:127.0.0.1:<port>`) or over Tailscale.

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

An installed B3 has a folded **B3 settings** section on its row: **Apply and restart** rewrites only these, in
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
  3. press **Apply and restart**.

  Turned off again, the folder is no longer mounted and B3 looks in its own (empty) one; its files stay, and B3
  logs that it could not load a plugin still listed in `[plugins]`. Apply sets `external_plugins_dir` in `[b3]`.

IP Geolocation by DB-IP (<https://db-ip.com>), licensed under CC BY 4.0.

### Updates

The card shows **Update available** when the panel's pinned version is newer than the installed one (a new
IW4MAdmin image digest or B3 commit), or, for an offline B3, when a newer month of the country database is out.
**Update** downloads or builds the new image, writes the unit again and restarts the add-on; its data, settings
and database are kept. It asks for the password like Install, and it is audited. A start, Apply or Update you ask
for clears the unit's start limit first (5 starts in 10 minutes, kept against a crash loop), so a run of changes
doesn't leave the add-on down; if systemd still refuses a start for that limit, the card says so. The panel's pins themselves are
proposed daily by Renovate (B3's fork `master`, IW4MAdmin's `latest` digest).

## Network

An add-on reaches only the game's RCON port (UDP, or TCP for a Source game) and its database. A database on another machine, and B3's geolocation,
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
from that start on (a B3 that stops while reading `b3.ini` says why only there). Install and remove ask for the password when the sign-in is older than the confirmation window.
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
