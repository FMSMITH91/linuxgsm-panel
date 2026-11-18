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
- **B3** (Call of Duty, United Offensive, Call of Duty 2, Call of Duty 4 / CoD4x, World at War, Soldier of Fortune 2
  and Wolfenstein: Enemy Territory): **legacy and opt-in.** It's built on the host from one pinned commit of
  FMSMITH91/big-brother-bot, with hash-pinned dependencies, and it needs one of the server's own databases from the
  Databases tab. On Soldier of Fortune 2 and Enemy Territory B3 has no private messages: every reply is said in
  public chat.

### B3's settings

An installed B3 has a folded **B3 settings** section on its row: **Apply and restart** rewrites only these, in
`b3.ini` and `conf/plugin_geolocation.ini`, and keeps every other edit you made there and in `conf/`.

- **Geolocation**, off by default:
  - **Offline: country.** B3 looks each player's country up in DB-IP's free "IP to Country Lite" database, in the
    add-on's `geoip` folder (read-only inside the container). No player address leaves the host. The panel's host
    downloads the database from db-ip.com once a month, checks it against the SHA1 that db-ip.com publishes, and
    keeps it for the month. Turn the download off in Settings → Outside services → *Country database for B3*; B3
    then keeps the copy it has. Geolocation Off downloads nothing.
  - **Online: city.** Each joining player's IP address goes to ipwho.is, through a relay (the only service the
    container can reach for it).
- **Plugins**: B3's own plugins that work on these games. Admin is always on. Never offered: adv (an internet
  feed), censor, punkbuster, translator (Google's service), banlist and the ftpytail plugins (they fetch from other
  machines, which the container can't reach), and other games' plugins.

IP Geolocation by DB-IP (<https://db-ip.com>), licensed under CC BY 4.0.

### Updates

The card shows **Update available** when the panel's pinned version is newer than the installed one (a new
IW4MAdmin image digest or B3 commit), or, for an offline B3, when a newer month of the country database is out.
**Update** downloads or builds the new image, writes the unit again and restarts the add-on; its data, settings
and database are kept. It asks for the password like Install, and it is audited. The panel's pins themselves are
proposed daily by Renovate (B3's fork `master`, IW4MAdmin's `latest` digest).

## Network

An add-on reaches only the game's RCON port and its database. A database on another machine, and B3's geolocation,
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

An install that stops again within 30 seconds is reported with its last log lines and left stopped. Install and
remove ask for the password when the sign-in is older than the confirmation window. Every install, start, stop and
remove is audited.

Removing an add-on deletes its container, image, unit and files: for B3 that is its whole folder, its settings and
any plugin settings you edited included. Its database is kept. Removing the last one also
removes the account's Podman storage (its base images and Podman's own folders) and turns lingering off; the
account's own journal is kept. Uninstalling the server also deletes the account's user journal, so an account
later given the same user id can't read the old add-ons' lines. The add-on's folder is in the game account's home,
so the server's backups include it.

The add-on reads the RCON password the game itself reads: `rconpassword` for Call of Duty, United Offensive,
Soldier of Fortune 2 and Enemy Territory, `rcon_password` for Call of Duty 2, 4 and World at War.

The add-on reaches the game on the port the game really listens on, read from the server account's own listening
sockets at install, not only from the config. LinuxGSM's Enemy Territory start command passes no port, so the port
in its config may not apply (the server then listens on 27960): an ET server must be running when B3 is installed. LinuxGSM's default World at War config sets
`rconpassword`, which that game ignores; the install then asks you to rename it to `rcon_password` and restart
the server.

The game's log is found where the game writes it: `serverfiles` for Call of Duty 4 (LinuxGSM sets its home path
there), `~/.callofduty` for Call of Duty and United Offensive, `~/.callofduty2` for Call of Duty 2, `~/.codwaw`
for World at War, `~/.sof2/base/date` for Soldier of Fortune 2 (LinuxGSM's `g_log "date"`, which the game takes as
a file name) and `serverfiles/etmain/etserver.log` for Enemy Territory.
