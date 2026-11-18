# Add-ons

A game server's **Files & Config → Add-ons** tab (with `manage_addons`) installs admin tools that run beside the game.
Each runs in a **rootless Podman container as the server's own account**. There is no root daemon and no Docker
socket, and the container's root is that account. The container has:
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
- **B3** (Call of Duty, United Offensive, Call of Duty 2): **legacy and opt-in.** It's built on the host from one
  pinned commit of FMSMITH91/big-brother-bot, with hash-pinned dependencies, and it needs one of the server's own
  databases from the Databases tab. Geolocation is off by default. When it's on, players' IP addresses go to
  ipwho.is and ipapi.co.

## Network

An add-on reaches only the game's RCON port and its database. A database on another machine, and B3's geolocation,
go through relays on the host's loopback.
- **Ubuntu 26.04:** it reaches nothing else.
- **Ubuntu 24.04:** it can't reach the internet or other machines, but services listening on the host's own other
  addresses (such as its Tailscale address) stay reachable.

## Installing, checking, removing

Installing the first add-on on a host (Ubuntu 24.04 or newer):
- installs `podman`, `uidmap` and `passt` from Ubuntu;
- gives the account a range of subordinate ids if it has none;
- turns on lingering, so the account's user manager starts the add-on at boot.

An install that stops again within 30 seconds is reported with its last log lines and left stopped. Install and
remove ask for the password when the sign-in is older than the confirmation window. Every install, start, stop and
remove is audited.

Removing an add-on deletes its container, image, unit and files. Its database is kept. The add-on's folder is in the
game account's home, so the server's backups include it.
