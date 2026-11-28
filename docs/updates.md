# Updates

**Updates** (in the sidebar, with a count) lists every update the panel knows is waiting, in one place:

| Group | What is listed | What it costs | When it happens by itself |
|---|---|---|---|
| Panel | A new signed panel release (with its changes) | The panel restarts: a few seconds. Game servers and websites keep running. | Never: press **Update now**. |
| Host system | Each host's OS packages, security ones counted apart | Services may restart; a kernel update needs a reboot | Security packages, where the host has automatic security updates on (the host's page says) |
| Game servers | A newer build of the game itself (a Steam build, a Minecraft release...), as LinuxGSM's `check-update` last read it: the installed and the available build, the Steam branch and the game's SteamDB history | Players are kicked: the server restarts (about as long as its last update took); nothing while the server is stopped | The nightly window, when automatic updates are on for it (the default depends on the game, below) and no players are on; a scheduled task of the server's that runs `update` instead, when its crontab has one |
| LinuxGSM | A server whose LinuxGSM is behind its latest release, with that release's notes | None: players stay on | A scheduled task of the server's that runs `update-lgsm`, when its crontab has one (the row says when, as the server's Scheduled tasks card last read it); otherwise press **Update now**, or add the task on that card. |
| Add-ons | An add-on whose image differs from the signed catalog's | The add-on restarts (about a minute); players stay on | The nightly window |
| Websites | A site with a newer image or new server settings from the panel (the row says what they change) | A few seconds offline; a few minutes first when its new image is built on the host | The nightly window |

Each row says what the update changes, what it costs, whether it is a **security update**, and when it installs by
itself. **Update now** runs the item's own update (the same as its own page's button, with the same password
confirmation where that asks for one); for the panel and a host's packages it opens that card, which asks you to
confirm. The pages that had their own Update buttons keep them, with a link here.

**Update everything safe now** updates, one at a time, every listed item that kicks no player and needs no reboot:
websites, add-ons on servers with no players on, and LinuxGSM. It asks for your password first. When nothing listed
is yours to run (a customer's sites, say), the button stays greyed with the reason beside it: nothing to update,
an item that kicks players or needs a reboot, a host's packages or the panel's update (they can restart services or
need a reboot, so their Update now opens their own page), or items their administrators or the nightly window update.
**Update now** leaves its row in place with the result.

Each row says when it updates by itself on its host's clock: tonight at the window's start, now (while the window
is open, until its end), or the next night once tonight's window has run.

The list is read from what the panel already knows (the daily OS check, the panel's update check, the daily game
check, what the server and add-on pages last read), so opening the page asks no host anything. Who sees what follows the existing
permissions: the panel and the panel host's packages a superadmin; another host's packages whoever may manage it; a
game server's game and its LinuxGSM whoever may update it; its add-ons whoever holds *Manage add-ons* on it; a website whoever may
see it. A customer sees only their own sites, and when each updates by itself.

## Game updates

**Where the row comes from.** Once a day per game server, staggered (one server every few minutes, the one checked
longest ago first), the panel runs LinuxGSM's `check-update`, which only reads the installed and the available build
and never stops the server. It skips a server the panel is already running something on (an update, a backup, a
wipe, a reboot, an install). **Check games now** on the page checks every server you may read, one at a time. The
server page's own *check-update* and *Update* feed the same row, so the two always agree.

**Update now** runs the server's own Update (LinuxGSM `update`, the same as the server page's button, with its
console output and history). It asks first, naming the server, with what it costs and, with players on, whether
they are warned first. With players on, on a game whose console has a chat
command (Source, GoldSrc, idTech3, Minecraft), the panel says "The server restarts in 1 minute to install a game
update." in the game and starts the update a minute later, unless LinuxGSM's own warning timer warns them already.
LinuxGSM only stops the server when the builds differ, and starts it again only if it was running.

**Update when empty** queues the update on the server: the same sweep that runs *Restart when empty* runs it once
the server has no players (or is stopped). The row then says it is queued, before any scheduled task or window.
**Don't wait** takes it off the queue.

**Automatic game updates** run in the nightly window, one server at a time, only with no players on (an unknown
count on a running server waits too); otherwise the next night. With **Back up first at night** on, the panel stops a
running server, backs it up (LinuxGSM's backup), updates it and starts it again: LinuxGSM's backup restarts a running
server by itself, and an update straight after would stop it while it is still starting. A failed step starts the
server again, is in the history, and sends the **Automatic update failed** alert. A server the window stopped and
could not start again has a history row saying it was left stopped, and why, and the alert says so too. Each start is
the dashboard's Start (its checks and history rows). A server whose own scheduled task
runs `update` is left to that task. The default, with its reason shown beside the switch:

| Game | Default | Why |
|---|---|---|
| Steam games (Garry's Mod, Counter-Strike, Rust, ...) | On | Players' Steam clients update themselves, and a server behind them refuses them. |
| Minecraft Java and Bedrock, and LinuxGSM's Paper, Velocity and Waterfall | Off | A new release can lock out players whose game is older, and break plugins and mods. The row shows the new version with a one-click update. |
| OpenRA, Vintage Story | Off | Players need the same release as the server, and a new one can break mods. |
| The other games LinuxGSM updates from their own releases (TeamSpeak 3, Factorio, FiveM, MTA, ...) | On | As OWASP recommends; switch it off if a release breaks your mods. |

LinuxGSM's output never says whether a game build is a security fix, so a game row is never marked as one.

## The nightly window

Websites, add-ons and games update by themselves between **04:00 and 05:00** on each host's own clock (before the
05:00 and 05:15 tasks the panel adds to a server it installs). A superadmin can change the window on the Updates page.
Automatic updates are **on** for every website and add-on by default; a game's default depends on the game (above).

- **One at a time.** The panel updates one item, waits for it to finish, then takes the next.
- **Busy items wait.** A website that answered visitors in the last few minutes (the web proxy still holds a
  connection to it) waits for the next night, and so does a site whose host did not answer the check. An add-on or a
  game whose server has players on waits too. The history says so, and the row then says it updates by itself the next
  night.
- **A failed update is undone.** A website is installed again from the image it ran before (still on the host), and
  an add-on gets back the settings record and unit it had and is started again. You get the **Automatic update
  failed** alert (Notifications), and the history says what happened. The next window tries again.
- **Security updates always go in.** When the signed catalog marks an image as a security update, it installs in the
  next window even for an item whose automatic updates are off. The row is marked *Security update*.
- **Off is allowed, with a warning.** Each website, add-on and game row has an *Automatic updates* switch (for whoever
  may update that item). The recommended value, on, is shown beside it. With a website or add-on off, the page keeps a
  warning listing the items that wait for someone to press Update now; a game row says why its default is what it is.

The recommendation is OWASP's: [Top 10 2025 A03 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures)
(which follows A06:2021 Vulnerable and Outdated Components) names not patching "in a risk-based, timely fashion" as
the weakness, and asks for a patch management process and staged rollouts instead of updating everything at once.

## History

The **History** fold lists the last 40 updates you may see: what, when, who started it (or *automatic*), and how it
ended (done, failed, waited for the next window, queued for when players leave). Each time is on the clock of the
host the update ran on, as the window's times are. A game update's end reads as one line (the build it installed,
when LinuxGSM printed it); its full output stays in the audit log. It is read from the audit log, so it shows the same
rows the Audit Logs page shows you.

## Marking a security update in the catalog

The signed add-on catalog (see [addons.md](addons.md#new-add-on-versions-without-a-panel-update)) may carry an
optional `security` section naming which of its pins are security updates:

```json
"security": {"addons": ["b3"], "sites": ["php", "wordpress"], "note": "OpenSSL fix in the base image"}
```

`addons` takes add-on ids, `sites` the parts of the `sites` section a website's image comes from (`static`, `php`,
`wordpress`, `runtimes`), and `note` one plain line shown beside those updates. Anything else is refused, by the
panels and by the signing tool alike, and a refused section marks nothing.

## Settings

`config.json` keeps the window and the switches under `auto_updates`: `{"start": "04:00", "end": "05:00", "off":
["website:3", "addon:7:b3"], "games": {"5": true}, "backup": ["5"]}` (`games`: a game server's switch where it was
changed from its default; `backup`: the servers backed up before their nightly game update). Change them on the
Updates page. What the daily game check read is kept in memory: after a panel restart the servers are checked again,
one every few minutes.
