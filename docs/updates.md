# Updates

**Updates** (in the sidebar, with a count) lists every update the panel knows is waiting, in one place:

| Group | What is listed | What it costs | When it happens by itself |
|---|---|---|---|
| Panel | A new signed panel release (with its changes) | The panel restarts: a few seconds. Game servers and websites keep running. | Never: press **Update now**. |
| Host system | Each host's OS packages, security ones counted apart | Services may restart; a kernel update needs a reboot | Security packages, where the host has automatic security updates on (the host's page says) |
| Game servers | A server whose LinuxGSM is behind its latest release, with that release's notes | None: players stay on | A scheduled task of the server's that runs `update-lgsm`, when its crontab has one (the row says when, as the server's Scheduled tasks card last read it); otherwise press **Update now**, or add the task on that card. |
| Add-ons | An add-on whose image differs from the signed catalog's | The add-on restarts (about a minute); players stay on | The nightly window |
| Websites | A site with a newer image or new server settings from the panel (the row says what they change) | A few seconds offline; a few minutes first when its new image is built on the host | The nightly window |

Each row says what the update changes, what it costs, whether it is a **security update**, and when it installs by
itself. **Update now** runs the item's own update (the same as its own page's button, with the same password
confirmation where that asks for one); for the panel and a host's packages it opens that card, which asks you to
confirm. The pages that had their own Update buttons keep them, with a link here.

**Update everything safe now** updates, one at a time, every listed item that kicks no player and needs no reboot:
websites, add-ons on servers with no players on, and LinuxGSM. It asks for your password first.

The list is read from what the panel already knows (the daily OS check, the panel's update check, what the server
and add-on pages last read), so opening the page asks no host anything. Who sees what follows the existing
permissions: the panel and the panel host's packages a superadmin; another host's packages whoever may manage it; a
game server's LinuxGSM whoever may update it; its add-ons whoever holds *Manage add-ons* on it; a website whoever may
see it. A customer sees only their own sites, and when each updates by itself.

## The nightly window

Websites and add-ons update by themselves between **04:00 and 05:00** on each host's own clock (before LinuxGSM's own
jobs at 05:00 and 05:15). A superadmin can change the window on the Updates page. Automatic updates are **on** for
every item by default.

- **One at a time.** The panel updates one item, waits for it to finish, then takes the next.
- **Busy items wait.** A website that answered visitors in the last few minutes (the web proxy still holds a
  connection to it) waits for the next night, and so does a site whose host did not answer the check. An add-on whose
  game server has players on waits too. The history says so.
- **A failed update is undone.** A website is installed again from the image it ran before (still on the host), and
  an add-on gets back the settings record and unit it had and is started again. You get the **Automatic update
  failed** alert (Notifications), and the history says what happened. The next window tries again.
- **Security updates always go in.** When the signed catalog marks an image as a security update, it installs in the
  next window even for an item whose automatic updates are off. The row is marked *Security update*.
- **Off is allowed, with a warning.** Each website and add-on row has an *Automatic updates* switch (for whoever may
  update that item). The recommended value, on, is shown beside it. With it off, the page keeps a warning listing the
  items that wait for someone to press Update now.

The recommendation is OWASP's: [Top 10 2025 A03 Software Supply Chain Failures](https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures)
(which follows A06:2021 Vulnerable and Outdated Components) names not patching "in a risk-based, timely fashion" as
the weakness, and asks for a patch management process and staged rollouts instead of updating everything at once.

## History

The **History** fold lists the last 40 updates you may see: what, when, who started it (or *automatic*), and how it
ended (done, failed, or waited for the next window). Each time is on the clock of the host the update ran on, as the
window's times are. It is read from the audit log, so it shows the same rows the Audit Logs page shows you.

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
["website:3", "addon:7:b3"]}`. Change them on the Updates page.
