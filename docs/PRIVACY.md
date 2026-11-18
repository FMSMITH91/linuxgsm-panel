# Privacy

What the LinuxGSM Panel keeps, for how long, and what leaves your server. The panel is software you
run yourself: there is no service behind it, no account to make, and nothing is sent to its authors.

## In short

- **Everything stays on your server.** The panel's data lives in `data/` on the host it runs on
  (`chmod 700`), and secrets in it are encrypted.
- **No telemetry, no analytics, no tracking.** The panel never reports usage, errors or anything else
  to anyone. Its pages load no third-party scripts, fonts or images: everything is served from the
  panel itself.
- **No e-mail.** The panel sends none.
- **Local first.** Where the panel can answer a question from your own server, it does; it asks an
  outside service only when it has to, and keeps working when that service does not answer.

## What the panel stores

| What | Why | Protected by |
| --- | --- | --- |
| Accounts: username, display name, group, e-mail if you enter one | Signing in, permissions | Password stored only as an Argon2id hash; e-mail, 2FA secret and linked Telegram chat encrypted (AES-256-GCM) |
| Sign-in sessions: when, from which address, which browser | "Sign out everywhere", spotting a stolen session | Address and browser text encrypted |
| Audit log: who changed what, when, from which address | Accountability; the sign-in attack counter | The address is reduced to its network (a /24 for IPv4, a /64 for IPv6) after `audit_ip_retention_days` (90 by default) |
| Remote hosts: address, SSH user, SSH password or key **path**, pinned host key | Managing them over SSH | Encrypted; an SSH key file stays where you keep it |
| Game servers, their settings and stats history (CPU, memory, players) | The dashboard and charts | Stats older than 14 days are deleted |
| Database logins for game databases | The Databases page | Encrypted |
| Alert devices (browser push subscriptions) and linked Telegram chats | Sending you your alerts | Encrypted; removed when you remove the device, unlink, or the account is deleted |
| Alert channel tokens (Telegram, Discord, ntfy) | Sending alerts | Encrypted |
| API tokens, 2FA backup codes, invite links | Signing in, inviting people | Stored only as hashes |
| The HTTPS certificate and its private key (`data/ssl`), your own or a Let's Encrypt one if you put one in | Serving HTTPS | The key is readable by the panel's account only (mode 0600); it never leaves the server and is not in the audit log, which records the certificate's name, issuer, expiry and fingerprint |
| Panel backups | Restoring the panel | Kept 14 days by default (1–365, Panel Server → Panel → Backups); can be encrypted with a passphrase |

The encryption key ring is `data/cred_key`, on the same host so the panel can start unattended. It
protects a copied database or backup, not a server someone has taken over; full-disk encryption covers
a stolen disk.

## How long

| Data | Kept |
| --- | --- |
| Full IP addresses in the audit log | 90 days (`audit_ip_retention_days`; 0 keeps them), then reduced to the network |
| Audit log entries | Until you set `audit_log_retention_days` in `config.json` (off by default) |
| Stats history | 14 days |
| Panel backups | 14 days by default (1–365) |
| "Remember me" sign-in | 3 days by default (Settings → Sessions & Security) |
| Device cookie (in your browser: your account's number and a random value, so wrong passwords sent from elsewhere do not pause your sign-in) | 180 days from your last sign-in; signing out clears it |
| Everything else | Until you delete it |

## What leaves your server

Each of these connects from your server to the service named, which sees your server's IP address and
the request. Nothing in them names you or your players. The web requests the panel makes itself name
`linuxgsm-panel` as their user agent; the update check's `git fetch` and the public-address lookup
(`curl`, then `dig`) are those tools' own requests and say what they always do.

| Service | When | What it is sent | Can it be turned off? |
| --- | --- | --- | --- |
| **GitHub** (`api.github.com`, `github.com`, `raw.githubusercontent.com`) | Checking for panel updates (at most every 5 minutes while a page shows the badge, and in the background every 30 minutes, or less often as set in Settings → Schedules), listing and switching branches | Which commit is newest | Yes: Settings → Outside services → *Panel update check*. Off: no "Update available"; update from the shell with `install.sh` |
| **GitHub** (`raw.githubusercontent.com`, `api.github.com`) | LinuxGSM's list of supported games and their package lists (re-read weekly), its newest version (daily) and its release notes (daily) | Which list or release notes to fetch | Yes: Settings → Outside services → *LinuxGSM game list and release notes*. Off: the copy already downloaded is used (a new install has none) |
| **linuxgsm.com** | Game icons on the install page | Which icon | Yes: Settings → Outside services → *Game icons*. Off: icons already downloaded, initials for the rest |
| **Steam Web API** | Opening a server's Workshop card | The Workshop item and collection ids shown | Yes: Settings → Outside services → *Steam Workshop titles*. Off: the ids are shown without titles |
| **Modrinth** | Searching for or installing a Minecraft plugin or datapack | The search words and your Minecraft version | Yes: Settings → Outside services → *Minecraft plugins and datapacks*. Off: no search or install from Modrinth |
| **api.ipify.org**, then OpenDNS | Finding a host's public address for players' connect line, **only** when the host has no public address of its own (behind a router) | Nothing but the request | Yes: Settings → Outside services → *Public address lookup*. Off: the host's own address is shown |
| **Have I Been Pwned** (`api.pwnedpasswords.com`) | Setting or changing a password (setup, Account, Users, `manage.py`), **only** after the panel's own lists have passed it | The first 5 characters of the password's SHA-1 hash, never the password or the rest of its hash (k-anonymity), with padding so the answer's size says nothing; only to `api.pwnedpasswords.com/range/`, redirects refused | Yes: Settings → Outside services → *Have I Been Pwned password check*. Off: only the panel's own lists are checked; no answer within 3 seconds keeps their result |
| **Telegram, Discord, ntfy** | Sending an alert, when you set the channel up. With a command bot on (Notifications → *Commands from Telegram*, *Two-way command bot* for Discord), the panel also keeps a connection open to Telegram or Discord to receive commands | The alert's short text. By default it names no person and no address (Notifications → *Include details* adds them). A command bot's answers go to the chat they were asked in | Yes: each channel's on/off switch, and the command bot's own. ntfy can be [your own server](NTFY-SELF-HOST.md) |
| **Your browser's push service** (Mozilla, Apple, Google, Microsoft) | Sending an alert to a device you turned alerts on for | The alert, encrypted end to end between the panel and your browser; the push service sees only its size and time | Yes: per device (Account → Alerts on this device) |
| **Your own Telegram chat** | Alerts, once you link it (Account → Link my Telegram) | The same short text as a browser alert | Yes: Unlink Telegram |
| **Tailscale** | If you use Tailscale, its client on your server talks to Tailscale's coordination server, or to your own Headscale server when you set one (the `/tailscale` page's *Control server*); then no Tailscale coordination server is involved | Tailscale's own traffic, under Tailscale's terms, or your Headscale's | Yes: don't use it, or log the host out |
| **Ubuntu package mirrors** | OS updates you start, and the daily check for them (an `apt update` on every host the panel manages, as Ubuntu's own daily apt timer also does) | Which packages are available | Yes: Settings → Schedules → *OS update check* (the daily check; updates you start still fetch). Off: no alert for waiting updates; a host's Maintenance tab checks when you press Check. The mirrors are the ones your system is set to use |
| **Software you install through the panel** | Installing or updating a game server (LinuxGSM from `linuxgsm.sh` and GitHub, then the game from Steam or its own source), preparing a host (gamedig from the npm registry, and Node.js from NodeSource's repository when the host has no recent one), installing Tailscale (`tailscale.com`), attaching Ubuntu Pro (Canonical) | The usual download requests of that software; Ubuntu Pro also gets the token you give it | Yes: they happen only when you start them |

Every switch is on by default and is checked where the request is made, so nothing in the panel
reaches a service while its switch is off. Turning off the update check or the breached-password check
asks first, because each is a security control.

The installer, run by you, also downloads the panel from GitHub and its dependencies from their usual
sources, and asks one service for the host's public address only when the host is behind a router. A
fresh install and every update also download the list of 100,000 common passwords the breached-password
check uses (`data/common-passwords-100k.txt`, from the SecLists project on `raw.githubusercontent.com`,
pinned to one commit and checked against its SHA-256), but only when the file is missing or does not
match: a host that has it downloads nothing. If the download fails, the install or update carries on
and that list is skipped until it is there.

## Your controls

- **Alert text:** Notifications → *Include details (IP addresses, usernames)*, off by default.
- **IP ageing:** `audit_ip_retention_days` in `data/config.json` (90 by default).
- **Audit log length:** `audit_log_retention_days` in `data/config.json`.
- **Backups:** how many days to keep, and a passphrase to encrypt them.
- **Alert devices and Telegram:** remove a device, unlink Telegram, or tick *Stop alerts on this device*
  when you sign out.
- **Your browser:** signing out clears the panel's cookies, its saved pages and its browser storage
  (the console's command history among them). When you keep alerts on that device, its alert
  subscription stays.
- **Outside services:** Settings → Outside services has one switch per service above, each with a
  note of what stops working when it is off.
- **Accounts:** deleting an account removes its devices, sessions and linked chat.

## Changes

This page changes with the panel. What is new in each release is in the [changelog](CHANGELOG.md).
