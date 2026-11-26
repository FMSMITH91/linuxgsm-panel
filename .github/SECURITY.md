# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull
requests, or discussions.** A public report tips off attackers before a fix is out.

Instead, report privately through GitHub's private vulnerability reporting:

1. Open the [**Security** tab](https://github.com/FMSMITH91/linuxgsm-panel/security).
2. Click **"Report a vulnerability"**.
3. Describe the issue.

The report stays private until a fix is ready. You can expect an initial response within a few
days. When you can, please include:

- the version and commit you're running (both are in the panel's footer, e.g. `2026.9.26 · a1b2c3d`),
- a description of the issue and its impact,
- steps to reproduce (or a proof of concept), and
- any suggested fix.

Coordinated disclosure is appreciated: please give a reasonable window to release a fix
before any public write-up.

## Supported versions

The panel is a rolling release: fixes land on `main` and are picked up by re-running the
installer, which updates in place (with a health check and automatic rollback). A version is
the date of the commit it runs (`2026.9.26`). Security fixes are applied to the **latest**
version only, so please update before reporting.

| Version | Supported |
| --- | --- |
| Latest `main` (the newest date) | ✅ |
| Anything older | ❌ — please update first |

## Threat model

[docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md) is the panel's threat model (OWASP Threat Modeling
Cheat Sheet): its assets, the trust boundaries (the browser, the panel, root through the helper, game
accounts, remote hosts, push services and chat bots, database servers, the update path and CI), STRIDE
against each one with the controls that answer it and the file that holds them, and the risks
accepted. The sections below are the parts an operator acts on.

## Deploying securely

The panel manages game-server hosts over SSH, so treat it as sensitive infrastructure:

- Keep it behind **Tailscale** (or a reverse proxy with a real certificate) rather than
  exposing the panel port to the public internet. See [docs/https.md](../docs/https.md).
- Keep **two-factor authentication** enabled on admin accounts. Settings → Sessions & Security →
  *Require two-factor authentication for administrators* (off by default) makes superadmins and
  anyone with terminal, user or group rights set it up before anything else.
- Keep the install **up to date** — re-running the installer applies the latest fixes.
- When you add a remote host, give its **host key fingerprint** (the Add Remote Server form's "Host key fingerprint (optional)" field, also on Edit; run
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host, over a channel you already trust).
  The first connection must then present that key, or the host is refused before its password or
  key is sent. Left empty, the first key seen is trusted and pinned (trust on first use), and every
  later connection must match it.

### First run: the setup token

Until the first administrator exists, the setup wizard's second step makes whoever submits it the
superadmin, which is root-equivalent on the panel's host. So:

- The installer ends by printing the wizard's link with a **one-time setup token** in it
  (`/setup?token=…`). The token lives in `data/setup_token` (mode 0600); `manage.py setup-token`
  (or `sudo linuxgsm-panel-recover setup-token`) creates it if it is missing and prints it again.
- Until an admin exists, `/setup` and every `/api/setup/*` endpoint answer only a browser that has
  shown that token, and the wizard's Tailscale endpoints refuse every caller. The token is deleted
  when the admin is created; after that the wizard answers only the browser that created the admin,
  or a superadmin who signs in.
- Treat the link like a password until you have used it: anyone holding it before you finish step 2
  can create the admin account.

#### Checking an install set up before the fix (GHSA-cwmq-pvg9-jjfx)

The token arrived in commit `aad46a4` (version 2026.9.29; that date also has earlier commits, so check
the commit in the footer). Before it, whoever reached the port while the wizard was open could create a
superadmin, or join the host to a tailnet of their own with Tailscale SSH on. Finishing setup undid
neither, so "my install was already set up" is not an all-clear. On each install set up on an older
commit:

1. **Superadmins.** `sudo linuxgsm-panel-recover list-users` (or `panel/install/manage.py list-users` in the
   panel's directory) lists every account, marking each `[superadmin]`. Look for one you did not create.
2. **The tailnet.** On the panel's host, `tailscale status --json | jq -r .CurrentTailnet.Name` names the
   tailnet the host is in, and `tailscale status` lists the machines that can reach it. If the tailnet
   is not yours, `sudo tailscale logout`. `tailscale serve status` shows what the host publishes, and
   whether any of it is on Funnel (the public internet).
3. **Sign-ins.** Older versions wrote no audit row for the wizard's steps, but every sign-in is logged
   with its address: look in Audit Logs for `login` rows by an account or from an address you do not
   recognise.

A superadmin is root on the panel's host (see "Known trust-model limitation" below). If any of
these shows someone else, treat the host as compromised: rebuild it rather than only deleting the
account.

### The panel owner

The panel owner ([docs/permissions.md](../docs/permissions.md#the-panel-owner)) is one account that the web UI
never lets another administrator deactivate, demote, rename, delete or reset, and that alone may open a
terminal on the panel's host or restore or download a panel backup (the ways in to `panel.db` and
the panel's keys from the UI).
Ownership moves by the owner's password plus a live 2FA code, or by `manage.py set-owner` from the
host's shell. It guards the account controls; it is not a boundary against a superadmin who uses the
other root-equivalent powers a superadmin has on the panel's host (see below), so give superadmin only
to people you would trust with the host.

## Updates are signed with a release key

Every commit on `main` is a GitHub squash merge signed by GitHub's key, which says nothing about who
asked for the merge. So each release is also signed with a release SSH key (`tools/sign-release.sh`)
whose private half is kept off GitHub. Signatures live on the `release-signatures` branch as
`<branch>/<sha>.sig`. The installer already on the host checks the commit it is about to install
with `ssh-keygen -Y verify` (namespace `linuxgsm-panel-release`) against the key the host already
holds, never the copy in the update: root-owned `/usr/local/lib/linuxgsm-panel/release-signers` on a
root install, the installed commit's `release-signers` on a per-user one. An unsigned or unreadable
target is held, and so, with no pin, is a `main` tip older than the installed commit.

What it does not cover:

- **The first install is trust on first use.** `curl … | bash` runs GitHub's installer, and a host
  with no key yet has nothing to check against. Check it yourself before the first install (below),
  and after the first update check that `/usr/local/lib/linuxgsm-panel/release-signers` (root
  install) or the checkout's `panel/install/release-signers` (per-user) is the release key:
  `ssh-keygen -lf` on it prints the fingerprint below.
- **A host that has no key yet holds** every update, saying so, until it is updated once by hand
  through its old installer or with `PANEL_ALLOW_UNSIGNED_UPDATE=1` over SSH.
- **The test host's deploy** ships the commit's own installer. It runs only when started by hand,
  only from `main`. Its reach is the tailnet ACL's: confirm the ACL lets the CI runner's tag reach
  the test host only. Its SSH connection checks the host's key against the `DEPLOY_HOST_KEY`
  repository variable alone and refuses any other; without that variable it stops before connecting.

### Checking a first install

The release key's fingerprint is:

```
256 SHA256:YhAumFmigcV9YJNrtPkaekEm1ed/NSL2Me3fxTjZ82w release (ED25519)
```

It is printed here and in the README; compare it with a copy you trust from somewhere other than the
download you are checking (an earlier visit, a colleague's install). Both pages live in this
repository, so they catch a changed download, mirror or proxy, not a compromised GitHub account.
Before running the installer, check that the commit you are about to install is signed with it:

```bash
git clone --quiet https://github.com/FMSMITH91/linuxgsm-panel.git lgsm-check && cd lgsm-check
ssh-keygen -lf panel/install/release-signers        # must print the fingerprint above
git fetch --quiet origin release-signatures
SHA="$(git rev-parse HEAD)"
git show "origin/release-signatures:main/${SHA}.sig" > ../lgsm-release.sig
printf 'linuxgsm-panel release\nbranch main\ncommit %s\n' "${SHA}" \
  | ssh-keygen -Y verify -f panel/install/release-signers -I release -n linuxgsm-panel-release -s ../lgsm-release.sig
```

`Good "linuxgsm-panel-release" signature for release with ED25519 key SHA256:YhAum…` means that
commit is a signed release; install from it with `bash install.sh` in that folder (as root:
`sudo bash install.sh`), which installs the checkout you checked rather than fetching again. A missing
`.sig` means `main` moved on since the last signed release: wait for it to be signed, or install the
newest signed commit (`git checkout <sha>` first). Anything else, do not install.

Each GitHub Release also carries the commit's software bill of materials,
`linuxgsm-panel-<tag>.cdx.json` (CycloneDX 1.6 JSON): every Python package the panel installs and
every npm package of gamedig, with the version and the hashes the lockfiles pin them to. It is made
from the tagged commit's own lockfiles (`tools/sbom.py`), the same bytes every time, so it can be
made again from the tag and compared, and fed to a scanner (for example `osv-scanner --sbom`).

A lost key is recovered with `PANEL_ALLOW_UNSIGNED_UPDATE=1` on a run by hand over SSH; the panel's
own update, its terminal and anything it starts through the helper cannot pass it.

## Known trust-model limitation: the panel has root on its own host

When the installer is run as **root** it creates a dedicated service user and grants it
passwordless sudo. What that grant permits depends on whether the root-owned helper pieces are
installed, and the installer prints which one it wrote:

| condition | grant |
|---|---|
| helper + root-owned `db_maintenance.py` + root-owned `panel.conf` + root-owned installer all present | `ALL=(root) NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper`, plus the game-account line and the helper's `Defaults!` line below |
| any of them missing | `ALL=(ALL) NOPASSWD:ALL`, and the panel falls back to `sudo bash -c '<verb rendered as text>'` |

On an install with the wide grant there is no privilege boundary between "the web panel is
compromised" and "the host is root-owned" — **re-run `install.sh` as root to get the narrow
grant**. Installs run as a **normal user** get no sudoers entry at all.

### The sudoers file

With the narrow grant, `/etc/sudoers.d/linuxgsm-panel` holds:

```
Defaults!/usr/local/lib/linuxgsm-panel/panel-helper env_reset, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"
<panel-user> ALL=(root)              NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper
<panel-user> ALL=(%lgsmpanel-games)  NOPASSWD: ALL
```

The `Defaults!` line makes the helper's starting environment this file's decision, not the host's
global policy. A sudo with no command-scoped `Defaults` (sudo-rs before 0.2.4) rejects it, so there
the installer writes the two grants without it and warns; the helper still replaces its environment
itself. The file is rewritten on every install and update.

Root is reachable only by running the helper — **not** `/bin/bash`, `/bin/sh`, `systemd-run`, the
`tailscale` binary or `sudo -u root`, each of which runs whatever it is handed.

**The host terminal's sudo is a separate, opt-in grant.** With `PANEL_TERMINAL_SUDO=1` the installer
also writes `/etc/sudoers.d/00-linuxgsm-panel-terminal`: `<panel-user> ALL=(ALL) ALL`, which asks
for a password every time (`PANEL_TERMINAL_SUDO=0` removes it). Its `00-` name sorts it first, so the
narrow lines above stay the last match. A compromised panel holds no password, but it could read one
typed into the terminal it renders, which is why this is off unless asked for.

### The helper

`tools/panel-helper` is installed root-owned at `/usr/local/lib/linuxgsm-panel/panel-helper`,
outside the panel's checkout (which the panel user owns and `git pull` rewrites). It takes a verb
and already-separated arguments, re-validates each against its own table, and execs a fixed
argument vector: no shell, and only the programs its verbs name. Its shebang is
`#!/usr/bin/python3 -I`, and it replaces its environment with a fixed minimal one
(`PATH=/usr/sbin:/usr/bin:/sbin:/bin`, a C.UTF-8 locale, root's `HOME`) before any verb runs.

Python compiles the script it is given on every run, and compiling the helper was more than half of
each call's CPU. So install.sh places three root-owned files: `panel-helper` (the path the sudoers
rule names, unchanged) holds `tools/panel_helper_entry.py`, a small entry under the same
`#!/usr/bin/python3 -I`; `panel-helper-code.py` holds `tools/panel-helper` byte for byte; and
`panel-helper-code.pyc` holds that code's bytecode, compiled by root at install time as a
checked-hash pyc (PEP 552). The entry reads nothing from its environment or arguments. It uses the
bytecode only when every directory from `/` down and both files are owned by root with no group or
other write bit and are not symbolic links (checked through open file descriptors), and the pyc's
magic number is this Python's and its source hash matches the code file; when only the pyc fails, it
compiles the code bytes it read through that checked descriptor (never re-reading the file by path).
When a directory on the way or the code file fails the ownership test, it runs nothing: it exits 1
with a message to re-run install.sh as root (fail securely). The hash only tells a stale pyc from a
current one; the ownership test is what keeps out a planted one, as it keeps out a changed helper.
Where the split cannot be placed, or the directories above it fail the entry's own check at install,
install.sh puts the helper whole at `panel-helper` as before.

It covers ufw, fail2ban, systemd, apt/dpkg, log reads, cron and user management, the sshd port
change, reboots, Ubuntu Pro, Tailscale on the panel's own host, the panel's restore, repair and
self-update, LinuxGSM actions as the game user, dependency installs, the GMod shared-content box,
a game server's MariaDB/MySQL databases, the panel's own Let's Encrypt certificate, root's crontab for the
owner's root cron page, readying a game account for add-on containers, and more — 137 verbs.
The narrowing is in the argument types:

- The systemd verbs take a unit from an **exhaustive list** (`ssh`, `sshd`, `fail2ban`,
  `ssh.socket`, `whoopsie`, `cups`, `modemmanager`, `unattended-upgrades`). The panel's own unit is
  not in it; `panel-restart` restarts it and takes only a delay of 1 to 300 seconds.
- `tls-le-copy` takes one **certificate name** (domain labels and dots) and copies only
  `/etc/letsencrypt/live/<name>/fullchain.pem` and `privkey.pem`, each a root-owned regular file under
  that certificate's own `live/` or `archive/` directory and nothing but PEM of its kind, into the
  panel's `data/ssl` (opened without following a link), owned by the panel's account, the key 0600.
  It copies only a name the operator opened at install (`PANEL_TLS_LE_NAMES`, recorded root-owned in
  `panel.conf` as `tls_le_names=`), so another service's certificate on the host stays root's.
- The write verb takes a **destination name** and the content on stdin, so `write-file /etc/shadow`
  fails on the name. The log verbs take a **source name** (`log-tail auth`), never a path.
- **The sshd port change** is all verbs: snapshot, write, `sshd -t`, restart, confirm the port
  listens, and restore the snapshot on any failure.
- **The detached OS-update job** takes no caller input. Before `full-upgrade` it runs, as does the
  host bootstrap's `apt-full-upgrade` verb on the panel host and on a remote, a read-only
  `apt-get -s` simulation, bounded to 600 seconds. Any package the host's own apt pinning would
  DOWNGRADE is kept at its installed version for that run only, through a temporary preferences
  file passed with `-o Dir::Etc::Preferences=`; nothing the operator set on disk changes. If the
  check cannot finish, the upgrade runs exactly as before, with no keep, and the log says so.
  `install.sh` runs the same step before each of its two full-upgrades.
- **File-browser downloads** are the one place a caller-chosen path crosses the boundary. The path
  is checked for shape (relative, no `..`, no NUL or newline), and the helper resolves and opens it
  only after dropping to the **game user**, from a home looked up in passwd. Over SSH the path
  travels on stdin, never in the command.
- **Secrets** (the Tailscale auth key, the Ubuntu Pro token) never appear on a command line; they
  travel on stdin.
- **Add-ons in containers** need root for two things only: Podman's packages (the existing `apt-install`
  verb, with the fixed list `podman uidmap passt`) and `addon-account-prepare <account>`, which gives a game
  account a range of subordinate uids and gids (only where it has none, starting after every range already
  in `/etc/subuid` and `/etc/subgid`) and turns on lingering for it. The helper refuses an account that is
  not in `lgsmpanel-games` (one the panel may already become) and the panel's own account;
  `addon-account-release` (lingering off, then the account's user manager stopped and its failed state
  cleared with `systemctl reset-failed`; then, for a uid of 1000 or more, Podman's two `/tmp` folders when they
  are real folders the uid owns and, with `forget` (an uninstall; `keep` after the last add-on's removal), its user
  journal files, after a `journalctl --rotate` only when an active file is there, so an account later given the
  same uid can't read the old add-ons' logs) refuses the same accounts. The containers themselves run rootless,
  as the game account, from its own user manager: no root daemon and no Docker socket (OWASP Docker
  Security Cheat Sheet, rules 1 and 11). A container's network reaches only what is forwarded to the host's
  loopback (the game's RCON port, its database, the relays it needs): on Ubuntu 26.04 nothing else at all
  (pasta `--splice-only`); on 24.04 not the internet or other machines (`-o 127.0.0.1`, `-4`), though a
  service listening on one of the host's own other addresses stays reachable.
- **Root's crontab** (`root-crontab-read`, `root-crontab-write`) is closed unless you open it at install
  (`PANEL_ROOT_CRON=1`/`0`, recorded root-owned in `panel.conf`; the default is closed). The write takes the
  new crontab on stdin, refuses any line that is not blank, a comment, a `NAME=value` variable or a job with
  cron's own schedule grammar, and installs it with `crontab -u root -` only while root's crontab still
  hashes to what the panel read. Opening it lets the panel owner run any command as root on this host from
  the root cron page; that page is off by default, the owner's alone, and asks for the password on every change.
- `apt-install` checks every package name and bounds the list; dpkg's conflict answers are fixed in
  the helper, so an unattended upgrade never overwrites a config file you edited.
- **Tailscale on the panel's host** changes only through verbs; the panel's account is not
  tailscaled's operator. The helper will not move a joined host to another tailnet. A join may name
  a self-hosted control server (`--login-server`), checked as an http(s) address with no path, and
  the login link it prints must be on that server. Tailscale SSH
  there is your choice at install (`PANEL_TAILSCALE_SSH=1`/`0`, recorded root-owned in `panel.conf`).
  Serve and Funnel publish only the panel's own recorded port, and Funnel is refused while another
  app is served on the same listener, unless Funnel is already on there.

### What is still escalated by hand

Both escalation routes are counted by a test that ratchets: the counts may fall, never rise.

| route | sites remaining |
|---|---|
| `run_command(..., sudo=True)` | 3 |
| `_sudo_sh(...)` | **0 — the route is gone** |
| **root total** | **3** (from 131) |

The three, all on **remote** hosts: the Tailscale installer (it runs Tailscale's downloaded install
script as root, which no verb can narrow — if that trade is not one you want, that step is the thing
to change), the LinuxGSM discovery scan (a fixed script; on the panel host it is the `lgsm-discover`
verb), and the reboot's escalation probe (the fixed command `true`). The VPS bootstrap, Tailscale
install and join routes refuse the panel's own host. NodeSource is configured on remotes without
running its script (the `nodesource-setup` verb pins the signing key), and gamedig is installed
from a hash-locked lockfile.

### The second line is the game accounts

The panel drives game accounts directly (file browser, GMod content, cron, installs), so the grant
lets it *become a game account*, bounded by a group:

- the Runas target is `%lgsmpanel-games`, never `ALL` or a named user, so `sudo -u root` stays
  refused;
- membership is set only by install.sh and the `gameuser-group` verb, which holds the group name
  as a literal; an account the panel creates (`user-create`) is enrolled by that verb as it is
  made, under every test below but the install one, since its home is still the skeleton;
- **only a game account is enrolled**: a uid in `/etc/login.defs`' `UID_MIN`..`UID_MAX`, not the
  panel's own account, only ordinary groups, and a LinuxGSM instance or Steam content tree in its own
  `/home/<name>`;
- **no account that can already escalate is enrolled**: one in a root-equivalent group (`sudo`,
  `admin`, `wheel`, `docker`, `lxd`, `adm`, `shadow` and others), one a sudoers, `doas.conf` or
  polkit rule names; a file among those it cannot parse counts as able to escalate.

A game account cannot write `/etc`, install packages, read another account's home, or edit the
helper or the sudoers file. Every `sudo -u <account>` the panel builds goes through
`ssh_manager._core.game_user_cmd` or `game_user_exec_cmd`, which refuse, not only quote, an
account or script name that is not a plain identifier, or is `root` (GHSA-hh39-76g3-wxcx,
reported by kta1kri; GHSA-c49r-gmr2-6qf5). A login or host handed to the system `ssh` client is checked the same way
and placed after `--`. A panel backup restore re-checks every such name in the archive's database
and refuses the restore naming the bad row.

### Root never runs or installs from the panel's checkout

- **The grant only narrows when all four root-owned pieces landed**; until then the wide grant stays,
  because narrowing under the fallback would break every privileged action.
- The offline database repair, restore and self-update run root-owned copies placed only by
  `install.sh`. Run as root, the installer stages those pieces from **root's own clone**
  (`/usr/local/lib/linuxgsm-panel/.source.git`), never from the panel-owned working tree or object
  store, and only from a commit on the tracked branch's first-parent line.
- Root keeps a **source floor**, `/usr/local/lib/linuxgsm-panel/.source-floor`: the newest commit of
  main it has staged from. It refuses any commit that does not contain it, and never lowers it.
  Removing the file (as root) resets the floor to e26a644, the way to go back to older root pieces on purpose.
- When the panel starts the update, root verifies against main only. To test another branch, run
  `cd / && sudo PANEL_BRANCH=<branch> bash /usr/local/lib/linuxgsm-panel/install.sh` over SSH.
- Inside the panel-owned tree the installer reads, snapshots and restores files as the tree's
  owner, and hands the tree over without following links.
- **The installed helper has to stay in step with the panel's code.** Only `install.sh` can refresh
  it, so it does so on every update as well as a fresh install. The panel's Diagnostics card names
  any verbs the installed helper lacks.

### Deleting a host

Deleting a host from the panel never connects to it, so what the panel installed there stays: the
gamedig tree, its two links and the weekly root cron that re-runs `install-gamedig.sh`. That job
fetches nothing while the tree is in place, so that part is root-owned, hash-locked and inert.
**Tailscale, if the panel set it up there, is not inert:** the host stays in your tailnet until you
log it out. Nor are add-ons (B3, IW4MAdmin): each keeps starting at boot as its game account, holding
the game's RCON password and its database login, so remove them on the server's Add-ons tab first.
The fail2ban whitelist file and the auto-block firewall rules stay too.
The install guide's [Removing a host](../docs/install.md#removing-a-host) lists each with the commands that remove it.

### What you can do today

- **If you only manage remote servers from this panel**, run the installer once over SSH with
  `cd / && sudo PANEL_LOCAL_GRANT=0 bash /usr/local/lib/linuxgsm-panel/install.sh`. It removes
  `/etc/sudoers.d/linuxgsm-panel` and `/etc/sudoers.d/00-linuxgsm-panel-terminal`, and records the
  choice in the root-owned `panel.conf`, so later updates keep it. The panel keeps working for
  remotes. Local-host management stops, and so do the panel's own root jobs: **Panel Server →
  Panel → Panel Updates → Update now** (and the bot's `/update`), restoring a panel backup, and the database repair. Then
  update by hand over SSH: `cd / && sudo bash /usr/local/lib/linuxgsm-panel/install.sh`.
  `PANEL_LOCAL_GRANT=1` puts the grant back. If you deleted the file by hand before this setting
  existed, the next update records that and leaves it deleted.
- **If you do manage the local host**, treat the panel host as you would any machine where a
  network service can become root: keep it off the public internet, keep 2FA on, and keep it
  updated.

## This repository's CI

Every workflow's token starts with no permissions (`permissions: {}`), and each job grants only the
scopes it uses. No workflow runs on `pull_request_target`, and every action is pinned to a full commit
SHA. Every job but the deploy starts with StepSecurity's Harden-Runner; the pull-request jobs whose
outbound hosts are few and known run it in block mode, refusing every host not on their list (OWASP
Top 10 CI/CD Security Risks, CICD-SEC-5 to CICD-SEC-7). The Docker images the fuzzing runs in are
pinned by digest too; the one image that cannot be, Scorecard's, is checked against a recorded
digest before and after it runs (CICD-SEC-3).

### The CI secret

The one secret credential the workflows use is `CODACY_PROJECT_TOKEN`, a Codacy repository API
token that sends test coverage to Codacy. It cannot touch the code, GitHub or any host, but it can
change which Codacy patterns run. It lives in a `codacy` environment that only `main` can use, and
only `codacy-coverage.yml` (a `workflow_run` job running `main`'s copy) reads it; the CI job that
runs pull-request code never holds it. `codacy-alerts.yml` (scheduled, on `main`) would read a
`CODACY_API_TOKEN` from the same environment if one were set; none is, because Codacy answers it
without one for this public repository. The test host's deploy logs in to Tailscale with OIDC, not a
stored credential.

Thank you for helping keep the project and its users safe.
