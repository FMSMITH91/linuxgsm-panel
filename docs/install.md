# Installing, updating and removing the panel

Back to the [README](README.md). Settings and deployment behind a proxy: [configuration.md](configuration.md).

## Requirements

- A host running **Ubuntu 22.04, 24.04 or 26.04 LTS** for the panel (CI tests all three, each on the Python that release ships — 3.10, 3.12 and 3.14; other distros may work but aren't supported).
- One or more game-server machines, reachable over SSH (key, password, or Tailscale SSH). The panel host can also manage itself.
- **LinuxGSM** on those machines, or let the panel install it.
- *Optional:* **[Tailscale](https://tailscale.com)** for private HTTPS with no open ports.

## Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/FMSMITH91/linuxgsm-panel/main/install.sh | bash
```

To check what you install first, the release key's fingerprint is
`SHA256:YhAumFmigcV9YJNrtPkaekEm1ed/NSL2Me3fxTjZ82w` (ED25519); [SECURITY.md](../.github/SECURITY.md#checking-a-first-install)
shows how to check that the commit you install is signed with it before you run the installer.

The installer runs unattended. It:

1. Installs its prerequisites and patches the OS with `apt full-upgrade` (skip with `PANEL_NO_UPGRADE=1`). If the upgrade needs a reboot it reboots at the end, unless game servers are running; `PANEL_NO_REBOOT=1` skips the reboot.
2. Clones the repo, builds a Python virtualenv, picks a free port (5000 by default) and serves HTTPS with a self-signed certificate.
3. Sets up the service, **never running the panel as root**:
   - **As a normal user** → a `systemd --user` service with linger, so it survives logout and reboot.
   - **As root** → a dedicated non-login **`lgsmpanel`** user running a system service, with a scoped passwordless-sudo entry for managing the local host (see [SECURITY.md](../.github/SECURITY.md)).
   - Either way, the `linuxgsm-panel-recover` command (reset a password, turn off 2FA, create an admin from a shell).
4. Asks whether to turn on **Tailscale SSH on the panel host** (no by default). Answer ahead with `PANEL_TAILSCALE_SSH=1` or `=0`, placed after `sudo`: `curl … | sudo PANEL_TAILSCALE_SSH=1 bash`. An update keeps the answer.
5. Keeps **root's crontab on the panel host** closed to the panel. `PANEL_ROOT_CRON=1` (placed after `sudo`, like the line above) opens it to the panel owner's root cron page; `=0` closes it again, and an update keeps the answer.
6. Keeps the host's **Let's Encrypt certificates** closed to the panel. `PANEL_TLS_LE_NAMES=panel.example.com` (a comma-separated list of certbot names, placed after `sudo`) lets Settings → HTTPS certificate load those; `=none` closes them again, and an update keeps the answer.

On a root install, `sudo` to root is refused in a terminal on the panel host (the `lgsmpanel` user's grant names only its helper and the game accounts). To allow it, re-run the installer with `PANEL_TERMINAL_SUDO=1` (`cd / && sudo PANEL_TERMINAL_SUDO=1 bash /usr/local/lib/linuxgsm-panel/install.sh`) and give the panel user a password (`sudo passwd lgsmpanel`); sudo then asks for it every time, and `PANEL_TERMINAL_SUDO=0` removes it. A per-user install's terminal runs as your own user, with whatever sudo that user already has. You would be typing that password into a terminal the panel renders, so it protects against a stolen session, not a compromised panel.

Then open **the link the installer prints at the end** — `https://your-server:5000/setup?token=…` (`http://` won't load) — accept the one-time certificate warning (**Advanced → Proceed**), and the **setup wizard** creates your first super admin. The token makes the install yours: until the first admin exists, only a browser that has shown it can use the wizard. Lost the link? `sudo linuxgsm-panel-recover setup-token` prints it again.

## Updating

- **In the panel:** *Panel Server → Panel → Panel Updates → Update now* (or the Telegram/Discord `/update` command). It moves only to a commit whose CI checks all passed, and survives its own restart. With the update check turned off (Settings → Outside services), the panel asks GitHub nothing about updates and offers none: use the installer.
- **From the shell:** run the installer already on the host: `cd / && sudo bash /usr/local/lib/linuxgsm-panel/install.sh` (root install) or `bash ~/linuxgsm-panel/install.sh` (per-user). This takes the branch tip directly, without the CI gate (or first a release it may not skip, below).

Either way the updater snapshots the code and database (keeping the last 3), installs dependencies only when they changed, restarts the panel and health-checks it. If the panel does not come back it **rolls back the code and database automatically**. On a root install it also refreshes the root-owned pieces in `/usr/local/lib/linuxgsm-panel`.

**Only signed releases are installed.** The installer already on the host moves the panel only to a commit signed with the project's release SSH key, which is kept off GitHub. Anything else is held with "Not updated: held at …" and the reason. The host checks against its own copy of the public key (`release-signers`), never the copy inside the update. Installing with `curl … | bash` runs the installer from GitHub, so it is not covered by the signature: use it only for a first install, which has no key to check against yet; see [SECURITY.md](../.github/SECURITY.md) for what to check after the first update. If a host says it has no release key, run the installer by hand once over SSH with `PANEL_ALLOW_UNSIGNED_UPDATE=1`: `cd / && sudo PANEL_ALLOW_UNSIGNED_UPDATE=1 bash /usr/local/lib/linuxgsm-panel/install.sh` (root install) or `PANEL_ALLOW_UNSIGNED_UPDATE=1 bash ~/linuxgsm-panel/install.sh` (per-user).

**Versions are dates**: the date of the commit, in UTC, shown with the short commit (`2026.9.26 · a1b2c3d` in the footer).

**Some releases cannot be skipped.** A release that the next one depends on (one that teaches the updater something) is listed in `panel/install/update-stops`. A panel further behind installs that release first, and the newest one on its next update: the Update card simply offers an update again.

**If updates keep rolling back to the same version:** the panel's updater predates the 2026.11.10 root clean-up, which moved the files it reads into `panel/install/`. Run it once over SSH with the release that taught it the new place, then update as usual:

```bash
cd / && sudo PANEL_UPDATE_REF=41fa75df02363e2808192d1cfc26cd772757721d bash /usr/local/lib/linuxgsm-panel/install.sh   # root install
PANEL_UPDATE_REF=41fa75df02363e2808192d1cfc26cd772757721d bash ~/linuxgsm-panel/install.sh                           # per-user
```

## Uninstall

```bash
sudo bash /usr/local/lib/linuxgsm-panel/uninstall.sh   # root / system install
bash ~/linuxgsm-panel/panel/install/uninstall.sh       # per-user install
#   add --yes to skip the "type yes to confirm" prompt
```

On a root install, run the root-owned copy above, not the one in the panel's checkout. The uninstaller removes the service, the panel's own firewall rule and Tailscale Serve routes, the panel files and `data/` (accounts, config and keys) and, on a root install, everything the installer put outside the panel directory (the sudoers entry, the helper directory with gamedig, its links and weekly cron, the recovery command, the sysctl tuning and the `lgsmpanel` user). It leaves NodeSource's apt repository and automatic security updates in place, and names them.

**Your game servers are left completely alone** — their users, files, LinuxGSM installs, autostart crontabs and game-port firewall rules are never touched.

### Removing a host

Deleting a host on **Remote Servers** makes the panel forget it and its game servers. The panel does not connect to the host to do that, so nothing on it changes and its game servers keep running. What the panel put there stays:

- **gamedig**, the player-query tool, in `/usr/local/lib/linuxgsm-panel/gamedig`, with the links `/usr/local/bin/gamedig` and `/usr/bin/gamedig` into it.
- **its weekly root cron**, `/etc/cron.d/lgsm-node-tools` (it fetches nothing while the tree is in place), and its log, `/var/log/lgsm-node-tools.log`.
- **Tailscale, if the panel set it up there.** This is the one leftover that is still a way in: `sudo tailscale logout` (or remove the machine in the Tailscale admin console), then `sudo ufw delete allow in on tailscale0` and `sudo rm -f /etc/sysctl.d/99-tailscale.conf`.
- **the fail2ban whitelist file** (its addresses can never be banned there): `sudo rm -f /etc/fail2ban/jail.d/zz-panel-whitelist.local && sudo fail2ban-client reload`.
- **auto-block firewall rules**, UFW denies commented `panel-autoblock` (`sudo ufw status numbered`, then `sudo ufw delete <n>`).
- **add-ons (B3, IW4MAdmin) keep running.** Each starts at every boot as its game account's user service (lingering is on), with the game's RCON password and its database login in its settings. Remove them on each server's **Add-ons** tab before deleting the host. Afterwards it takes, as that account, stopping and disabling its `lgsm-addon-*` user units and `podman system reset`, then `sudo loginctl disable-linger <account>`.
- **whatever "Prepare & Secure" set up**, if you ran it: ordinary host configuration (packages, UFW, fail2ban, SSH hardening, swap, timezone, automatic updates).

To remove the panel's gamedig and its cron, run this on the host over SSH — **not on a host where a panel is installed** (there `uninstall.sh` removes them), and not if that host's servers use "restart when empty", which counts players with gamedig:

```bash
sudo rm -f /etc/cron.d/lgsm-node-tools /var/log/lgsm-node-tools.log
for l in /usr/local/bin/gamedig /usr/bin/gamedig; do   # only links into the panel's tree
  case "$(readlink "$l")" in /usr/local/lib/linuxgsm-panel/gamedig/*) sudo rm -f "$l" ;; esac
done
sudo rm -rf /usr/local/lib/linuxgsm-panel/gamedig
sudo rmdir /usr/local/lib/linuxgsm-panel 2>/dev/null || true   # only if nothing else is left in it
```
