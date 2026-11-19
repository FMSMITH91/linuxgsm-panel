# Security features and recovery

Back to the [README](README.md). The security policy and the trust model: [SECURITY.md](../.github/SECURITY.md); the threat model: [THREAT-MODEL.md](THREAT-MODEL.md); privacy: [PRIVACY.md](PRIVACY.md).

## Security

- **HTTPS by default** (self-signed out of the box; your own or a Let's Encrypt certificate in Settings, or Tailscale Serve or a proxy, for a trusted cert).
- **Passwords** hashed with Argon2id (older bcrypt hashes are upgraded at the next sign-in). A new password needs 15 characters (8 with 2FA on), any characters, must not contain the username, and is checked against a bundled list of common passwords, then a downloaded list of 100,000 breached ones (fetched by the installer and each update, SHA-256 pinned), then Have I Been Pwned's Pwned Passwords (only the first five characters of the password's SHA-1 hash are sent; Settings can switch it off); there are no composition rules. Sign-ins are rate-limited per address and per account name (an increasing pause, never a permanent lock). A browser that has signed in to an account gets a device cookie, and the name's pause does not hold it, so wrong guesses sent from elsewhere cannot keep you out; it gets a pause of its own after repeated wrong passwords, and signing out clears it. **TOTP 2FA** with backup codes, which Settings can require of superadmins and of anyone allowed the terminal, users or groups; until they set it up they can open no page, console or terminal. Turning 2FA off needs a password of 15 characters first, and an admin's 2FA reset also issues a new password the account changes at its next sign-in. High-risk actions ask for the password again once the last sign-in or confirmation is more than 10 minutes old (Settings > Sessions & Security, 0 to switch it off; API tokens are exempt, and can be given an expiry): opening a terminal; changing users, invites or groups; adding or editing a host, its pinned host key, firewall, bans and blocks, SSH port or mode, Tailscale, Ubuntu Pro, OS updates or a reboot; updating the panel, changing its port, its HTTPS certificate or its encryption key; uninstalling a server; restoring a panel backup, deleting one or changing the backup settings; restoring a game server from a backup or starting an upload of one; a database's admin login, database server, password reset, delete (a kept one's too), restore or upload; syncing a server's ports into the firewall; turning on alerts for a device or linking Telegram; and saving Settings, or saving or testing Notifications. Users are told in the panel about changes to their password, 2FA and API token.
  - Locked out by required 2FA (lost phone and backup codes)? Another superadmin can turn your 2FA off on the Users page (not the panel owner's: only the panel host can), or on the panel host run `linuxgsm-panel-recover disable-2fa <user>` (or `manage.py disable-2fa <user>`), sign in, and set 2FA up again. The 2FA setup page always stays reachable, so the last superadmin can never be shut out by the switch.
- **Sessions** in `HttpOnly`, `SameSite=Lax` cookies, `Secure` over HTTPS; "Sign out everywhere" revokes every session.
- **Privacy:** no telemetry, no analytics, no third-party scripts, and no e-mail. What the panel keeps, for how long, and what leaves your server: [PRIVACY.md](PRIVACY.md).
- **Encryption at rest** — SSH credentials and remote host addresses, database logins, emails, 2FA secrets, bot and channel tokens, linked Telegram chats, alert-device subscriptions and session addresses are encrypted with AES-256-GCM in `data/panel.db` and `config.json` (key ring in `data/cred_key`, rotated from Panel Server → Panel → Diagnostics); `data/` is `chmod 700`. Passwords (Argon2id), API tokens, 2FA backup codes and invite links are stored only as hashes.
- **SSH host-key pinning**, **signed updates** (see [Updating](install.md#updating)), CSRF protection, a Content Security Policy (scripts and `<style>` blocks only from the panel itself or with the page's nonce, and no inline `style` attributes) and security headers, and input validation on anything that becomes an OS operation.

> Prefer Tailscale over exposing the panel to the internet, and never commit `data/` (already in `.gitignore`). The security model, including what the panel can do as root on its own host, is in [SECURITY.md](../.github/SECURITY.md).

## Recovery

Locked out? One command on the panel host talks straight to `data/panel.db`, so it works even when you can't log in (a password reset revokes existing sessions):

```bash
sudo linuxgsm-panel-recover                          # reset the sole superadmin's password
sudo linuxgsm-panel-recover reset-password <user>
sudo linuxgsm-panel-recover disable-2fa <user>       # lost your authenticator
sudo linuxgsm-panel-recover create-admin <user>      # or: promote / activate <user>
sudo linuxgsm-panel-recover set-owner <user>         # make an active superadmin the panel owner
sudo linuxgsm-panel-recover set-site-domain <host[:port]>   # the address browsers use, behind a proxy that hides it
```

The panel host's shell is the authority over the panel owner. `set-owner` moves ownership to any
active superadmin (2FA is not needed there) and records it in the audit log; `deactivate` and
`demote` refuse the current owner until `set-owner` has moved it. `create-admin` never takes
ownership from an existing owner.

Run `--help` for the full list. On an older install without the command, update it first with the installer already on the host (see [Updating](install.md#updating)), which places the command. Don't pipe `recover.sh` from GitHub into a root shell: no release signature covers it.
