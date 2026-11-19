# SFTP

Back to the [README](README.md). Who may do what: [permissions.md](permissions.md).

The panel can run its own SFTP service. Each panel user signs in with their **own** panel account
and sees one folder for each game server they may edit files on, named after the server. Inside a
folder are that server's files, exactly as the panel's file manager shows them. Nothing outside those
folders can be reached. The game accounts themselves are not changed: they work as they do on plain
LinuxGSM.

The service is **off** until a superadmin turns it on.

## Turning it on

Settings → **SFTP**:

| Setting | What it does | Recommended |
| --- | --- | --- |
| SFTP service on | Starts the service. Off stops it, and nothing listens. | — |
| Listen on | **This host's Tailscale address** (offered only while Tailscale is up), **only this host** (127.0.0.1), or **all addresses** (0.0.0.0, and :: when the host has IPv6) | Tailscale; 127.0.0.1 without Tailscale |
| Port | The TCP port | 2222 (the default) |
| Largest upload (MiB) | A single file larger than this is refused | 4096 |
| Absolute session limit (hours) | A session ends this long after sign-in, whatever it does: it opens nothing new after it, a file already open may finish for up to an hour, then the session is closed and the user signs in again. Until set, the panel's own sign-in limit (Settings → Sessions & Security) | 8 (OWASP: 4 to 8 hours) |
| Close an idle session after (minutes) | A session that has made no SFTP request (a listing, a read, a write) for this long is closed by the service; 0 never closes one | 15 (OWASP: 15 to 30 minutes for most applications, 2 to 5 for high-value ones) |
| Also allow the account password with an authenticator code | Lets an account with two-factor authentication sign in with its password and its current code instead of a key | Off: SSH keys only |

Saving restarts the service. The card shows whether it is running, on which address, and the
service's **host key fingerprint**.

### Which address

- **Tailscale address**: only devices on your tailnet can connect. Nothing else to do.
- **127.0.0.1**: only programs on the panel's host can connect. Use it when you reach the host
  through your own VPN or an SSH tunnel, for example `ssh -L 2222:127.0.0.1:2222 you@panel-host`,
  then connect your SFTP client to `localhost`, port 2222.
- **All addresses**: anyone who can reach the host can try to sign in. The panel never opens the
  firewall itself. To allow the port with ufw, run on the panel's host (here for port 2222):

  ```sh
  sudo ufw allow 2222/tcp
  ```

  To allow only one address or network, use `sudo ufw allow from 203.0.113.0/24 to any port 2222 proto tcp`
  instead. A cloud provider's firewall needs the same port opened there. Remove the rule when you
  turn SFTP off or move it: `sudo ufw delete allow 2222/tcp`.

  With all addresses, keep sign-in to SSH keys (the default). Failed sign-ins count towards the
  panel's fail2ban jail, which then also bans on the SFTP port.

## Connecting

Each user adds their key on their **Account** page → **SFTP**: paste the one line of the `.pub`
file (an Ed25519 key is recommended: `ssh-keygen -t ed25519`). ECDSA keys work, and RSA keys of
3072 bits or more. Adding a key asks for your password, and your authenticator code when you use
two-factor authentication, every time: a key signs in without your browser session, so a borrowed
session must not be enough to add one. Each added or removed key is recorded in the audit log and
shown in your account's recent security changes. Changing your password, "Sign out everywhere", an
administrator's password reset and deactivating the account remove your keys: add yours again after.
Removing a key ends any SFTP session signed in with it at its next request; a key's "last used"
changes only when a session really starts.

In FileZilla (Site Manager → New site):

| Field | Value |
| --- | --- |
| Protocol | SFTP - SSH File Transfer Protocol |
| Host | The address on the Settings card (the Tailscale address, `localhost` through a tunnel, or the host's own address) |
| Port | The port on the Settings card (2222 by default) |
| Logon Type | Key file, and choose your private key (FileZilla converts an OpenSSH key when asked) |
| User | Your panel username |

On the first connection FileZilla shows the server's host key fingerprint. Check that it is the one
on the Settings card (and on your Account page) before you trust it.

The command-line client works the same way: `sftp -P 2222 -i ~/.ssh/id_ed25519 you@100.64.0.1`.

### Password and code

When a superadmin allows it, an account with two-factor authentication can sign in with
**Logon Type: Interactive**: FileZilla asks for the password, then the verification code from the
authenticator app. Each code works once. An account without two-factor authentication cannot sign
in with a password at all. Backup codes are not accepted over SFTP.

## What you see and can do

- The top folder lists one folder per game server you hold `edit_files` on (with access to that
  server), named after the server. Reading files also needs `view_files`, as in the file manager.
- Inside a folder: the game account's home. Files are read and written **as the game account**, never
  as root and never as the panel's own account.
- A link that leads outside the server's folder cannot be opened, listed or written through. Links
  cannot be made over SFTP.
- The file manager's rules apply: the LinuxGSM folder, `serverfiles`, the script and the account's
  own start-up files are never deleted or renamed; `~/.ssh`, `~/.bashrc` and the other sign-in files
  are never written (`~/.forward` too), nor what the account's services read when they start
  (`~/.config/systemd`, `~/.local/share/systemd`, `~/.config/environment.d`, `~/.config/containers`,
  `~/.config/user-tmpfiles.d`, `~/.local/share/user-tmpfiles.d`, `~/.local/share/dbus-1`) or the
  folders above them; LinuxGSM's own `_default.cfg` is never written; a LinuxGSM config that would
  switch `logtimestamp` on is refused whole (it freezes the live console); the live console's log and
  its folders are never changed; names with control characters, text-direction characters or spaces
  at either end are refused.
- Renaming never replaces a file that is already there. Moving between two servers' folders is not
  possible.
- An upload larger than the limit, or one that would leave less than 256 MiB free on the game host's
  disk, is refused. A new file is staged and only moved into place when it completes, so a refused one
  leaves nothing. Writing into, or appending to, an existing file changes it in place: the part written
  before the refusal stays (it is within the limit), so check that file afterwards.
- Every upload, delete, rename, new folder and permission change is recorded in the audit log, about
  that server, with your address. Reads are not recorded.
- A session ends at its absolute limit (8 hours by default, the panel's own sign-in limit): after it, a new
  listing, open, rename or delete is refused with "This SFTP session has reached its time limit"; a file already
  open can finish for up to an hour; then the session is closed, recorded in the audit log, and you sign in again.
- A session with no SFTP request for the idle timeout (15 minutes by default) is closed by the service and
  recorded in the audit log; a transfer in progress is activity. Most clients reconnect when you next click.
- Permissions are checked again on every request: when an administrator removes your access, signs
  you out everywhere or deactivates your account, the next request is refused. A file already open
  stops working within a second. When the panel cannot answer that check (it is busy, or waiting on
  a host that stopped answering), an open file goes on for up to 5 seconds on its last answer, then
  fails with "try again"; a refusal is never put off. One host's checks use at most a quarter of the
  panel's answer slots, so a host that stopped answering does not hold up the others.

## Signing in safely

- Sign-in counts against the same limits as the web sign-in: 8 failures from one address in 5
  minutes, then a pause; a day limit per address; and a pause for a name after repeated wrong
  passwords (password sign-in only: a key cannot be guessed, so wrong passwords sent by someone else
  cannot lock you out of key sign-in). Each failure is in the audit log and in `data/auth.log`, which
  the panel's fail2ban jail reads.
- A deactivated account, one that must change its password first, and one that Settings requires
  two-factor authentication of and has none, cannot sign in.
- The client only ever learns that sign-in failed; the reason is in the audit log.

## Performance

The service runs in its own process, so a large transfer never slows the panel's pages or the live
console. Files on a **remote** host travel through the panel's host (the panel opens an SFTP session
to that host as the game account), so the speed is the slower of the two links. Requests are
pipelined in both directions.

Measured on one development machine (an 8-core desktop, files on the panel's own host, paramiko's
client over 127.0.0.1): a 100 MiB upload took 1.6 s (about 63 MiB/s) and the same download 0.3 s.
That is a measurement of one machine, not a promise; a remote host adds the second hop.

## How it works (for administrators)

- The service is `panel/services/sftp_server.py`, a child process of the panel started and stopped
  by `panel/services/sftp_broker.py`. It stops when the panel stops, and is started again if it
  ends.
- Each game server's files are reached through the host's own OpenSSH `sftp-server` program, run as
  the game account: on the panel's host with `sudo -u <account>` (the panel's sudoers grant
  already allows becoming a game account), on a remote host over the panel's existing SSH connection
  to it. `sftp-server` is run with `-P symlink,hardlink`.
- The host key is Ed25519, made the first time the service is turned on, and kept in `config.json`
  encrypted with the panel's key ring, like every other stored secret.

### Algorithms

The service offers OpenSSH's own defaults (sshd_config(5)) as far as the SSH library implements them,
and nothing older:

| Kind | Offered |
| --- | --- |
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521` |
| Ciphers | `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`, `aes256-ctr`, `aes192-ctr`, `aes128-ctr` |
| MACs | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512`, `hmac-sha2-256` |
| Host key | ssh-ed25519 |
| User keys | ssh-ed25519, ecdsa-sha2-nistp256/384/521, rsa-sha2-512, rsa-sha2-256 (RSA of 3072 bits or more) |

No SHA-1 key exchange or MAC (RFC 9142 moves the SHA-1 exchanges to "SHOULD NOT"), no CBC cipher, no
DSA key and no `ssh-rsa` (SHA-1) signature. RSA keys need 3072 bits: NIST SP 800-57 Part 1 Rev. 5
rates RSA-3072 at the 128-bit security of Ed25519 and P-256, and RSA-2048 at 112 bits.

### Sources

- OWASP Authentication Cheat Sheet: "Login Throttling", "Account Lockout", "Authentication and
  Error Messages", "Logging and Monitoring", "Re-authentication After Risk Events". Its brute-force
  advice is why keys are the default: a key cannot be guessed.
- OWASP Multifactor Authentication Cheat Sheet: 4 "Quick Recommendations", 5.2 "When to Require
  MFA", 5.3.2 "TOTP Seeds and Validation Window" (a code is used once), 5.5 "Failed Login Attempts".
- OWASP Authorization Cheat Sheet: "Deny by Default", "Validate the Permissions on Every Request".
- OWASP Session Management Cheat Sheet: "Session Expiration" (idle 15 to 30 minutes for most applications, 2 to 5
  for high-value ones, enforced on the server, the session invalidated). An SFTP session is mapped to a web
  session; its activity is its SFTP requests, so an open but unused client is idle and a long transfer is not.
  "Absolute Timeout" (every session gets one, regardless of activity; 4 to 8 hours as the example): the
  panel's own sign-in limit, with an hour's grace for a file already open (the recommended 4 GiB upload over a
  10 Mbit/s link).
- OWASP Path Traversal Prevention Cheat Sheet: "Validate the Resolved Path", "Symbolic Links and
  Race Conditions" (files are reached as the game account, so a link can only reach what that account
  can).
- OWASP File Upload Cheat Sheet: "Upload and Download Limits", "Filename Safety", "User
  Permissions". Its extension allow-list does not fit: a game server's files are configs, scripts,
  maps, mods and binaries of every kind. Only users with `edit_files` (already the right to run
  commands as the account) can write, as the game account, within the size limit.
- OWASP Key Management Cheat Sheet: "Key Strength" (NIST SP 800-57, SP 800-131A), "Storage".
- OWASP has no SSH or SFTP cheat sheet; the OpenSSH manuals (sshd_config(5), sftp-server(8)) and
  RFC 9142 are the next authorities used.
