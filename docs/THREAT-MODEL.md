# Threat model

This is the panel's threat model, written to the OWASP Threat Modeling Cheat Sheet: its four
questions, a data-flow model with its trust boundaries, STRIDE against each boundary, a response for
every threat, and how the result is checked. It describes `main`; keep it in step with the code (the
"Keeping it current" section says when).

| Question | Where it is answered |
| --- | --- |
| What are we working on? | [System model](#system-model), [Assets](#assets) |
| What can go wrong? | [STRIDE per trust boundary](#stride-per-trust-boundary) |
| What are we going to do about it? | The mitigations in each table, and [Residual risks](#residual-risks) |
| Did we do a good enough job? | [Review and validation](#review-and-validation) |

Technique: STRIDE per trust boundary, chosen because the panel's risk sits where data crosses from
one owner to another (a browser to the panel, the panel to root, the panel to a game account). It
does not cover privacy threats as LINDDUN would, nor business-logic abuse beyond what the
permission model expresses; those are named under residual risks where they matter.

## System model

The panel is a Flask application (`panel/install/app.py`, routes in `panel/routes/`) that manages
LinuxGSM game servers on its own host and on remote hosts over SSH. It keeps its state in SQLite
(`data/panel.db`) and its secrets encrypted at rest (`data/cred_key`, `panel/core/cred_keyring.py`).

```mermaid
flowchart LR
  subgraph Internet
    B[Browser / phone]
    PS[Push services<br/>FCM, Mozilla, Apple, WNS]
    CH[Telegram / Discord / ntfy]
    GH[GitHub: code, releases,<br/>release-signatures]
  end
  subgraph PanelHost[Panel host]
    P[Panel web app<br/>panel user]
    DB[(panel.db + cred_key)]
    H[panel-helper<br/>root]
    GA[Game accounts<br/>lgsmpanel-games]
  end
  subgraph Remote[Remote hosts]
    RS[sshd]
    RG[Game accounts]
  end
  DBS[(Database servers<br/>MariaDB/MySQL)]
  B -- "TB1 HTTPS (Tailscale Serve / proxy)" --> P
  P -- "TB2 sudo + verb" --> H
  P -- "TB3 sudo -u account" --> GA
  P -- "TB4 SSH (pinned host key)" --> RS
  RS --> RG
  P -- "TB5 HTTPS POST" --> PS
  P -- "TB5 HTTPS" --> CH
  CH -- "TB5 bot commands" --> P
  P -- "TB6 db-query as the database's own account" --> DBS
  GH -- "TB7 signed update" --> H
  P --- DB
```

Trust boundaries:

| ID | Boundary | Who is on the far side |
| --- | --- | --- |
| TB1 | Browser to panel | anyone who can reach the port; signed-in users with a role |
| TB2 | Panel to root (the helper) | the panel's own account, which a web compromise would hold |
| TB3 | Panel to game accounts | game server processes, mods and plugins, players' data |
| TB4 | Panel to remote hosts | the remote's sshd and its game accounts |
| TB5 | Panel to push services, chat channels and other outside services | third-party services; anyone in a bot's channel |
| TB6 | Panel to database servers | database contents written by players and plugins |
| TB7 | GitHub to an installed panel (updates) | anyone holding the GitHub account or a CI token |
| TB8 | CI runners (pull-request code) | anyone who opens a pull request |

## Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| Root on the panel host | the helper runs as root; the wide grant is root outright | `/usr/local/lib/linuxgsm-panel/panel-helper`, `/etc/sudoers.d/linuxgsm-panel` |
| Accounts, sessions and 2FA seeds | a superadmin is root-equivalent on the panel host | `panel.db` (`panel/db/models.py`), session cookie |
| Stored secrets: SSH passwords and key paths for remotes, bot and channel tokens, database passwords, VAPID key | each opens another system | `panel.db` and `config.json`, encrypted with the key ring; an SSH key file itself stays on disk, protected by its file permissions |
| The key ring | decrypts every stored secret | `data/cred_key` (mode 0600) |
| Game servers and their files, worlds and backups | the service the panel exists for | game accounts' homes, local and remote |
| Databases of game servers | players' data | MariaDB/MySQL, local or on another machine over Tailscale |
| The release key and the update path | every panel installs what it verifies | the signer's machine; `release-signatures` branch; `panel/install/release-signers` |
| Audit log | accountability for every change | `panel.db` `audit_log` (`panel/security/auth.py` `log_action`) |

## STRIDE per trust boundary

Each row is one threat, the response (Mitigate, Eliminate, Transfer, Accept) and the controls with
the file that holds them.

### TB1: browser to panel

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| S | Password guessing, credential stuffing | Mitigate: Argon2id hashes, per-account throttle and lockout, a new password screened against the bundled common-password rules, a downloaded list of 100,000 breached passwords and (when the setting is on) Pwned Passwords, 2FA, which Settings can require for administrators (off by default) and which then holds every page and every Socket.IO path (connect, console join, terminal events and both revocation sweeps ask `account_guard.held_at_sign_in_gate`, because a before_request never runs for a socket event) (`panel/security/account_guard.py`, `panel/security/auth.py`, `panel/core/common_passwords.py`, `panel/core/breached_passwords.py`, `panel/routes/server_files.py`, `panel/routes/host_terminal.py`). |
| D | Wrong guesses keep a named account (the superadmin's) locked out | Mitigate: device cookies (OWASP "Slow Down Online Guessing Attacks with Device Cookies"): a browser that signed in to the account holds a signed cookie (HMAC-SHA256 under its own key, account id and a random nonce, rotated at each sign-in; `__Host-`, Secure, HttpOnly, SameSite=Strict over HTTPS) and is counted on its own, so the name's pause holds only unknown clients. A known browser's own failures pause that browser; the address limits and fail2ban apply to every client (`panel/security/device_cookie.py`, `panel/security/account_guard.py`, `panel/routes/auth_routes.py`). Accept: a browser that signed out (Clear-Site-Data drops the cookie) or never signed in is held by the name's pause until it ends. |
| I | A new password leaves the panel for the breach check | Mitigate: k-anonymity: only the first five hex characters of its SHA-1 go to `api.pwnedpasswords.com`, the answer is padded, the match is made locally; nothing else is sent. Only after the local checks pass; Settings switches it off; no answer within 3 s keeps the local result (`panel/core/breached_passwords.py`). |
| S | Session theft or fixation | Mitigate: `__Host-` cookie, Secure/HttpOnly/SameSite, rotation on sign-in, idle and absolute limits, session bound to its client address (IPv6 by /64) and User-Agent under "strong" protection, server-side revocation (`__Host-` prefix in `panel/security/auth.py`; `panel/security/session_cookie.py`, `panel/core/session_policy.py`). Sign-out deletes the remember cookie with the cookie's own Secure, HttpOnly, Path and SameSite attributes, so a browser applies it to a `__Host-` cookie, and sends `Clear-Site-Data: "cache", "cookies", "storage"` (`remember_deletion_with_attributes` in `session_cookie.py`; `panel/routes/auth_routes.py`). |
| T | Cross-site request forgery | Mitigate: CSRF token on every state-changing request (Flask-WTF `CSRFProtect`, `panel/install/app.py`), Fetch Metadata guard with the Origin/Referer check as its fallback (`panel/routes/account_security.py`), SameSite cookie. A page left open across a new session gets that session's token in the JSON refusal of an in-page request and resends it once (`_csrf_refused`, `panel/static/js/panel.js`); only same-origin script can set the header or read the reply. Behind a proxy that hides the panel's address, the target origin is configured (`site_domain`, `manage.py set-site-domain`) and the journal says so when a form was refused for it. |
| S | Traffic read or altered in transit | Mitigate: HTTPS through Tailscale Serve, a reverse proxy or the panel's own TLS (ECDSA P-256, SHA-256, 397 days, `panel/services/certs.py`; TLS 1.3, and TLS 1.2 with ECDHE AEAD suites only, no CBC: OWASP Transport Layer Security Cheat Sheet, `tls_context` in `panel/core/wsgi_serve.py`), HSTS. The operator's own certificate goes in through Settings (pasted, or a Let's Encrypt one copied by the helper's `tls-le-copy` verb: one validated name the operator opened at install (`PANEL_TLS_LE_NAMES`, root-owned `panel.conf`), fixed paths, root-owned PEM only; `panel/services/tls_own.py`): a mismatched key, passphrase key, unreadable file or expired certificate is refused, a weak key, SHA-1/MD5 signature, uncovered panel address, self-signed certificate or missing chain is noted. It is never replaced by a self-signed one, a renewed Let's Encrypt certificate is loaded daily, HSTS is sent with a CA-signed one (one day for its first 30 days, then two years), and the expiry alert starts 30 days ahead. |
| T | Injection (SQL, shell, template, path) | Mitigate: SQLAlchemy bound parameters; validation before a value reaches a shell (`panel/core/validation.py`); no shell between the panel and root (TB2); Jinja autoescape; strict CSP: scripts and style elements only from the panel or carrying the per-request nonce, no `'unsafe-inline'` anywhere, `style-src-attr 'none'`, `object-src` and `base-uri` `'none'` (OWASP Content Security Policy Cheat Sheet, "Nonce-based Strict Policy"; built in `panel/install/app.py`, sent by `panel/security/headers.py`). Pages also send Cross-Origin-Opener-Policy `same-origin` and Cross-Origin-Embedder-Policy `require-corp`, and every response Cross-Origin-Resource-Policy `same-origin` (OWASP HTTP Headers Cheat Sheet). |
| R | A user denies a change | Mitigate: audit row for every change with actor and address (`log_action`); denials logged (`account_guard.py`). |
| I | Secrets shown to a role that should not see them | Mitigate: permission per route (`panel/security/auth.py`), server access per group, LinuxGSM `details` masked for roles without MANAGE_SERVERS, debug report scrubbing (`panel/ops/debug_report/privacy.py`). |
| D | Request floods, huge uploads, log flooding | Mitigate: a malformed request line (no HTTP version, an unknown protocol) is refused before the app with nothing logged and no version named, and a client that hangs up mid-response (closes or resets the connection) leaves no traceback, while any other failed response is logged in full (`panel/core/wsgi_serve.py`); app-wide request cap, chunked uploads with size limits (`panel/routes/backup_upload.py`, `panel/routes/databases_files.py`), the panel's own ban list (`panel/security/banlist.py`) beside fail2ban. Transfer: volumetric floods to the network in front (Tailscale or a proxy). |
| E | A lower role reaches an admin action | Mitigate: deny by default, permission checks on every request, step-up re-authentication for root-equivalent actions (`account_guard.py`), the owner account no other admin can change (`panel/security/owner.py`). |

### TB2: panel to root (the helper)

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| S | Another local process poses as the panel | Mitigate: sudoers grants the helper to the panel's account only; the helper is root-owned outside the checkout. |
| T | The panel (if compromised) hands root a crafted command | Mitigate: verbs, not shell text: the helper re-validates every argument against its own table and execs a fixed argv (`tools/panel-helper`, mirrored by `panel/security/privileged.py`); destinations and log sources are names, not paths. |
| T | Root runs bytecode that is not the installed helper's code | Mitigate: the file sudo runs is a small entry (`tools/panel_helper_entry.py`) that loads the helper's bytecode only when every directory from `/` down and both files are root-owned with no group or other write bit and no symbolic link, checked through file descriptors, and the pyc is a checked-hash pyc (PEP 552) of the installed code; otherwise it compiles the code as before. The hash catches a stale pyc, the ownership test a planted one; root compiles it at install from the same signed source. |
| T | Root runs code from the panel-owned checkout | Eliminate: root stages its pieces from its own clone, at or above a source floor, and only signed commits (see SECURITY.md, "Root never runs or installs from the panel's checkout"). |
| R | Root actions without a trace | Mitigate: each root-equivalent action is audited by the route that starts it (`log_action`). |
| I | Secrets on a command line | Mitigate: secrets travel on stdin (`run_privileged(..., secrets=...)`), never argv. |
| D | A verb hangs the host | Mitigate: timeouts on every verb call; long jobs are detached with their own bounds. |
| E | The panel (if compromised) gains root through root's crontab | Mitigate: `root-crontab-read` and `root-crontab-write` are refused by the helper on the panel host unless the operator opened them at install (`PANEL_ROOT_CRON=1`, recorded root-owned in `panel.conf` as `root_cron=yes`; default closed). The write checks every line's shape (cron's own schedule grammar, no control characters), takes the content on stdin, and installs it only while root's crontab still hashes to what the page read. In the panel the root cron page is off by default, the panel owner's only, and every change asks for the password (and 2FA code) in the same request and is audited with the old and new line (`panel/routes/root_cron.py`). |
| E | The panel (if compromised) gains root through the add-on verbs | Mitigate: `addon-account-prepare` takes an account name only, refuses the panel's own account and any account outside `lgsmpanel-games`, adds only a subordinate id range the account lacks (after every range in use, so ranges never overlap) and turns on lingering; Podman comes from Ubuntu's archive through the fixed `apt-install` list. Rootless containers give an account nothing beyond what its own uid has. |
| E | Wide grant (`NOPASSWD: ALL`) when a root piece is missing | Accept, stated: the installer prints which grant it wrote; SECURITY.md tells how to get the narrow one or drop the local grant. |

### TB3: panel to game accounts

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| S | An account name that is really root or another user | Mitigate: `game_user_cmd` / `game_user_exec_cmd` refuse anything but a plain identifier, never `root`; Runas is `%lgsmpanel-games` only. |
| T | A game account that can escalate is enrolled, then driven by the panel | Mitigate: enrollment refuses accounts in root-equivalent groups or named by sudoers/doas/polkit; every write path calls `game_account_write_refusal` first (`panel/routes/_shared.py`). |
| T | Files the panel writes for a game account start code later (shell start-up files and what the distribution's `~/.bashrc` sources, `~/.ssh`, `.rhosts`, `.k5login`) | Mitigate: the file tools refuse such targets (resolved host-side), and a game restore, of an uploaded archive too, keeps the account's own copies and never takes the archive's (`_LOGIN_FILES` in `panel/ops/ssh_manager/files.py`, `KEEP` in `panel/services/game_restore.py`). |
| I | Game output (console, logs, player names) carries escapes or markup | Mitigate: terminal rendering strips control sequences (`panel/core/terminal.py`, fuzzed by `tests/fuzz/fuzz_console.py`); templates escape. |
| D | A game's output floods the panel | Mitigate: bounded reads and rings for console feeds. |
| E | A mod or plugin uses the panel to reach root | Mitigate: game accounts cannot write `/etc`, the helper or sudoers; the panel never runs game-authored text as a command. |
| T | An add-on image is swapped or tampered with upstream | Mitigate: IW4MAdmin's image is pinned by digest in `panel/services/addons.py` and pulled once at install (`Pull=never` at every start); the publisher was checked (IW4MAdmin's own release workflow pushes `ghcr.io/raidmax/iw4madmin`). B3's image is built on the host from `panel/addon_images/b3/`: the base image by digest, B3's source at one commit (the build fails unless the checkout is exactly that commit) and its Python packages by hash, from wheels only (pip `--require-hashes`). Accept, stated: IW4MAdmin's image is a third party's build, not reproduced or signature-checked here; the B3 build's `apt-get install git` (its first stage only) takes Debian's current signed packages. |
| E | An add-on (third-party code) escapes its container or reaches more than it needs | Mitigate: rootless Podman as the game account (container root is that account), every capability dropped, no new privileges, read-only root filesystem, memory and process caps, restart limit (OWASP Docker Security Cheat Sheet rules 3, 4, 7, 8, 11); its own network namespace (pasta) reaching only what is forwarded to the host's loopback: the game's RCON port, a database on this host, and relays (systemd-socket-proxyd as the account, each to one fixed address) for a database on another machine and for B3's geolocation when it is chosen; on Ubuntu 26.04 `--splice-only` leaves it no interface but loopback; on 24.04 `-o 127.0.0.1` and `-4` keep it off the internet and other machines; its DNS off; its page published on 127.0.0.1 only; the game's log folder mounted read-only. Install and remove need Manage add-ons (no group by default) and step-up; every action is audited (`panel/routes/addons.py`); a unit check pins the network options (tests/unit/part255.py). Accept: a kernel flaw is shared by every container. Open, on Ubuntu 24.04 only: a service listening on one of the host's own non-loopback addresses (its Tailscale address, say) is reachable from the container; pasta 2024-02 has no option that closes it. |
| I | An add-on's settings hold the RCON and database passwords | Mitigate: written over stdin, never on a command line; the file is 0600 in a 0700 folder of the game account, which could already read both; the log view and the log lines of a failed install, Apply, Update or Start mask the server's database passwords and the RCON passwords: the game config's and b3.ini's, read by the same shell that reads the log (`secrets_sh`), and any value written as an rcon_password or rconpassword setting, so a failed read still masks a config line a log echoes (`panel/services/addons.py` `scrub`; OWASP Logging Cheat Sheet, "Data to exclude"). |
| I | B3's geolocation sends players' IP addresses to third parties | Mitigate: off unless chosen at install, with a plain note on the card saying what is sent and to whom (ipwho.is); when on, the container reaches only that service, through its own relay (B3's second service, ipapi.co, is not reachable: pasta's -T takes no address, so only one service fits on port 443). Nothing is sent to Google (B3's translator plugin, which uses Google's translation service, is never turned on). |
| I | A later account given a removed account's uid reads the old add-ons' logs | Mitigate: journald names a user's journal by uid, so `addon-account-release forget` (run at every uninstall; the last add-on's removal runs `keep`, which leaves the account's journal alone) deletes that uid's user journal files, rotating the journal first only when an active file is there (journalctl has no narrower rotation), and Podman's `/tmp` folders for it, for uids of 1000 or more only, matching exact file names (`tools/panel-helper` `_addon_forget_account`). journald keeps a user journal it opened until it restarts and re-creates it, empty, at every rotation, so after its rotation the verb also deletes the active file of any uid that has no passwd entry and no process when that file holds no entries; archived files of other uids are never touched (`_orphan_user_journals`). Removing the last add-on also removes the account's Podman storage (`podman system reset`). |
| E | A later account given a removed account's uid inherits its tmux socket folder | Mitigate: useradd reuses a deleted account's uid, and tmux trusts a socket folder (`/tmp/tmux-<uid>`) that its uid owns. `addon-account-release forget` (every uninstall) removes `/tmp/tmux-<uid>` and the JVM's `/tmp/hsperfdata_<account>`, each only when it is a real folder (lstat: a link is never followed) owned by that uid, and only for uids of 1000 or more (`tools/panel-helper` `_forget_account_tmp`; the remote form `panel/security/journal_forget_sh.py` `account_tmp_sh`). OWASP's "Insecure Temporary File" page: a pre-existing entry with a predictable name in a shared /tmp lets one user affect another's. |
| E | An operator's own B3 plugin runs code the panel never checked | Accept, off by default: B3's own-plugins folder (`Data/extplugins`) is loaded only after the operator turns it on in B3's settings, which shows the warning, asks again, takes the step-up confirmation and is audited (`addon_settings`, "own plugins on"). The folder is mounted read-only (OWASP Docker Security Cheat Sheet rule 8), so B3 can't rewrite the code it loads; the container keeps its read-only root, dropped capabilities, no-new-privileges and loopback-only network. What such a plugin can reach is what B3 can: its database and the game's RCON. |
| T | A tampered or substituted DB-IP country database reaches B3 | Mitigate: downloaded by the panel's host only for a B3 set to offline geolocation and only while Settings → Outside services has DB-IP on; https to db-ip.com and download.db-ip.com only (a redirect anywhere else is refused); size caps on the page, the .gz and the unpacked file; kept only when its SHA1 matches the one db-ip.com's page publishes and it carries the MaxMind DB marker; written to the add-on's folder as the game account and mounted read-only (`panel/services/geoip.py`). The file is data: B3's maxminddb reader parses it, and the container has no network beyond the game and its database. |
| E | An add-on update or settings change runs new code as the game account | Mitigate: MANAGE_ADDONS, server access and step-up as for install; audited (`addon_update`, `addon_settings`); the image is the catalog's pin (an IW4MAdmin digest, or B3 built from one fork commit with hash-pinned wheels), proposed by Renovate as a reviewed PR; the unit is rewritten with the same lock-down (`panel/routes/addons_change.py`). |

### TB4: panel to remote hosts

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| S | Man in the middle on the first or a later connection | Mitigate: host keys pinned on first use and enforced after (`panel/ops/ssh_manager/_core.py` `_PinPolicy`); an optional fingerprint on the Add Remote Server form and Edit makes the first connection verified too, refused before the credential is sent when it does not match (`panel/routes/remotes.py`). Accept: without a fingerprint the first connection is trust on first use. |
| T | Remote output crafted to mislead the panel's parsers | Mitigate: parsers degrade to empty on bad input and are fuzzed (`tests/fuzz/`: status replies, ufw, cron, configs, fail2ban). An empty read is never taken as a measurement. |
| I | Stored SSH credentials leak | Mitigate: passwords and key paths encrypted at rest with the AES-256-GCM key ring; never logged; backups hold them encrypted. A key file is not copied into the panel: it stays where the operator keeps it, under its file permissions. |
| E | Panel's own host reached through a "remote" entry | Mitigate: bootstrap, Tailscale install and join routes refuse the panel's own host. |

### TB5: push services, chat channels and other outside services

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| S | A browser registers a push endpoint that points at an internal address (SSRF) | Mitigate: allow-list of push service hosts, https:443 only, request rebuilt from the parsed parts, every resolved address must be public (IPv4 carried in IPv6 unwrapped, IPv4-compatible refused), connect to the checked address, no redirects (`panel/services/webpush.py`; fuzzed by `tests/fuzz/fuzz_push.py`). |
| S | Someone takes over another account's subscription | Mitigate: a subscription moves only with proof of holding it (`panel/services/push_alerts.py`). |
| S | A stranger in a bot's channel sends commands | Mitigate: only the configured chat is answered; in it, commands that change anything run only for listed user ids, and the read-only /status, /servers, /hosts, /connect and /help are open (`panel/services/bots/commands.py` `OPEN_COMMANDS`, `command_refusal`; `panel/services/notifications.py` `parse_command_users`). |
| S | A stranger links their own Telegram chat to someone's account and gets that account's alerts | Mitigate: a link needs a one-time code the signed-in account asks for after a password re-check (128 random bits, SHA-256 at rest, 10 minutes, once, five per account per 10 minutes), claimed only from a private chat; the chat id is encrypted on the account, the link is audited and shown to the account as a change to its security (`panel/services/telegram_link.py`, `panel/routes/push_devices.py`). A linked chat only receives: commands still come from the chat on the Notifications page. |
| I | Alert text reveals more than a lock screen should | Mitigate: push text is the event and the server's name only; endpoints and keys never logged. |
| D | A slow push service stalls the panel | Mitigate: one background sender, bounded queue, timeouts. |
| I | An outside service learns that this server exists and what it asks (update checks, LinuxGSM's files, game icons, Workshop titles, Modrinth, the public address, the breached-password check) | Mitigate: local first, the minimum sent (k-anonymity for the password check), and one switch per service in Settings → Outside services, enforced where each request is made (`panel/core/outside_services.py`); docs/PRIVACY.md lists each service and what it is sent (OWASP User Privacy Protection Cheat Sheet, "Prevent IP Address Leakage"). |

### TB6: database servers

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| T | A statement reaches another database | Mitigate: every statement runs as the database's own account, whose grant is that one database; identifiers come from the structure the panel read, values are bound parameters (`panel/ops/ssh_manager/db_data.py`). |
| T | An uploaded dump switches to another database | Mitigate: the upload scan is a small SQL lexer (strings, quoted names, `--`, `#`, block and executable comments, any blank between words, across lines) and refuses USE, CREATE/DROP/ALTER DATABASE, CONNECT and schema-qualified names of system or other panel databases; it also refuses what would make the client or server read the text differently from it (an `sql_mode` with NO_BACKSLASH_ESCAPES or ANSI_QUOTES, a big5/cp932/gbk/gb18030/sjis client character set, client commands, a quoted DELIMITER, version-gated comments a server could end early) and SQL built or loaded while it runs (PREPARE/EXECUTE, LOAD DATA) (`panel/ops/ssh_manager/db_upload_scan.py`; fuzzed by `tests/fuzz/fuzz_upload_scan.py`, mawk against gawk). The grant above still holds for what the scan does not read. |
| I | The audit log records a value typed into the SQL box | Mitigate: literals masked, comments skipped (`db_data.mask_literals`; fuzzed by `tests/fuzz/fuzz_db_data.py`). Each literal is read both with backslash escapes and as under NO_BACKSLASH_ESCAPES; where the two disagree about its end, the rest of the statement is not logged (`_mask_quoted`; tests/unit/part219.py). |
| I | A database on another machine is reachable from the internet | Mitigate: remote database servers only over Tailscale; the panel reports a server listening beyond loopback and the tailnet. |
| D | A runaway query | Mitigate: statement time limit with KILL QUERY, answer size cap (`tools/panel-helper` db-query). |

### TB7: GitHub to an installed panel

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| S | A commit merged by someone holding the GitHub account | Mitigate: panels install only commits signed with the release key, kept off GitHub, verified against the key the host already holds (`tools/sign-release.sh`, `install.sh`). |
| T | A dependency changed upstream | Mitigate: hashed lockfiles, installed in pip's hash-checking mode (pip itself `--require-hashes`, the panel's packages `--no-deps`, every line hashed) (`install.sh`); gamedig from a hash-locked npm lockfile; dependency review, pip-audit and osv-scanner in CI; a CycloneDX SBOM attached to each GitHub Release (`tools/sbom.py`). |
| T | The downloaded breached-password list is altered | Mitigate: fetched from a fixed SecLists commit and saved only when it hashes to the SHA-256 pinned in `install.sh`; the panel re-hashes it on every read and skips it on a mismatch (`panel/core/breached_passwords.py`). |
| R | Which code a release contains | Mitigate: release notes from the CHANGELOG, the signature and the SBOM on the release; the SBOM is reproducible from the tagged commit. |
| E | First install trusts whatever GitHub serves | Reduce, then accept: the release key's fingerprint is published in README and SECURITY.md, which shows how to check the commit's release signature before the first install; unchecked, it is trust on first use. |

### TB8: CI runners

| STRIDE | Threat | Response and controls |
| --- | --- | --- |
| T | Poisoned pipeline execution from a pull request | Mitigate: no `pull_request_target`; `workflow_run` jobs run main's copy and treat artifacts as untrusted; actions pinned by full SHA; required checks and signed commits on `main` (OWASP Top 10 CI/CD Security Risks, CICD-SEC-1 and CICD-SEC-4). |
| I | A secret reaches pull-request code | Mitigate: the only secrets live in environments only `main` can use; pull-request jobs hold the job token alone (CICD-SEC-6). |
| E | A job's token can do more than the job needs | Mitigate: every workflow starts with `permissions: {}` and each job grants only what it uses (CICD-SEC-5). |
| I | A compromised tool sends data out of a runner | Mitigate: Harden-Runner on every job but the deploy; the pull-request jobs that reach only known hosts run it in block mode with an allow-list (the unit suites' `checks` matrix, their coverage and JavaScript coverage jobs, and Lighthouse among them); the rest audit (CICD-SEC-7, CICD-SEC-10). |

## Residual risks

| Risk | Response | Why, and who owns it |
| --- | --- | --- |
| A superadmin is root on the panel host | Accept | The panel manages the host, and every superadmin keeps its host-level powers there (firewall, SSH, OS updates, reboot, the panel's port, Tailscale, IP blocking, Ubuntu Pro) by design. The controls are step-up re-authentication before each of those changes and an audit row for each; the panel-host terminal and panel backup restore stay the panel owner's only. SECURITY.md says so and how to drop the local grant. Owner: whoever grants superadmin. |
| The panel owner can run any command as root through root's crontab | Accept, opt-in | That is the root cron page's purpose. It is off by default, the owner's alone, re-confirmed with the password on every change and audited; on the panel host the operator must also open it at install (`PANEL_ROOT_CRON=1`). On a remote host the panel is root by design already. The audit row keeps the line, which superadmins can read, so the page tells the owner to keep secrets in a root-only file rather than in the line. Owner: the panel owner, and the operator for the panel host. |
| A game account's own sign-in files (`~/.bashrc`, `~/.profile`, `~/.k5login` and the like, `~/.ssh`) can still be planted by what an account-level grant writes | Accept | The file browser refuses those paths and a game restore, of an uploaded archive under RESTORE_BACKUP too, keeps the account's own copies, but LinuxGSM sources the game's `.cfg` files as bash, so a write there (the config editor, a restored or uploaded archive's cfg) runs as the account and reaches the same files at its next start or monitor run. Game accounts are kept as they are on a plain LinuxGSM install, where the account can sign in over SSH, so no host-side control (such as sshd reading game accounts' keys from outside their homes) is added; docs/permissions.md says what giving these permissions amounts to. Owner: whoever grants RESTORE_BACKUP or EDIT_FILES. |
| Wide sudo grant on an install missing a root piece | Accept, with a fix path | The installer prints it, and the panel host's page tells superadmins while it lasts (`system_ops.wide_sudo_grant`), with the command; re-running install.sh as root narrows it. |
| First SSH connection to a remote, and the first install, are trust on first use | Reduce, then accept | The Add Remote Server form (and Edit) takes the host key's SHA256 fingerprint (RFC 4251 section 4.1: a fingerprint checked out of band); left empty, the first key is trusted. The release key's fingerprint is published in README and SECURITY.md, with how to check a commit's signature before the first install. |
| The upload scan is a lexer, not the server's parser | Reduce, then accept | Keywords split over lines, comments or any blank are now read, and the settings that would change how the text is read are refused. What it cannot see: statements inside routines already in the database that the dump calls, and a server whose own default sql_mode has NO_BACKSLASH_ESCAPES or ANSI_QUOTES (the scan reads with the defaults). The database account's one-database grant refuses those statements. Owner: whoever changes the database server's defaults. |
| The SQL box's audit line keeps numbers | Accept | String and hex literals are masked under either escape mode (a literal whose end depends on sql_mode masks the rest of the line), but decimal numbers stay in the audit line by design, so an id or amount typed into a statement is recorded. Owner: whoever grants EDIT_DATABASE_DATA. |
| Push services and chat platforms see alert metadata | Transfer | To the vendor, under its terms; the text is minimal. |
| An operator's own TLS certificate expires | Accept, with warning | With HSTS, browsers refuse an expired trusted certificate with no way past it, so the web page is unreachable until it is renewed; the panel and the host's shell keep working. The expiry alert warns from 30 days, and a Let's Encrypt certificate put in through Settings is reloaded daily once certbot renews it (docs/https.md section 5). Owner: the operator who installed the certificate. |
| Harden-Runner audit-only jobs (ClusterFuzzLite, main-only jobs) | Accept for now | ClusterFuzzLite runs in Docker containers with their own networking; a main-only job cannot be checked by a pull request before it holds every panel's update. The unit suites' `checks` matrix and Lighthouse now run in block mode: `checks` allows apt's regional mirror by a `*.archive.ubuntu.com:80` wildcard, and its TEST-NET dials are refused at once; Lighthouse allows the two hosts its throwaway panel fetches from and refuses Chrome's own calls, which are not the audited page's. tests/unit/part223.py lists each audit-only job with its reason, and each block-mode job's allowed hosts, and fails when a job's mode changes without that list. |
| Scorecard's action image is pulled by tag | Reduce, then accept | ClusterFuzzLite's images are pinned by digest now (the fuzz image's Ubuntu 24.04 base, and this repository's copies of its two actions, `.github/actions/cflite-*`), and Renovate proposes each new digest. Scorecard's cannot be: its results are published only from a job whose steps name the image by tag, so `scorecard.yml` records the digest, checks the tag against it before the analysis runs, and checks the digest the analysis job pulled after it. What is left is the seconds between the first check and the pull, which the second check reports. |

## Review and validation

- **Tests.** Nine suites run on every pull request that changes code (unit, smoke, rbac, template
  actions, input validation, URL map, manage, setup wizard, performance budget; a
  documentation-only one runs the unit suite alone, which reads the docs); every security check is
  proved by breaking the code it guards.
- **Fuzzing.** `tests/fuzz/` holds Atheris targets for the parsers of untrusted input, run 60 s each
  on pull requests that touch them, 600 s nightly, and by ClusterFuzzLite.
- **Scanners.** CodeQL, Bandit, Semgrep, zizmor, Gitleaks, pip-audit, osv-scanner, Dependency Review,
  SonarCloud and Codacy, with an open-alerts gate on main.
- **Penetration test.** An OWASP ZAP and WSTG test of a local panel (November 2026) found no critical
  or high issue; its medium and low findings were fixed in the next release. A second round the same
  month (ZAP, Nuclei, Nikto, Schemathesis, Dalfox, testssl.sh, Trivy) found nothing above low; its
  findings were fixed in the release after.
- **This document** was checked against the code it points to when written; a reviewer should be
  able to find every control in the file named beside it.

## Keeping it current

Update this file when a change adds a trust boundary (a new kind of host, service or account), a new
way in (a route family, a bot, an upload), a new privileged verb family, or a new stored secret, and
when a residual risk's response changes. SECURITY.md summarises it for reporters and operators.
