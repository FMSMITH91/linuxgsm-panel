# Changelog

All notable, user-facing changes to the LinuxGSM Panel. The project is pre-1.0 and alpha — see the
README disclaimer. Versioning is loosely [semantic](https://semver.org). Note: the panel's in-app
"update available" check compares git commits, so you always get the newest CI-verified commit
regardless of this file — this changelog is for humans.

## [Unreleased]

### Added
- **Download the console log** from the Live Console header — the full LinuxGSM log file, not just
  the slice on screen. It reuses the file browser's download route (the log lives under the game
  user's home), so it needs the same permission; the button is hidden for anyone who would only be
  bounced by it.
- **Line numbers in the file editor.** A gutter beside the editor, kept in step with the text as
  you type and scroll. The editor no longer soft-wraps (a wrapped line occupies several rows, which
  would push every number below it out of alignment) — long lines scroll sideways instead, as they
  do in any code editor. Drag the bottom edge to make the whole editor taller; the numbers follow.
- **Drag and drop now takes folders, and actually works.** Two separate problems. Dropping a
  *folder* never worked: the handler read `dataTransfer.files`, which for a folder is a single
  contentless entry — folder contents are only reachable through `webkitGetAsEntry()`, which is now
  walked recursively, so nested subfolders upload with their structure intact (the server already
  created missing parent directories, so nothing changed behind the API). And dropping a *file*
  often appeared broken: the drop target was the file-list panel alone, a couple of centimetres
  tall when the listing is short, and nothing suppressed the browser's own drop behaviour — so a
  near miss made the browser navigate the tab to the dropped file. The whole File Browser card is
  the target now, the page suppresses the default everywhere, and a miss does nothing instead of
  navigating away. Reported on Linux, but it behaved the same in every browser.
- **An "Upload folder" button**, for when dragging between the desktop and the browser misbehaves
  (common on Wayland). Same recursive upload, via the file picker instead of a drag.
- **Downloads in the file browser** — a download button on every row of Files & Config, plus one in
  the editor header for the file you have open. A file streams as-is: any type, any size, no 1 MB
  cap and no "binary file" refusal, because the editor's read and a download are different jobs. A
  folder downloads as a `.tar.gz` built while it streams, so pulling a whole `addons/` or `cfg/`
  directory is one click rather than a file at a time; it asks first, since a folder's finished size
  is not knowable up front. Protected files (the `lgsm` tree, `serverfiles`) are downloadable —
  protection is about deleting them. Needs the same permission as the rest of the file browser.
  Reads happen **as the game user**, never as root: a symlink under that home reaches only what that
  user could already read, and the path is re-checked on the host after the privilege drop. Over SSH
  the filename never appears in the command — the remote command is fixed text and the path travels
  on stdin, because a download over SSH gets parsed twice and that is where quoting bugs hide.

### Changed
- **Backup retention is typed, not picked from a list.** "Keep daily backups for", "Keep per
  server" and each server's own override were dropdowns offering a handful of values (1, 2, 3, 5,
  7, 14, 30) — so the number you actually wanted was only available if it happened to be on the
  list. All three are number fields now. A per-server override is set by typing a number and
  cleared by emptying the box, which is what its "Default" placeholder says.
  The server has always clamped these (1-30 game backups, 1-365 days), and it still does — but a
  clamp you cannot see is worse on a field you type into than on one you pick from: entering 100
  would have stored 30 while the page said "Saved". It now says **"Saved — 100 is out of range,
  kept 30"** and shows the stored number. The bounds come from the server, so the field and the
  clamp behind it cannot drift apart. Changing the global default also refreshes the rows that
  inherit it, instead of leaving them showing the old number until the next page load.
- **The pure helper layer moved out of `app.py`** into `panel/core/validation.py` (the input
  patterns, the port and password rules) and `panel/core/http.py` (how a handler answers: JSON for
  a fetch, flash-and-redirect for a form, and the two error shapes that keep exception text out of
  a response). They were defined in `app.py` and imported back out of it by most of
  `panel/routes/`, which every static analyser reads as a cycle even though the runtime imports are
  lazy. Nothing about a route changed — same endpoints, methods and guard chains, asserted against
  the committed URL-map baseline — and the names crossing that cycle dropped from 82 to 63.
- **A new test suite, `tests/input_validation_test.py`,** drives every numeric form field with the
  values a browser never sends — boundaries, blanks, non-numeric text, a newline, non-ASCII digits
  — and asserts a refusal with no row written, plus a positive control per field so it cannot pass
  against a route that refuses everything. The suites around it assert structure; none of them ever
  sent a handler a bad value, which is why the port bugs above survived them.
- **Running a test suite in-tree no longer edits your `data/config.json`.** Every suite that boots
  the app has to set `setup_complete` and a short SSH timeout, and deleting the file only when the
  suite created it left those edits behind on a developer's machine — where a leftover
  `ssh_timeout: 1` then failed a check in a *different* suite, pointing at config rather than at
  whoever wrote it. A pre-existing config is now restored byte-for-byte.
- **The application modules now live in a `panel/` package.** Eighteen of the twenty-one Python
  modules that sat loose in the repo root moved into `panel/{core,db,security,ops,services}/`,
  grouped by the layering the import graph already had — root drops from 37 tracked files to 19.
  Nothing a user sees changes, and no route, endpoint, method or guard moved: the URL-map snapshot
  matches its baseline byte for byte across all 208 rules. `app.py`, `manage.py` and
  `db_maintenance.py` deliberately stay at the root, because the systemd unit, `recover.sh` and the
  installer each address them by path, as do the shell scripts behind the documented install and
  recovery one-liners. `README.md` has the map. Two new gates keep it honest: one fails if a
  package imports *down* the stack at module level, the other if an on-disk path (`data/`,
  `translations/`, the git tree) goes back to being derived from a module's own `__file__` instead
  of `panel.REPO_ROOT` — which, during this move, silently pointed the database, secret key and
  credential key at `panel/core/data/` and would have presented a live install as a fresh one.
- **LinuxGSM's data files are no longer committed here.** `lgsm/data/serverlist.csv` (every
  supported game) and `lgsm/data/ubuntu-24.04.csv` (each game's apt packages) belong to LinuxGSM,
  and vendoring them froze the panel's game list at whatever upstream shipped the day the copy was
  taken — it was already **two games behind** by the time this replaced it, and the only way to add
  a newly-supported game was a panel release. They are fetched from LinuxGSM's repository and
  cached under `data/` (git-ignored, survives updates, refreshed weekly), so new games appear on
  their own. A response that is not the file we asked for — a captive portal's login page, a
  truncated body — is never cached, a stale copy is served when a refresh fails, and if there is no
  copy at all the install page says so and offers a Retry instead of rendering an empty menu.
- **Uploads are roughly an order of magnitude faster**, which matters most for a folder of many
  small files. Two things were wrong, and both were latency rather than bandwidth. Writing one file
  took at least **three SSH round trips** (create the directory, send a base64 chunk, decode it) —
  a file small enough for one command now takes **one**, and that is essentially every config,
  script and Lua file a game server holds. And the browser sent files **strictly one at a time**,
  leaving the link idle between them; up to four now upload at once. A 400-file gamemode was
  ~1,600 serialised round trips. Large files still stream in chunks. Both paths also write to a
  temp file and rename it into place, so a failure part-way can no longer leave a half-written file
  where the original was.
- **`ssh_manager`'s shell quoting is now `shlex.quote`** rather than a hand-rolled `'`-and-escape.
  The two produce equivalent shell words, so no command changes; the point is that the one thing
  every remote command depends on being right is the standard library's implementation, and static
  analysis recognises it as a sanitiser where it can know nothing about a local function returning
  an f-string. Its test changed with it: it asserted the old *spelling* (`_quote("abc") ==
  "'abc'"`), and now round-trips a dozen payloads — quotes, `$(id)`, backticks, tabs, newlines,
  non-ASCII — through a real shell and requires each to come back verbatim as a single argument.

### Fixed
- **A game server could be installed on a port that does not exist.** The install form took
  `int(port)` straight from the request with no range check at all, so `0`, `-5` and `99999` were
  stored on the row, opened in the firewall and written into the LinuxGSM config. Three other port
  fields in the panel each had their own bounds check — two of them with their own test — so the
  rule was never in doubt; the endpoint that actually writes a server was just the one nobody drove
  with a bad value. Ports are now parsed by one shared helper that carries the range with the parse,
  and enforced again at the data layer (a `@validates` hook, like the shell-identifier one beside
  it) so the next route to assign a port cannot skip it. Non-ASCII digits are refused too: Python's
  `int()` reads `٢٧٠١٥` as 27015, which meant a port nobody typed could be stored.
- **The port picker could hand back a port that was already in use.** After scanning 400 candidates
  it returned the last one it had tried — occupied by definition — and reported the search as
  successful, so the install went ahead and failed later on the host as the game's own
  "Port N was unavailable". The same walk could also run past 65535. It now reports that it found
  nothing and the caller refuses with a message that names the real problem.
- **Installing to a host that was switched off returned a 500.** Picking a free port scans the
  host's listening ports over SSH, and an unreachable host raised straight through the route. A
  host being down is a normal condition for this panel, not a fault in it — the install form now
  says so and writes no row.
- **The setup wizard could save a panel port that the panel cannot bind.** Step 1 writes the
  address the panel listens on, and nothing downstream re-checks it, so a typo of `0` or `99999`
  produced a panel that would not come back up on its next boot — recoverable only with
  `linuxgsm-panel-recover` or by editing `data/config.json` by hand. It is validated against the
  same bounds as the in-panel port change, which is where the code had always assumed it happened.
- **Rotating a remote's SSH credential did not take effect.** Editing a host rewrote its user, host,
  port and credential and committed without dropping the pooled SSH connection, so the panel kept
  authenticating with the OLD credential for as long as its 30-second keepalive held the socket
  open. Repointing a host at a different address was worse: the pooled entry became unreachable for
  the life of the process, because the only way to close a connection was to name the address the
  row currently held. The pool is now invalidated from the row itself, so it cannot be missed by a
  route added later.
- **A new game server could inherit a deleted one's status.** SQLite hands a deleted row's id
  straight to the next INSERT, and two id-keyed status maps — the last per-server backup outcome,
  and the GMod content-install state — were not among those cleared when a row goes away. Both are
  read to render a server's page, so a newly created server could show the previous one's failed
  backup, or a content install frozen at "running". The maps register themselves for pruning now
  rather than being listed by hand somewhere else, which is how these two were missed.
- **An update that changed only the privileged helper raised no "update available" badge.**
  `tools/panel-helper` is the root-owned end of the sudo boundary and only `install.sh`, run as
  root, can refresh it — the badge is what tells the operator to do that. It was classified as
  documentation-style noise along with the rest of `tools/`, so the panel could move on while the
  installed helper did not, which makes the feature behind a new verb fail silently.
- **The self-update's CI gate read only the first 100 checks on a commit.** Enough for the
  workflows that exist today, but the failure mode was the wrong one: a check that did not fit was
  simply not seen, so a commit whose only failure sat on the second page would have read as passing
  and been offered as an update. It follows the pages now.
- **Every host was given Ubuntu 24.04's package list, whatever it was actually running.** LinuxGSM
  publishes a dependency list per distro release — `ubuntu-22.04.csv`, `ubuntu-26.04.csv`,
  `debian-12.csv` and twenty more — and the panel hard-coded the 24.04 one. The panel supports
  22.04, 24.04 and 26.04, so this was not hypothetical: on **22.04**, Garry's Mod silently missed
  `libtinfo5:i386`, and Minecraft asked for `openjdk-25-jre`, which does not exist on that release
  — and `apt-get install` is atomic, so one unavailable package takes the whole batch down. The
  panel now reads the host's own `/etc/os-release` and fetches that distro's list, falling back to
  the default for a distro LinuxGSM does not publish. The slug comes from the remote host and is
  interpolated into a URL, so it is validated against LinuxGSM's exact filename shape first.
- **Start/Stop/Restart on Files & Config reported a failure right after reporting success.** The
  action had actually worked. `server_actions.js` is shared by the server detail page and Files &
  Config, but it called `pollStats`, which is defined only in `server_detail.js` — a script Files &
  Config does not load. `setTimeout(pollStats, …)` evaluates the identifier immediately, so the
  success handler threw `ReferenceError` the moment the toast was shown, and the trailing `.catch`
  reported that as "Action failed — connection error". The call is guarded now; more importantly,
  the connection-error toast moved out of the trailing `.catch` and into the handler that only sees
  upstream failures, so a bug in the success path can never again tell you an action failed when it
  succeeded — which invites running a restart a second time.
- **Ctrl+A in the console selected the whole page.** The console is a plain `div`, so the browser
  handed select-all to the document and you got the nav, the cards and the forms along with the
  log. Click into the console and Ctrl/Cmd+A now selects exactly the console. Ctrl+A anywhere else
  on the page is untouched, as are Ctrl+C and Ctrl+Alt+A.
- **An unreachable host blanked the console on page load.** `api_console` answers one with an empty
  list, and the first poll adopted that over the server-rendered content. It keeps what is on
  screen and adopts the next poll that actually returns something.
- **Restart and Stop on the dashboard fired with no confirmation.** The server detail page has
  always asked before either — the dashboard did not, so a mis-click on a row restarted or stopped
  a populated server instantly. Both now confirm, naming the server and saying how many players are
  connected (read from the row's live player count, so it costs no extra request; when the count is
  unknown it claims nothing either way). Bulk **Restart** joined bulk Stop and Update in confirming
  too — it was the one bulk action that skipped the prompt. Start is unchanged: it is not
  destructive and does not ask.
- **The live console kept throwing away its history.** Three separate limits, and fixing any one
  alone would not have been noticeable. The API only ever tailed **100 lines**; the poll **rebuilt**
  the console from that window on every refresh, discarding whatever was on screen; and the
  websocket handler — the path that actually runs on a busy server — had its own **500-line cap**
  and its own rendering. The console now keeps a real scrollback: each poll contributes only the
  lines that are new (found by overlapping its window with what is already shown), both append
  paths share one buffer and one 5,000-line cap, and the default window is 250 lines rather than
  100. A **Load older** button pulls a much deeper slice of the log when you need to look further
  back than the page has been open.
- **"Replace existing file" never replaced anything.** Ticking the overwrite box on an upload
  conflict did nothing: the file uploaded, hit the server's existence check, and came back as
  "already existed". `confirmDialog` removes its overlay *before* it calls `onConfirm`, so both
  upload dialogs were reading their checkboxes out of a document that no longer contained them —
  `document.querySelectorAll('[data-ovw]')` matched nothing and `getElementById` returned null,
  both of which read as "unticked". They read the node they passed in as `bodyNode` now, which a
  detached element still answers for. This affected the per-file ticks (shipped earlier, so they
  have never worked) as well as the folder dialog's replace-all. `confirmDialog` now documents the
  ordering, and two static guards refuse either spelling.
- **Running the installer the "other" way built a second panel instead of updating the first.** The
  update check asks whether there is an `app.py` and a unit file *where it is about to install* —
  but that location has already been decided by how the script was invoked: as root it looks under
  the service user's home, as yourself it looks under yours. Neither sees the other. So
  `sudo ./install.sh` on a host with a working per-user install found nothing, declared a fresh
  install, created the service user and would have stood up a **parallel** panel: its own user,
  service, database, and the same port as the one already running. It now looks for an install in
  the other service model first and refuses, naming what it found and how to update it. Adopting it
  automatically would mean moving a running service between systemd scopes and re-owning its data
  directory, which is not something an installer should do unasked.
- **Six endpoints answered HTTP 500 when a remote host was simply unreachable.** A host that is
  powered off, rebooting, or behind a broken link is a normal condition for a panel that manages
  remote machines — not a fault in the panel. `live`, `pro-status`, `uptime`, `firewall`,
  `check-updates` and `tailscale-check` all raised straight through, so opening a host's Manage page
  while it was down filled the browser console with 500s, and any alerting on the panel's own 5xx
  rate fired for someone else's downtime. `live-stats` already answered `200` with an error field
  and explained why in a comment; its siblings never followed. They do now, keyed on the
  `ConnectionError` that `ssh_manager` raises specifically for unreachable — anything that is *not*
  a connection failure still returns 500, deliberately, because those are the panel's own bugs.
- **Four buttons on the Remote Servers page did nothing.** `manage_remotes.html` loaded its script
  from inside the content block, which `base.html` renders *before* `panel.js`. The top-level
  `pollWhenVisible(...)` call in `manage_remotes.js` therefore threw `ReferenceError` while the file
  was still evaluating, and every top-level statement after it was skipped — including the delegated
  click handler wiring **Tailscale check, Tailscale bootstrap, Install Tailscale and Delete remote**.
  Function *declarations* are hoisted, so the page looked normal and the only symptom was one line in
  the browser console. The live-stats auto-refresh on that page never started either. Both page
  scripts now load from `{% block scripts %}`, and a template gate fails the build if any page loads
  a script before `panel.js` again.
- **A failed swap-file setup still wrote a swap entry to `/etc/fstab`.** The shell form was
  `fallocate && chmod && mkswap && swapon && grep -q … || echo … >> /etc/fstab`, and `&&`/`||` are
  left-associative with equal precedence — so the append ran whenever *any* earlier step failed,
  not only when the grep found nothing. A host that ran out of space got an fstab entry pointing at
  a file that was never formatted.
- **A parser could crash on a superscript digit.** `str.isdigit()` is true for characters like `¹`
  that `int()` refuses, and the panel used that pairing in 35 places — including the query port read
  from a game server's own config, and the session-cookie user loader. Found by the fuzzer, fixed
  everywhere with `isdecimal()`, which is exactly the predicate `int()` accepts.
- **A dead constant in `ssh_manager` turned main red.** `_OS_UPDATE_LOG` stopped being used when the
  detached OS-update job moved into the privileged helper — the helper writes that log and hands it
  back through the `os-update-log` verb, so the panel never names the path any more. The alias, and
  a comment still claiming the runner "writes to it by name", are gone. The reason it reached main
  at all is the more useful half: the local orphaned-constant gate counted a *test* reference as
  proof a name was alive, and the only thing left mentioning this one was its own parity test. The
  gate now requires a reference from production code and says so when a name is test-only.
- **The "main has open code-scanning alerts" gate raced CodeQL and reported the wrong answer.** It
  ran on the same push as the analysis rather than after it, so a commit that *fixed* an alert
  failed the gate, and — worse — a commit that *introduced* one passed it, with the alert then
  blamed on whatever landed next. It now runs when CodeQL completes.
- **`tailscale0` was never actually allowed through UFW.** `ufw_allow_tailscale()` passed its
  argument list as `_run`'s positional `timeout` *and* a `timeout=` keyword, so every call raised
  `TypeError` before reaching UFW — 100% of the time, since the verb conversion. The
  "Allow Tailscale Interface" button answered HTTP 500, and the two automatic callers (after
  `tailscale up`, and during Serve setup) swallow exceptions, so the guard that exists to stop
  exactly the "UFW is up but tailscale0 is not allowed" lockout had silently never run.
- **The installer's update path never refreshed the root-owned helper.** The block that installs
  `panel-helper`, `db_maintenance.py`, `panel.conf` and the root-owned installer sat *after* the
  update path's `exit 0`. So every update — in-panel self-update, the CI auto-deploy, a plain
  re-run — shipped new code against whatever helper first landed on the host. The verb table grows
  most releases, and a stale helper answers a new verb with `unknown verb` and no fallback, so the
  feature behind it stopped working with no message anywhere. The sudoers grant was never
  re-evaluated either, which left a host that first installed pre-helper on `NOPASSWD:ALL`
  indefinitely. Both are now done on update as well, and the Diagnostics card compares the panel's
  verb table against the installed helper's and names the missing verbs.
- **The "Repair database" button could never appear.** `remote_manage.html` carried
  `id="diag-repair-btn"` on both the panel-file restore button and the database repair button, in
  the same block — and `getElementById` returns the first. So a healthy DB check *hid the
  file-restore button*, an unhealthy one told you to click a button that stayed hidden, and
  `repairDb()` relabelled the wrong control. A template gate now fails on any id rendered twice in
  the same page (ids in mutually exclusive Jinja branches are still fine).
- **Disabling Tailscale Serve on a sub-path mount did not disable it.** The handler hardcoded
  `mount: '/'`, and `tailscale serve --remove /` exits 0 on a node whose mapping is at
  `/lgsm-panel` — so the panel reported success, cleared `tailscale_setup_done` and
  `tailscale_mount`, and left Serve running, with the panel no longer prefixing its own URLs. The
  Disable button now carries the configured mount. The Mount Point field also shows the configured
  mount instead of always `/`.
- **Changing the panel's port dropped the fail2ban whitelist.** The port change rewrites the
  panel-login jail, and that call omitted the whitelist — so `ignoreip` came back as localhost only
  and every whitelisted IP/CIDR silently lost its exemption until the next boot re-applied it (or
  indefinitely, if the restart that follows failed). Its two sibling call sites always passed it.

- **`datetime.utcnow()`, which Python has scheduled for removal, is gone** from all 22 call sites
  (including twelve database column defaults). Stored timestamps are unchanged — still naive UTC, to
  the microsecond — they now come from `clock.utcnow()`.

### Security
- **CSRF could be skipped by sending an `Authorization: Bearer` header.** The exemption exists
  because an API-token request carries no cookie, so there is nothing for a cross-site page to
  ride — but it tested only for the header, so a request sending both a Bearer header and a session
  cookie skipped CSRF while being authenticated from the cookie. Not reachable from a browser (a
  custom header forces a CORS preflight, and the `SameSite=Lax` cookie is not sent cross-site), so
  this is the exemption now resting on the condition it claims rather than a fix for a live hole.
- **A compromised remote host could inject markup into the panel.** A host's own
  `tailscale status --json` output — its tailnet IP and MagicDNS name — plus the addresses returned
  by the migrate endpoint and its live CPU figures went into the admin's page unescaped. The strict
  CSP (no `unsafe-inline` for scripts) stops that becoming script execution, so this was HTML
  injection rather than XSS, but it is the same class the 0.10.0 release fixed elsewhere and it
  survived in `manage_remotes.js`. The regression gate written to catch the next one could not see
  these: it only read the expression sitting at the sink, and this markup is accumulated into a
  variable first. It now follows a variable to its sink, understands helpers that assign their own
  parameter to `innerHTML`, and is verified by mutation against all seven values.
- **`X-Forwarded-Prefix` was trusted from any client.** `PrefixMiddleware` read it unconditionally
  while the panel can bind `0.0.0.0`. `SCRIPT_NAME` is what every `url_for()` and outgoing
  `Location` is built from, so a caller could rewrite the links in its own response — including to a
  protocol-relative `//host`. It is now believed only from loopback (where Tailscale Serve sits) or
  when `trust_proxy` is set, which is the rule `client_ip()` has always applied to
  `X-Forwarded-For`.
- **The rolling database backup was left world-readable.** `data/panel.db.backup` and any
  `panel.db.corrupt-*` copy hold every password hash and encrypted credential the live database
  does, and were created at the process umask — the one set of files in `data/` that
  `harden_data_permissions()` did not cover. (`data/` itself is `0700`, so this was defence in
  depth, not exposure.)
- **The self-signed TLS private key was written at the process umask, then chmodded.** It is now
  created `0600` by `os.open`, so there is no window in which an unencrypted key is readable.
- **The sudoers grant is no longer `NOPASSWD:ALL`.** On an install where the root-owned pieces are
  present, `/etc/sudoers.d/linuxgsm-panel` now contains a single line permitting one command — the
  privileged helper — and nothing else. Not `/bin/bash`, not `systemd-run`, not the `tailscale`
  binary, not `sudo -u`: each of those runs whatever argv you hand it, so permitting any one would
  be `NOPASSWD:ALL` in disguise. Each was a call site once; each is a verb now.

  Getting there needed two things beyond the verb conversions. First, **root had to stop executing
  code out of the panel's own checkout** — that directory is owned by the service user and rewritten
  by `git pull`, so a boundary that let root run files from it would have been decorative; the
  offline DB repair and the self-update now run root-owned copies placed only by `install.sh`.
  Second, the grant **only narrows when all three root-owned pieces landed**; a host running new
  code that has not had `install.sh` re-run as root keeps the wide grant, because it still falls
  back to the pre-helper path and narrowing under that would break every privileged action rather
  than secure anything. The installer prints which grant it wrote.
- **`tailscale up` on the panel's own host wrote root's output to `/tmp`.** The local flow built its
  own `sudo bash -c` script — a backgrounded `tailscale up`, a redirect to `/tmp/tsup.log`, and a
  poll loop. `/tmp` is world-writable, so any local user could pre-create or symlink that path and
  redirect what root wrote there. The equivalent REMOTE flow was converted to the
  `tailscale-up-login` verb some time ago — which writes to `/run/panel-tailscale-up.log`
  (root-owned, `0600`, cleared on reboot) — but the local twin was never switched over. It is now,
  on every path: the helper when installed, the tool directly when already root, and the verb's own
  rendered shell form otherwise, which uses the `/run` path too. `tailscale up` on this host also
  stops needing `sudo bash`, which is one of the call sites blocking the sudoers grant from being
  narrowed; a new census ratchet holds the remaining count at 1.
- **A missing `data/config.json` reopened four unauthenticated setup endpoints.** The setup wizard's
  Tailscale endpoints (`/api/setup/tailscale/{status,install,up,serve}`) have no login — during a
  fresh install there is no user yet — so they are safe only for as long as their "setup is still
  open" test is. That test was `is_setup_complete()`, which is *DB row AND config flag*, and the
  config half fails open: `load_config()` returns `DEFAULT_CONFIG` (where `setup_complete` is
  `False`) on any `JSONDecodeError`/`OSError`. On a fully configured panel, a `config.json` that was
  deleted, truncated by a full disk, or hand-edited into invalid JSON therefore unlocked all four to
  anyone who could reach the port: `install` runs the Tailscale installer as root, `up` returns an
  auth URL that joins **the panel's host** to the caller's tailnet with SSH enabled, and `serve`
  rewrites `bind_host` and `site_domain`. They now use the same DB-row-only lock the wizard itself
  has used since the equivalent hole was closed there — the reasoning was already written down in
  `setup_wizard()`, just never applied to these four. A lost config file should degrade the panel,
  not hand it over.
- **Three VPS-preparation actions could be aimed at the panel's own host.** The remotes page hides
  *Prepare* and *Tailscale* for the local host, but the API routes behind them accepted a POST
  carrying its id — so anyone with "manage remotes" could apt full-upgrade the panel's own machine,
  rewrite its `sshd_config`, pipe an installer into a root shell, and reboot it out from under the
  request. The routes refuse the local host now, with a JSON 400 that says why.
- **The privileged helper carries every local escalation.** The panel escalated local work as
  `sudo bash -c '<command>'`, which is why its sudoers grant could never be narrowed: permitting
  `/bin/bash` *is* `NOPASSWD:ALL`. `tools/panel-helper` is a root-owned script that takes a verb and
  separated arguments, re-validates each one, and runs a fixed command — no shell, and `bash` is not
  a program it can reach. 86 verbs cover the `ufw`, `fail2ban-client`, `systemctl` and `apt`/`dpkg`
  families, the log reads, user/cron management, the root-owned config writes, the sshd port change,
  the deferred reboot, Ubuntu Pro, the host controls, the GMod shared-content box, the fail2ban
  activity report and the VPS hardening steps. Root-escalating call sites that still build a shell
  string are down from 131 to 4, the `_sudo_sh` route is gone entirely, and a ratcheting test counts
  BOTH routes (an earlier count missed `_sudo_sh`, which had 18 sites of its own). See SECURITY.md.

- **The panel could not hear its own deprecation warnings.** A filter installed at import time
  silenced every `DeprecationWarning` in the process, permanently — and did not silence the one it
  named, because eventlet's banner is not a `DeprecationWarning` at all, so it printed on every start
  regardless. Running the panel under `-W always::DeprecationWarning` heard nothing. Now only
  eventlet's banner is silenced, and `-W` / `PYTHONWARNINGS` work again.

## [0.10.0-alpha] — 2026-09-09

Two months of work that had accumulated on `main` unreleased. The headline items are OS-update
visibility, Ubuntu 26.04 support, a mobile pass, and a run of security fixes.

### Added
- **OS updates, surfaced in the panel** — a login banner listing hosts with packages waiting, and a
  per-host card filled from the daily sweep's answer rather than by running `apt` on page load.
  Security updates are called out separately from ordinary ones.
- **OS-update alerts to Telegram/Discord** when a host first has updates waiting, on the transition
  rather than daily, so it stays an alert instead of noise you filter out.
- **Ubuntu 26.04 support.** CI now runs the suite on 22.04, 24.04 and 26.04, each paired with the
  Python that release actually ships (3.10 / 3.12 / 3.14). 22.04 and 24.04 remain supported.
- **Overwrite prompt on file upload** — dropping a file whose name already exists asks first, showing
  the size and modified date of both the file on the server and the one being uploaded, with a
  tickbox per file. Unticked files are skipped.
- **Start / Stop / Restart on Files & Config**, which previously told you to restart the server
  without offering a way to do it, plus its missing History tab.

### Changed
- **The mobile layout reclaims most of the first screen.** Measured at 375x812, page content used to
  begin below the fold; the two-factor reminder alone took 30% of the viewport. It is now a single
  strip, the server table's action buttons stay pinned in view instead of sitting off-screen behind
  a horizontal scroll, and tab strips scroll rather than wrapping their labels onto three lines.
- **Host status says what it means.** "Offline" described both a host the panel cannot reach and a
  stopped game server, in the same red, on the same screen. Hosts now read Reachable / Unreachable,
  and a host that has not been checked yet reads "Checking…" rather than asserting it is unreachable.
- **The dashboard tiles add up.** Servers that were installing or failed appeared in no tile, so the
  numbers visibly disagreed with the total.
- **Accessibility**: every form label is now associated with its input, modal close buttons have
  accessible names, and controls that fell under WCAG 2.2 AA's 24px target size were raised.
- The **Autostart switch follows the crontab** instead of a database column that could go stale.
- The **users page renders one edit modal** rather than one per user.

### Fixed
- **The OS-update alert never actually ran.** It was the one database-touching background task
  without a Flask app context, so every tick raised and was swallowed at debug level.
- **A failed `apt` check no longer reads as "System is up to date."** apt produces no output when it
  fails, which is exactly what a clean host produces; the check's exit status is now carried through
  to the UI and the alert.
- **Deleted hosts and servers no longer leave state behind.** SQLite reuses a deleted row's id, so a
  newly added server could inherit "already alerted" flags — and, worse, the previous server's player
  capacity — from the one that used to hold that id.
- The **pending-restart banner** now accounts for the daily-restart schedule.
- Console output rendering: Minecraft commands no longer display as `ssasay  hi` or `>=>`.

### Security
- **Cross-site scripting from a compromised remote host.** A host's own output — its Tailscale login
  URL and IP — was rendered into the panel admin's browser unescaped in several places.
- **Symlink escape in the file browser.** The path check was lexical and could not see symlinks,
  because the path lives on the remote machine; every file operation now resolves the path where it
  actually is before acting on it.
- **TOTP codes are single-use.** A code stays valid for about 90 seconds, so one observed once could
  be replayed for the rest of that window.
- **Session fixation.** The authenticated session is now established on a clean session rather than
  inheriting whatever the pre-login one carried.
- **The setup wizard is locked by database state**, not by a config flag. An unreadable `config.json`
  reopened the unauthenticated wizard on a configured install, where it could rewrite the panel's
  bind address and port.
- **Failed API-token authentication is throttled.** `/login` had a brute-force limit; the bearer-token
  path — the panel's other way in — had none.
- **Chat-bot actions are attributable.** A `/restart` or `/update` from Telegram or Discord was logged
  as a "system" action, with nothing recording that a chat message caused it or who sent it.
- **A panel restore no longer leaves the database and both encryption keys in `/tmp`** after it runs.
- Shell identifiers are re-validated where they are used, not only when assigned, and are length-bounded.
- `SECURITY.md` now documents an important limitation honestly: a root install grants the panel's
  service user unrestricted passwordless sudo, so there is currently no privilege boundary between a
  compromised panel and a rooted host. It explains why this cannot be narrowed by editing sudoers
  alone, and that remote-only installs can remove the grant entirely.

## [0.9.0-alpha] — 2026-07-13

### Added
- **Per-device session management** — the account page now lists every device/browser signed in to
  your account (device, IP, last-active) and lets you revoke them **individually**, not just all at
  once. Logging out now signs out only the current device; "Sign out everywhere" still clears them all.
- **Garry's Mod content mounting** — install Counter-Strike: Source and other Source-engine games'
  content via LinuxGSM so GMod maps and props render instead of missing-texture errors. One shared
  copy per host, mounted read-only into each GMod server with per-server enable/disable, one-click
  uninstall, a free-disk readout, and a weekly content auto-update cron (16 installable games).
- **Two-way Discord command bot** over the Gateway — alongside the Telegram bot; `!status`,
  `!servers`, `!players <name>`, `!update`, and `!start` / `!stop` / `!restart <name>`, locked to the
  configured channel.
- **Settings page** (superadmin) — branding (site name, accent colour, login tagline), the default UI
  language for new users, and session/security tuning (idle timeout, remember-me, session-protection
  level, auto-block threshold), all applied live.
- **Configurable alert thresholds** — disk %, CPU-load %, and memory % — plus **sustained-duration
  high-load alerts** that page only after load stays over the line for a set number of minutes.
- **Metrics + player history charts** (24h / 7d) on the server page, live-updating.
- **Weekly auto-update of npm + gamedig** (the player-query tools) on every host.
- **"Jail" column** on the login-security top-offenders table.

### Changed
- **Every scheduled task is now editable and deletable**, including the LinuxGSM/panel-installed ones.
- **Mods merged into a single Install/Remove list**; installing a mod no longer auto-restarts the
  server — you're prompted to restart when ready.
- **GMod content installs via LinuxGSM** (not raw SteamCMD), so it gets validation and the weekly
  update cron for free.
- **Group-by-host** on the Game Servers list now shows one card per host.
- Removed the global **notifications master switch** — a channel's own enable toggle is the on/off.
- **start/stop/restart run in the background** so the button never hangs; remaining per-server SSH in
  request handlers was parallelised.
- **Account page** — two-column layout on desktop; the API-access (personal token) card was removed.

### Fixed
- **PaperMC / Velocity / Waterfall** now report player count + max (queried via gamedig on the real port).
- **Minecraft/Paper console** no longer shows terminal control-code noise (JLine ANSI + prompt lines).
- **Sidebar active-state** is correct under a URL mount prefix (e.g. `/lgsm` via Tailscale Serve).
- **Import** auto-caches each server's LinuxGSM command list, so "Supported Commands" isn't blank.
- Remote **public-IP resolution** moved off the request path — an unreachable host no longer hangs a page.
- **Self-update snapshot** no longer aborts on a root-owned unreadable file (e.g. a Tailscale cert key).
- The panel no longer binds to loopback unless Tailscale Serve is actually configured to proxy it.

## [0.8.0-alpha] — 2026-07-11

First tracked release. The `VERSION` file had drifted from the git tags (last tag `v0.7.15-alpha`),
so this re-baselines it and starts the changelog. Notable changes since then:

### Added
- **Telegram command bot** — drive the panel from Telegram: `/update`, `/status`, `/servers`,
  `/hosts`, `/players <name>`, and `/start` / `/stop` / `/restart <name>`, with a `/` autocomplete
  menu. Opt-in and locked to the configured chat.
- **Global ban list** — ban a SteamID once and it applies to every Source/GoldSrc server across all
  hosts, via each server's own native ban list.
- **Proactive admin alerts** to Telegram/Discord for 18 events (server down, host unreachable, disk
  low, high load, brute-force, backup failed, update available, cert expiring, and more), plus a
  per-server "notify when empty" one-shot.
- **In-game server names** on the dashboard and Game Servers list (from gamedig, with a console
  fallback for servers that don't answer Steam queries).
- **Sort + group-by-host** on the Game Servers list, and click-to-sort columns on the dashboard.
- **Security whitelist** (IP/CIDR) that is never fail2ban-banned or UFW auto-blocked — on the panel
  host and every remote.
- REST **API tokens** (Bearer auth).

### Changed
- **Auto-block** now firewalls IPs by failed-attempt count over a rolling 7-day window (not a fixed
  top-20), and pushes the whitelist into remote hosts' fail2ban too.
- **Installs and bootstraps no longer reboot a host that has running game servers** — they reboot
  only when an update requires it, never out from under players.
- Player-count polling runs **concurrently**, so a pass no longer scales with the number of servers.
- Config writes go through a lock-safe read-modify-write, so concurrent writers can't lose changes.
- README rewritten and shortened.

### Fixed
- A failed gamedig query now reads as **unknown**, not a bogus `0` players.
- Server controls are disabled while a server is installing or uninstalling.
- Cleared the CodeQL full-SSRF finding on the Discord webhook sink (constant host + validated
  id/token).
- The Telegram `/update` completion check compares the **git commit**, not the static VERSION.

[Unreleased]: https://github.com/FMSMITH91/linuxgsm-panel/compare/v0.10.0-alpha...main
[0.10.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.10.0-alpha
[0.9.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.9.0-alpha
[0.8.0-alpha]: https://github.com/FMSMITH91/linuxgsm-panel/releases/tag/v0.8.0-alpha
