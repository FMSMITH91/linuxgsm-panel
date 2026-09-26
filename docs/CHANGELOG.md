# Changelog

All notable, user-facing changes to the LinuxGSM Panel. The project is pre-1.0 and alpha — see the
README disclaimer. Versioning is loosely [semantic](https://semver.org). Note: the panel's in-app
"update available" check compares git commits, so you always get the newest CI-verified commit
regardless of this file — this changelog is for humans.

## [Unreleased]

### Added
- **A terminal in the browser, for the panel's own host and for every remote.** xterm.js over the
  socket the console already uses. It needs a new "use terminal" permission (`use_terminal`) and
  access to the host; on the panel's own host it is superadmin-only whatever the grants say, because
  a shell there runs as the account that owns the panel's database and keys. Every session opened
  and closed is audited, never what was typed. Limits: 12 sessions in all, 3 per user, 512 KB/s of
  output per session, and a session closes after 15 minutes with no input. Host access is re-checked
  while a session is open, not only when it opens, and an account that has been told to change its
  password cannot open one. On a remote the shell runs as the account the panel connects with —
  often root — and the page names that account.

  On the panel host `sudo` refuses by default, because the panel user's grant names only the helper.
  `PANEL_TERMINAL_SUDO=1 ./install.sh` grants it general sudo **with a password required** (give the
  account one with `sudo passwd lgsmpanel`), `=0` removes it, and leaving it unset changes nothing.
  A web terminal sees every keystroke, that password included, so this protects against a stolen
  panel session and not against a compromised panel; the README says so. Remote hosts' sudoers are
  never touched.
- **The install picker knows which games LinuxGSM caps at an older Ubuntu.** LinuxGSM's game list
  declares the newest release each game supports, and four sit below the rest: Battlefield 1942 and
  Battlefield: Vietnam at 22.04, BATTALION: Legacy and Onset at 20.04. The panel parsed that column
  and threw it away, so on a 24.04 host those installs created the account, downloaded for several
  minutes and only then failed with LinuxGSM's "not supported". Once a host is chosen the picker now
  greys them out, labelled "(needs ubuntu 20.04)" and so on, and the install route refuses them up
  front, naming the cap and the host's release. Both compare against the **selected host's**
  release, not the panel's, and both let everything through when a host's release cannot be read —
  refusing an install that would have worked is the worse mistake.
- **A failed install says why, and offers what you can do about it.** The dashboard row used to say
  "Failed" and nothing more: the reason lived in the install job's memory and was gone at the next
  restart, there was no Retry, Remove was on another page, and Files & Config was greyed out on
  exactly that row. The reason is now stored with the server, stripped of LinuxGSM's colour codes,
  and shown above that host's table with **Retry install**, **Edit its config** and **Remove**.
  Retry is left out, with a sentence saying so, when another attempt cannot help. Files & Config
  opens for a failed install — the config LinuxGSM writes before the download is usually where the
  fix is (a `steamuser` it asks for, say) — and the reconcile ticker now re-checks failed rows, so
  after fixing the config and pressing Update the server is adopted once its files land. An install
  that died before the download step is marked failed too, instead of staying "installing" with
  nothing able to act on it.
- **Game servers can be uninstalled from the dashboard.** The only Uninstall sat on Remote Servers →
  a host → Overview, well down a table. Every dashboard row now has one for anyone allowed to
  uninstall, behind the confirmation the host page already used: type the server's account name to
  enable the button, because it deletes the server, its files and every backup it has. The
  failed-install banner's Remove uses the same gate rather than a plain yes/no.
- **Install progress is shown where the server is.** An install takes five to forty-five minutes,
  and its progress lived on a page you were usually not on — the install form's toast said progress
  was "shown live below", under the form. The dashboard now shows a progress row directly beneath
  the installing server (step, bar, percentage, elapsed) that stays with it through sorting and
  filtering, and Install a Server shows an "Installing now" panel that says the install carries on
  if you leave. `/api/installs` answers "is anything installing" for the servers you can see, and
  nothing polls unless something is. The Offline tile's "+N installing or failed" is now just "+N
  failed".
- **The update card's list of changes links each commit and PR**, to the repository this checkout
  tracks, so a fork links to the fork. The links are built only from a hex SHA, a run of digits and
  a repository URL of the expected shape; anything else renders as plain text, as before.
- **The sidebar footer links to the panel's repository, and its commit SHA to that exact commit**,
  so what is actually deployed is one click away. The URL comes from the checkout's `origin`, so a
  fork links to itself, and anything that cannot be read falls back to the canonical repository.
- **Console history can have real timestamps, not just lines you watched arrive.** The panel tails
  the console log, so on its own it can only date what it saw — on an idle server that means the
  whole of history is blank. LinuxGSM can stamp the log *at write time* (`logtimestamp`, which
  pipes the tmux capture through `gawk strftime`), and the Live Console now offers to turn that on
  where the gap is noticed. Once it is, every line arrives already dated, for every game — the
  Call of Duty family included, which has no per-line time of its own.

  The stamp LinuxGSM writes is in the **host's** local time with no offset, so the panel reads it
  against that host's timezone, converts it to a UTC instant, and the browser renders it in yours
  — a line written at 05:09 in Tokyo reads as 15:09 in US Central. It is stripped from the text
  and shown in the gutter, so the time is not printed twice. A host whose timezone is not known
  yet leaves those lines undated rather than reading them against a guess, and turning the setting
  on edits the instance's LinuxGSM config and takes effect at the server's next start — the
  confirmation says both.
- **Each console line now carries the time the panel saw it**, in your own timezone, with a
  "Times" toggle in the Live Console header (remembered per browser — a Minecraft server already
  prefixes its own `[HH:MM:SS]`, so the gutter is duplication there). 24-hour in the gutter so the
  column stays aligned and the same width all day; the hover text gives the full date in your
  locale's own format. Lines the panel *watched arrive* are stamped — a push from the console
  poller, or output from an update it ran itself, which is why an update's output still reads with
  its timestamps after a reload. The window fetched on page load is a fresh tail of the game's log
  file, which for most games records no per-line time at all: those lines were written at some
  unknowable point before the panel looked, so their gutter stays **blank** rather than claiming
  the moment you opened the page.
- **Three remaining timestamps now render in your timezone too** — ban dates, invite expiry and
  Tailscale peer last-seen. They formatted the stored UTC value themselves, so they showed UTC
  with nothing saying so, which reads as a wrong local time rather than as a UTC one. There is now
  a check that no template can format a stored timestamp itself.
- **LinuxGSM's colour now survives into the console.** `[  OK  ]` green, `[ FAIL ]` red,
  `[ INFO ]` blue — the same output `putty` shows, which is most of what makes a long `update`
  readable at a glance. Every display path used to run the text through `strip_escapes`, which is
  right for the paths that *parse* console output and wrong for the one showing it to a person.
  The server keeps SGR (and only SGR — erase-line, cursor moves, window titles and stray `ESC`
  bytes are still removed) and the page turns each run into a styled node. Applies to a game's own
  console too, so a Minecraft server's JLine colour comes through as well. Console lines are built
  as DOM nodes and never as markup: player names and chat arrive in that text verbatim, so it is
  attacker-authored end to end, and there is now a gate pinning that.
- **The installed game version is shown on the server detail page**, on its own line under the
  host and port. Two sources are read, because no single one answers it for every game the panel
  manages: SteamCMD records an exact build id on disk (`serverfiles/steamapps/appmanifest_*.acf`
  — the same `buildid` LinuxGSM's own `update` compares against Steam), and the running game
  reports the version players see over its query protocol. The reported string is shown when
  there is one, the build id otherwise, and the hover text says where the number came from and
  when Steam last changed the files. For the Call of Duty family — which is not SteamCMD-based
  and has no `update` command at all — the live query is the only version that exists, so that is
  what appears. Neither read is on the render path: the page draws first and fills the line in
  afterwards, and the answer is cached until an update moves it. A game that is neither
  SteamCMD-based nor currently answering shows a dash rather than a number that might be wrong.
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
- **`LICENSE` is the plain MIT text**, so GitHub and OpenSSF Scorecard detect it as MIT. The terms
  are unchanged. The notice appended to it (not affiliated with LinuxGSM; built largely with AI) is
  in the README's disclaimer, which already said most of it.
- **Imported game servers get Autostart turned on, as a fresh install already does.** Autostart is
  LinuxGSM's `monitor` cron, which brings back a server that should be running and leaves a
  deliberately stopped one down. An import left it off, so an imported server did not come back
  after a host reboot. It is turned on only for a game that has `monitor` and an account the helper
  enrolled, the switch reads On only once the cron line is written, and it never starts a stopped
  server. Servers already in the panel are not changed.
- **The installer refuses a Python older than 3.10 by name** — "Python 3.10 or newer is required,
  and this python3 is 3.8" — before apt runs, instead of failing inside pip with "No matching
  distribution found". A `python3` that does not run is named too.
- **A queued restart that LinuxGSM finishes with a non-zero exit is cleared after one attempt**, and
  audited with its exit line. It used to be retried up to three times, and LinuxGSM exits non-zero
  on some restarts that worked. A restart that got no answer at all is still retried.
- **A panel bound to a public address with Tailscale Serve set up keeps serving its own HTTPS**, and
  Serve is pointed at it with `https+insecure`. A loopback bind, or an unset one proxied by Serve,
  is unchanged.
- **The update card answers one question: is there something to install?** It showed a green tick
  while the install was behind whenever the newer commits touched only docs or CI. It now offers an
  update exactly when one would be allowed to install — still the newest commit that has passed CI —
  and otherwise says "You're up to date" with the running SHA; a verified commit below a tip that is
  still being checked is still offered. The commit count and the list come from the same set, and
  when none of the commits change what the panel runs they are still listed, with a note that they
  are docs, tests or tooling.
- **The 2FA reset in Users → Edit is always visible**, disabled with a reason when the account has
  no 2FA to reset. It was hidden unless the account already had 2FA on, so an admin looking for it
  found an empty section and concluded the feature did not exist.
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
- **"Daily restart when empty" never restarted on a host whose Node.js came from Ubuntu.** The
  hourly check runs from the game account's crontab, and cron gives a crontab the PATH
  `/usr/bin:/bin`. Ubuntu's own npm installs gamedig into `/usr/local/bin`, where cron does not
  look, so the check never found gamedig, never counted a player, and waited for an empty server
  that never came. That covers 24.04 and 26.04 panel hosts whose Node.js the installer took from
  Ubuntu, and remotes that already had Ubuntu's Node 18+. Hosts with NodeSource's Node were not
  affected: its npm puts gamedig in `/usr/bin`, and on the test host (Node from NodeSource) the
  check counted 0 under cron's own environment. The check now sets its own PATH
  (`/usr/local/bin:/usr/bin:/bin`) for the player query only. Existing lines are fixed without
  touching the setting: the in-place upgrade that runs whenever a server's Scheduled Tasks are
  opened now also runs once a day for every game server, and adds the PATH to that call without
  changing anything else on the line. That upgrade also no longer rewrites a crontab whose listing
  failed, because it replaces the whole crontab with the lines it read.
- **Player counts and lists never worked on a fresh Ubuntu 24.04 or 26.04 install.** Both ship a
  Node new enough to skip NodeSource, and the distro's `nodejs` has no `npm`, which the gamedig step
  needs — so gamedig was never installed. The installer and the add-host bootstrap now install `npm`
  when Node 18+ lacks it, and the installer warns if gamedig is still missing. A full system and
  per-user install was run on Ubuntu 26.04, whose `/usr/bin/sudo` is sudo-rs, and it turned up three
  more: a sudo-rs refusal on the Firewall page read as "The panel can't reach this host"; the
  install retry for a just-created account only recognised classic sudo's wording for an unknown
  user; and, on every release, uninstall said it had removed the panel's UFW rule on hosts that
  never had one (`ufw delete` exits 0 for a missing rule) — it now counts the rule before and after.
- **"1 RLock(s) were not greened" no longer prints on every start under Python 3.13+** (Ubuntu
  26.04). It asked for an import-order fix nothing could make: Python 3.13 binds two `threading`
  internals into a default argument that eventlet's patching never reaches, which also leaked an
  entry per dummy thread. They are rebound around the patch, only when they have exactly that shape;
  3.10 and 3.12 are unchanged.
- **After an in-place Ubuntu release upgrade the panel could not start, and re-running the installer
  did not fix it.** `do-release-upgrade` moves `/usr/bin/python3` to a new minor version; the venv's
  `python3` follows it and finds none of the panel's packages (`No module named 'eventlet'`, in a
  restart loop). The installer skipped pip while `requirements.txt` was unchanged, and with the code
  already current it exited "Already up to date" before reaching pip at all. A venv whose recorded
  Python no longer matches the interpreter it resolves to is now rebuilt through the full update
  path (snapshot, health check, rollback), and `linuxgsm-panel-recover` names the problem. Minimal
  images (Docker, some LXC) ship no zone database, so every time zone name was refused; `tzdata` is
  now installed there, non-interactively.
- **The live console no longer re-appends old output after an update and a start.** Reported as "I
  stop seeing the live console respond till I load more of the old log". The stream never stopped:
  the 30-second catch-up poll failed to match the page's copy of the log and appended its whole
  window again under the live output — +82, +29 and +33 duplicate lines on three polls after stop,
  update, start. The update's `[panel]` lines went into that copy though they are never in the log;
  the poll's window lost trailing whitespace (Minecraft's `list` reply ends in a space); and
  LinuxGSM's start rotates the log with `mv` and `touch`, which the poller only noticed when the
  file shrank, so it read the new log from the old offset and missed the boot output. Offsets are
  keyed by inode now, panel lines are shown but kept out of the comparison, the window is read
  byte-exact, and the poll appends only while the socket is down (and once after a reconnect).
  **Load older** no longer wipes the console for a log it could not read. A colour code thousands of
  digits long, or a game writing without newlines, can no longer stall a console, and
  `/api/server/<id>/log-timestamps` is off-only, like the page.
- **The Tailscale page's Disable, and the SSH toggle, did the wrong thing.** Disable aimed at the
  first Serve route listed — with the panel at a sub-path, another app's `/` — and left the panel's
  own mapping in place; turning Tailscale SSH off ran `tailscale up … --reset`, resetting every
  other Tailscale setting; and Enable offered a mount another app already held, which replaces its
  mapping. Disable now removes the panel's own route, and is refused while the panel is bound to
  loopback, where Serve is the only way in: bind `0.0.0.0` under System → Panel Server first.
- **The firewall's delete guard protects the rules that keep you in.** It failed open when the
  firewall could not be read (every rule became deletable), when `config.json` was corrupt (the
  tailnet rule), and when a stale `tailscale_setup_done` said Tailscale was the way in (the panel's
  only web port). It did not recognise `ufw allow OpenSSH` or `… on eth0` rules as SSH, nor a
  `LIMIT` on the panel's port, and it treated an outbound rule on that port as the panel's. A stale
  rule number could delete a different rule, and a non-English `ufw` read a live firewall as
  inactive. The panel host's firewall status dropped every rule whose To column is not a number —
  the `tailscale0` allow, app profiles, the panel's own denies. "Remove rate limit" deleted the rule
  and closed the port; it rewrites LIMIT to ALLOW now. `force` still overrides the guard.
- **`uninstall.sh` removes what it installed, and only that.** A per-user uninstall left the weekly
  root cron (`npm install -g … gamedig`, as root), the helper tree, `panel.conf` and the recovery
  symlink behind. It could not stop a per-user service over a non-interactive SSH session and then
  deleted the running panel's files; it now confirms the stop and refuses otherwise. It left an
  enabled fail2ban jail watching a log it had just deleted, took host-shared pieces that belonged to
  another install on the same box, and ran `tailscale serve reset`, which wipes every Serve mapping
  on the node rather than the panel's; a per-user uninstall now closes its own port. It reported
  removing the UFW rule and the panel user whether or not it had — and a surviving panel user still
  owns the SSH key to every host the panel managed, which the warning now says. It no longer exits
  silently when the service account is already gone.
- **`install.sh` fails safe mid-update.** Its snapshot check accepted a truncated archive — the
  disk-full case its own comment names — and the rollback then killed the script with the panel
  half-populated and no message. An abort while the panel was stopped left it down with the rollback
  unreachable, and the database snapshot was taken while the service was still writing to it. On a
  per-user install its firewall probe ran without `sudo`, so the panel's port was never opened and
  the banner printed an address the firewall blocked; an unanswered probe is reported as unknown
  now.
- **"Is anyone on?" no longer answers "no" when it could not tell.** A failed gamedig query prints
  JSON with no player list, which `jq` counts as 0 — so the hourly "daily restart when empty" check
  restarted a full server whenever a query failed (packet loss, a world save, a firewalled query
  port), and reboot-when-empty read the same zero. Only a counted 0 means empty now. The host-reboot
  confirmation lists running servers whose count could not be read and warns they will be
  disconnected, and passes a server's query-type override as the server page does; the per-server
  restart and stop confirmations say they could not check. The unattended reboot no longer treats a
  host as idle while a server on it is still installing.
- **A server's status is what the game's port says, and a failed read no longer overwrites it.**
  LinuxGSM's `STARTED` only means a tmux session exists, and the wrapper inside it outlives a
  crashed game — so a server that crashed, or never booted, read as online, and the detail page
  committed that over the correct "offline" (and wrote "online" over an install in progress).
  "Online" now means the game's port is listening, everywhere. The other direction too: a `details`
  read that timed out (it runs a full `du` — 13 seconds on a 6.5 GB install) wrote "unknown"; the
  stats endpoint persisted an all-zero failed read as "offline", which let "notify when empty" fire
  and clear itself with players still connected; and a port scan that did not answer wrote every
  server on that host offline, with a "Server offline" alert each. Only a status that was actually
  read is stored now. A queued "stop/restart when empty" is no longer discarded because the server
  had crashed.
- **Auto-blocking and the fail2ban watchers no longer act on reads that failed.** An empty fail2ban
  read released every auto-block the panel had placed; a quiet remote host whose logs simply held no
  Ban lines read as "could not read" forever, so its expired blocks were never released; and an
  unreadable firewall made the reconcile re-issue up to 200 privileged commands a cycle. One failed
  read of the panel's jail logged an unban for every live ban and then, on the next good read, a ban
  and a notification for each — three or more tripping "Login attack in progress". A failed read
  also repainted the Auto-block toggle as off, which saving the threshold then persisted.
- **An unreachable host no longer renders as idle and healthy.** Only the paramiko transport raises
  on a failed read; the local and Tailscale transports return empty output, which the metrics code
  turned into a full set of zeros. A host that was down showed "Reachable · CPU 0% · RAM 0% · Disk
  0%" on the dashboard and "CPU 0%, 0 cores, RAM 0 of 0" on its Live Resources card, drew a dip to
  0% in each server's live chart, and recorded those zeros in the history charts. The Reachable
  badge was never refreshed at all — the column was written only at creation, by Test connection and
  by a bootstrap — and an open dashboard kept a silent host's last figures under "Auto-refreshing".
  Each now shows the host as unknown or unreachable, the live chart leaves a gap, and the badge
  follows the monitor.
- **Database repair keeps the fullest copy.** It preferred a rebuild of the damaged file over a
  complete backup whenever the rebuild was a well-formed file — in the reproduction, 17 rows of
  4,000, reported as a successful repair, after which the rolling backup was refreshed from it. It
  now counts the rows in both, takes the fuller, and says which. The dump-based rebuild also threw
  away every row it had salvaged when it met one bad page. And the pre-update database step —
  integrity check, fresh rolling backup, abort on a corrupt database — never ran on a root install:
  the root-owned copy imported the panel's package, which is not importable there.
- **GMod shared content on a remote host is detected correctly.** The remote check always answered
  that the content was downloaded, so it never was, and weekly update crons were written for scripts
  that do not exist; an unreachable host read as "not downloaded", and content already on disk was
  fetched again. A content mount now says it needs a restart while the server is running, since
  until then the server cannot read the new files.
- **A failed read can no longer be saved back over a real config.** A config edit, port change or
  alert edit whose read of the LinuxGSM config failed wrote a file containing only the keys being
  changed. A `common.cfg` without a trailing newline made the Raw tab open empty, and Save wrote
  that over the real config. A file whose read failed opened in the editor as an empty file. The
  Alerts card showed blank webhooks and tokens after a failed read, and one Save replaced the real
  ones. Each now reports the failed read and changes nothing.
- **A failed read no longer triggers something destructive.** A `df` that timed out made the
  backup-headroom check delete backups to "free space" (two of four in the reproduction). A failed
  `du` marked an installed server as failed and re-ran its whole download. An unreadable GMod mount
  state unmounted everything — through the content uninstall, and through the content card, which
  showed every box unticked and applied that. Opening Files & Config on a host that did not answer
  turned the server's Autostart and Daily restart off, and said "No scheduled tasks yet." about a
  crontab it never reached. "Refresh commands" on an empty read wiped the stored command list,
  hiding Start, Stop and Update for everyone.
- **"Nothing there" and "could not look" no longer render the same.** A folder the panel could not
  read showed "(empty folder)"; the Backups card said "No backups yet."; the firewall page repainted
  an unreadable host as "Inactive" with "No open ports yet." after one refresh; the Public SSH card
  called an unreadable firewall "tailnet-only", the reassurance an operator acts on before closing
  port 22; "Ubuntu Pro is not installed" was cached for a day from a timed-out read; the fail2ban
  overview said "No fail2ban jails found." for a host whose read failed or whose fail2ban was
  stopped; the file-integrity check showed its green tick when git could not run; discovery reported
  an unreachable host as having no servers; and an unreachable remote was reported as having
  Tailscale installed. Each now says it could not read.
- **Actions that report success now check that they succeeded.** Unblocking an address returned
  success unconditionally, on the panel host and on remotes. "Disable public SSH" reported "✓
  tailnet-only" and audited a hardening that had not happened on a host without ufw. Closing the
  panel's public port said "already closed" about a firewall it never read, and could force-delete a
  DENY rule on that port. Opening game ports reported the ports it asked for, and a panel port
  change reported "Firewall: opened" either way. A refused remote reboot and a failed host reboot
  were audited as reboots, and a refused full backup as one that ran. A scheduled task's "Run now"
  said "Started" for a launch that never happened. The hourly auto-block audit counted attempts, not
  results. A global ban said "Banned across all Source servers" regardless; it now records how many
  servers applied it, were not running, or failed. And the SteamCMD crash-dump sweep did nothing at
  all on remote hosts.
- **An upload no longer overwrites a file because a check failed.** The "does this already exist?"
  check answered "nothing conflicts" when its listing did not run, and the server-side re-check read
  a failed probe as "no file there" — replacing a file the caller had asked not to overwrite.
- **On a phone, the dashboard's Actions column no longer covers the row.** It is pinned to the right
  edge so the controls stay reachable, and it had grown to 270px of a 341px viewport, sitting on top
  of the server name, status and players. Its buttons now wrap into two rows in 190px; desktop is
  unchanged.
- **The VPS bootstrap no longer acts on probes that never answered.** It rebooted a host after the
  upgrade when its "are game servers running?" probe timed out, told a host it needed no reboot when
  that check had not run, reported "Swap already present" on a host it never read (which then got no
  swap), and skipped creating the game account when `id` did not answer. And filling in the optional
  game-user field on a remote made every privileged command — ufw, apt, fail2ban, the sshd
  hardening, the whole bootstrap — run as that user instead of root, while reporting success. That
  field's inline edit box is gone, and the add-host help says what it is for.
- **Tailscale migration checks the new way in before closing the old one.** "Migrate to Tailscale"
  closed port 22 and blanked the host's only stored credential because tailscaled was running — not
  because Tailscale SSH was on, or the panel could log in that way — and gave one generic reason for
  every refusal. A node with a MagicDNS name and no address was migrated to the old host. It now
  logs in over Tailscale first, and names the real problem, including the `tailscale set --ssh` to
  run. Bring-up also skipped the `ufw allow in on tailscale0` rule when UFW's status could not be
  read; interface detection could pick `wg0` on a host running both, which "Allow Tailscale" then
  opened all inbound on; and a bad Serve mount point is a 400 with a message rather than a 500.
- **A branch switch that failed to launch no longer changes the tracked branch.** The route reported
  the failure, but the panel was left tracking a branch its checkout was not on, and the next
  ordinary Update moved the checkout onto it.
- **Backups honour a server's own retention, and "Back up now" counts.** A per-server retention
  override was read only by the scheduled ticker; "Back up now", the full backup and the
  wait-until-empty queue pruned to the global number and deleted the archives the override said to
  keep. A backup taken by hand or by that queue did not move the schedule's clock either, so the
  ticker backed the same server up again within the hour. The safety copy taken before a panel
  restore had its result ignored, so the restore went ahead when that copy failed; it is checked
  now, with an explicit override for a database already too broken to copy.
- **Bans on imported Source servers survive a map change.** `banid` with `writeid` persists to
  `banned_user.cfg`, which the engine reloads only if the server config execs it, and the panel
  added that line only when it installed the server. Bans from the Players panel and global bans now
  make sure of it first, on every target server.
- **Installs that worked were reported as failures, and one that could not work was reported
  online.** A slow first boot (Insurgency took 40 seconds) ended with "installed, but it didn't
  start" after a 15-second wait; the wait is about 90 seconds now, and a start LinuxGSM did not
  complain about says the server is still coming up. A game that ignores the panel's port setting (a
  Velocity proxy, for one) had its default port adopted even when another server held it — and was
  then called online on that server's socket; the panel keeps its own port and names the clash,
  including against servers installed by hand, and no longer rewrites the other server's firewall
  rule while doing so. SCP: Secret Laboratory never started, because its launcher waited at an EULA
  prompt and a per-port config prompt in a tmux session nobody was attached to; both are answered at
  install. A retry keeps the GMod content selection, and install progress no longer freezes after
  one failed poll.
- **Left 4 Dead 2 installs.** SteamCMD refused it with "Invalid platform": the app publishes only a
  Windows launch entry, a SteamCMD bug with a workaround documented by LinuxGSM's maintainers —
  download once with `steamcmdforcewindows=yes`, then turn it off and validate, which fetches the
  Linux binaries. The install does that itself, once, and sets the option back even if the download
  fails. A classified failure reason no longer ends with LinuxGSM's misleading "check
  steamcmdforcewindows" hint.
- **SteamCMD stopped working for every game on a host once ten accounts had used it.** Steam uses
  one crash-dump directory per Linux account (`/tmp/dumps` to `/tmp/dumps09`) and refuses to run
  when all ten are taken — the panel creates an account per game server, and `userdel` leaves the
  directory behind, so ten uninstalls could wedge an idle host. Installs, updates and validates all
  failed, surfacing as "the download may be corrupt". A helper verb now frees orphaned slots, never
  a live account's, on uninstall and before each install, so a wedged host heals on its next
  install. Failures a retry cannot fix — this one, a game that needs a Steam account that owns it, a
  game LinuxGSM caps at an older Ubuntu — stop the retry loop instead of costing three more
  downloads.
- **On an install hardened by `install.sh` run as root, the panel could not manage a single game
  server.** The narrow sudoers grant permits one command, the privileged helper, and about 45 call
  sites ran `sudo -u <game user> bash -c …`, which it does not. Restart did nothing, the file
  browser, GMod content, cron and install flows all failed, and the dashboard still showed the
  servers online from its port scan. The grant now has a second line letting the panel become
  accounts in the `lgsmpanel-games` group, and only those; game accounts are enrolled by the
  installer and a helper verb, LinuxGSM commands go through a bounded `lgsm-command` verb, and
  crontab edits run as the game account rather than as root. The installer now applies this on every
  run — including one with nothing new to fetch, which used to exit "Already up to date" without
  refreshing the helper or the grant.
- **Installing a game server failed at the dependency step on a hardened host, silently.** The step
  ran `sudo bash -c`, which the narrow grant refuses, the failure was logged at debug level and the
  step reported success, so the install failed later at the download looking like a bad archive. It
  is now a sequence of helper verbs that also enables `multiverse` (where `steamcmd` lives) and
  pre-answers the SteamCMD licence prompt, and it reports what did not install. The panel's own host
  also sent every command without an explicit `sudo=` through `sudo`, so about twenty reads that
  need no privilege — the dashboard port scan, disk, uptime — failed under that grant; console logs
  are read as the game account instead. The OS update, the reboot and "enable unattended upgrades"
  no longer refuse under the narrow grant.
- **The file editor saves exactly what it opened.** Opening a file and pressing Save without typing
  converted every CRLF line ending to LF (UT2004's `.ini` files are CRLF) and dropped the trailing
  newline and any leading blank lines. Files now travel between the host and the editor as base64,
  and a read that comes back malformed is treated as a failed read, not as content.
- **Changing the SSH port works on Ubuntu 22.10 and later.** sshd there is socket-activated:
  `ssh.socket` owns the listening socket, so a `Port` in `sshd_config` passes `sshd -t` and is
  ignored — the change opened the firewall, found nothing listening and reverted, every time, on the
  current LTS. The panel now detects socket activation and writes an `ssh.socket` drop-in, whose
  content the helper restricts to listen addresses, since a unit file can run commands as root. A
  bind address that would lock you out is refused before anything is touched — loopback, where sshd
  starts fine so the change used to report success, or an address the host does not have — and a
  bind change's message no longer promises a fallback port that `ListenAddress` cannot provide.
  After a port change the Public SSH card no longer reads `2222/tcp` as port 22 open, and a reverted
  change removes the allow rule it had added.
- **The panel-login fail2ban jail never banned anyone on Debian or Ubuntu**, while the panel showed
  it Active. Those distributions default every jail to `backend = systemd`, which reads the journal
  and ignores `logpath`, and the panel writes failed logins to a file. The jail now pins a file
  backend, and a jail with a stale `logpath` or the wrong backend is rewritten on startup, so
  existing installs correct themselves.
- **Commands with a lot of output, and helper verbs run outside systemd, no longer hang.**
  `run_command` waited for a remote command to exit before reading its output, and a command that
  fills the 2 MiB window cannot exit — a long `journalctl`, a fail2ban log grep or a big update's
  output hung that request for good. And 26 helper verbs read a stdin nobody sent them: under
  systemd stdin is `/dev/null`, so it went unnoticed, but started any other way they sat until
  "Command timed out".
- **Console lines are no longer cut at 80 columns, and the player list with them.** `tmux
  capture-pane` returns the pane's visual lines unless asked to join them, so every line was
  hard-wrapped mid-word — and a vanilla Minecraft `list` reply, which puts every player on one line,
  parsed as one player named `Ali` out of twelve. That count feeds the Players panel, the
  empty-server notification and reboot-when-empty. Also in the console: a chunk beginning with a
  newline could arrive glued to the line before it; **Load older** had never worked, always
  answering "Could not load more console output"; reverse video and the bright background colours
  were kept but styled by nothing; undated lines sat 78px left of dated ones; and when a re-run
  action's log was truncated, the first chunk of its output was dropped.
- **Pages no longer offer controls their route refuses, and a few that did nothing now work.** A
  moderator holding only "start server" was shown Stop and Restart as well, on the dashboard and in
  the bulk bars; Files & Config was offered to viewers who could not open it; the panel host's
  Manage page showed superadmin-only controls to holders of "manage remotes", and read the panel's
  port as blank; the Groups page linked to pages a delegated admin could not open. Clicking the text
  of the pending-restart banner called `window.stop()` and aborted every request on the page. After
  importing discovered servers, the host page's Uninstall posted without its CSRF token. The Install
  page fetched itself in full every eight seconds, and the players card and the History tab could
  stay empty on first load. Hiding a server page's Controls card stopped the rest of that page's
  live status from updating.
- **Browser fixes in the translated UI and the dashboard.** With the page in Spanish or French, the
  translator rewrote user data — a server named "Console", a username "Admin", a folder called
  `Backups`, so uploads were said to go into a folder that does not exist — and counted phrases like
  "7 entries" could never be translated. The "System updates waiting" security banner dismissed
  itself six seconds after every page load. "Show this panel again" never restored a hidden panel. A
  new tag did not appear on its dashboard row until a reload, so filtering by it hid the server.
  Copy on the 2FA backup-codes page did nothing on an `http://` install; Tailscale's "waiting for
  you to authorize" polls never stopped; the Join link was intercepted on touchscreen laptops; and
  Ctrl/Cmd+K was swallowed on the login page.
- **Bad requests and down hosts no longer answer 500.** A JSON field of the wrong type made two
  dozen endpoints fail with "Something went wrong"; a host that is simply switched off made the
  mutating remote endpoints raise; and with no error handler at all, any failure on an API call came
  back as an HTML page the browser could not parse. API calls now get JSON errors with a real
  status: a 400 for bad input, and an "unreachable" answer for a host that is down. A `config.json`
  that is valid JSON but not an object (`null`, a list) crashed every page, and one that does not
  parse is no longer overwritten with defaults — backup passphrase and whitelist included.
- **Scheduled Tasks edit and delete work on a crontab whose first line is indented.** The read
  stripped that indentation, so delete reported success and removed nothing, and an edit added its
  rewrite beside the original — the job then ran on two schedules. A `%` in a restart-pending job
  was cut off by cron, and rescheduling the panel's own daily-restart line in the generic editor
  ended its run tracking.
- **Notifications that fail are logged, and a restart cannot replay a Telegram command.** A provider
  that rejected a message (a rotated token, a deleted webhook) logged nothing, so alerting could
  stop without a trace. After a restart, a failed Telegram priming poll asked for every unconfirmed
  update Telegram still held — up to 24 hours — so a `/stop` sent hours earlier stopped a running
  server. `/console` printed an internal sentinel instead of saying there was no session, and
  `/players` reported a server that was down as empty.
- **The install page says why the game list is empty** — a DNS failure, an HTTP error, a response
  that was not a CSV, a read-only `data/` — instead of a fixed guess about GitHub. Retry tells a
  fresh fetch from the cached copy, rather than answering "Loaded 30 games." with every fetch
  failing.
- **Editing your own account can no longer leave the panel without a superadmin.** With a password
  reset or 2FA change in the same edit, the demotion was committed before the "last superadmin"
  guard ran: the request answered "aborted" and the panel had none left, recoverable only through
  `manage.py`.
- **A new host or server no longer inherits a deleted one's state.** SQLite hands a deleted row's id
  to the next insert. A deleted host's auto-block opt-in (which then added UFW denies to the new
  host), its backup-schedule overrides, its cached specs and Ubuntu Pro status, and the address
  player queries were sent to all carried over; so did install and bootstrap job state (a new server
  shown as "Install failed", a new host refused because "a bootstrap is already running"), up to 14
  days of CPU, RAM and player history, the distro used to pick its package list, and its place in
  every user's saved layout. All of it is cleared with the row now, including when every host is
  deleted.
- **Downloading a game backup whose name contains a newline or a non-Latin-1 character** (an
  em-dash, CJK) no longer fails with a 500.
- **Console text is no longer struck through, bolded or italicised at random.** SGR 38/48/58 are
  extended-colour *introducers* that consume the parameters after them — `38;5;n` is one
  256-colour instruction, `38;2;r;g;b` one truecolor instruction. The panel dropped the introducer
  and then read each sub-parameter as if it were its own attribute, so an RGB triple became
  formatting: `48;2;1;9;3` came out as dim + bold + **strikethrough** + italic. Minecraft converts
  a plugin's `§x` hex colour into exactly these sequences, which is how a line ended up drawn
  through an EssentialsX warning and the URL beneath it. The whole instruction is consumed and
  dropped now (the panel does not render extended colour), and a real code sharing the same
  sequence still applies.
- **The console no longer loses output, or cuts a line in half, during a busy burst.** The poller
  reads at most 64KB per tick but then advanced its offset to the log's *full* size, so anything
  past that cap was silently discarded — and the 64KB boundary itself landed mid-line, reaching
  the screen as a fragment (a bare `[20` where a timestamp had been sliced). A server writing more
  than 64KB between two 2-second polls is not hypothetical: it is every Garry's Mod start, loading
  hundreds of Lua modules, which is exactly when someone is watching. The offset now advances by
  what was actually read, so a burst drains over the next few ticks instead of being thrown away,
  and a chunk's trailing half-line is held until the next read completes it.
- **The panel no longer offers to turn LinuxGSM's `logtimestamp` on**, and offers a way to turn it
  off. It works — the log really is stamped at write time — but LinuxGSM builds the capture as
  `cat | gawk '{ print strftime(...), $0 }' >> consolelog`, and gawk writing to a *file* is block
  buffered, not line buffered: measured at 0 lines reaching the log after 33 lines of input, with
  everything appearing only once 4KB had accumulated. On a quiet server that is an apparently
  frozen console. The pipeline is built in `command_start.sh`, so nothing in the panel can add an
  `fflush`. Shipped as a one-click offer before that was measured; the parsing stays, so a log
  stamped by hand still reads correctly, but the invitation is gone.
- **Console lines with a timestamp are no longer taller than lines without one.** The gutter is an
  inline-block, and per CSS an inline-block whose `overflow` is not `visible` takes its baseline
  from its bottom margin edge rather than its last line box — so it hung below the text beside it
  and the line box grew by a descender to contain it. Measured at 24.44px per stamped line against
  18.72px unstamped, which reads as ragged double-spacing wherever stamped and unstamped lines
  meet. Reported as "why is there like a extra space inbetween lines".
- **Console timestamps now appear on a server that only polls, and an empty column says why.**
  Reported as "I still don't see the timestamps in the console", and it was two things. The
  timestamp was attached only to lines pushed over the websocket; the 30-second HTTP poll that
  also feeds the console passed none — so on an install whose websocket cannot connect, *no* line
  ever got a time. A poll delta is new output the panel just watched arrive (accurate to the poll
  interval) and is stamped now; only the first window, which is history written before the panel
  looked, stays blank. Second, on an idle server every line on screen IS that first window, so the
  column was legitimately empty and indistinguishable from a broken feature — the console now says
  "Times appear on lines as they arrive" while nothing is stamped, and drops the note the moment
  one is.
- **Schedules are now set in your own time, not the host's.** A cron entry fires on the host's
  clock — which this panel's own bootstrap sets to **UTC** — and the daily restart wrote a
  hardcoded `0 5 * * *` with no time shown in the UI at all. So "daily restart when empty" on a
  server run by someone in US Central fired at 23:00 their time, in peak hours, and nothing on
  screen said so. The panel now learns each host's timezone and keeps it; the restart time is
  entered in **your** timezone and converted before it reaches the crontab, with the host's own
  time shown underneath ("Runs at 19:00 on the host (Asia/Tokyo)"). The cron editor carries the
  same label, so its "Daily 5am" preset finally says whose 5am. A host whose timezone cannot be
  read says exactly that and leaves your time untouched rather than guessing UTC.

  One caveat that cannot be engineered away here: a crontab line is a fixed wall time on the host,
  so where two timezones' daylight-saving rules differ the schedule is an hour out after the next
  changeover. The panel writes what is correct today and shows you the host time it wrote.
- **A long action's output no longer vanishes when you reload the page.** "when you refresh the
  page after i did update...those messages went away" — and they did: the console socket reaches
  only the pages open at the time, and `/api/console` rebuilds a console by tailing the *game's*
  console log, which a panel action never writes to. So an update's output lived in exactly one
  place, the DOM of whichever tab happened to be open. The panel keeps a bounded per-server
  backlog of what it pushed and replays it on the next console load — including when the host is
  unreachable, which is when you most want to still be able to read what the update said.
- **"Watch the live console for progress" was not true of any long action.** Accepting an update,
  validate, backup, force-update, mods-update or fastdl answered with exactly that, and then sent
  nothing to the console at all — reported as "it says to watch the console for updates, there is
  nothing that gets sent to the console". The command ran on its own SSH channel with its output
  captured into a variable, so the only place it ever surfaced was the audit log after the fact,
  truncated to 300 characters; and the console the message points at is a tail of the *game's*
  console log, which an update never writes to. An operator watching it saw an unchanging screen
  for the whole download, with no way to tell a working update from a stalled one. A long action
  now tees its output through a file in the game user's home, and the console poller tails that
  file on the same ticks it already tails the game log — so the output appears as it is produced,
  bracketed by `[panel] update started` / `[panel] update finished` markers. The full output still
  comes back to the panel, so the audit-log entry and the chat bots' completion message are
  unchanged.
- **The Update button appeared for games that have no update command.** `GameServer.supports_update`
  knows the Call of Duty family is not SteamCMD-based (`_NO_UPDATE_GAMES` exists for exactly that),
  and `/api/servers/bulk-action` asks it and skips those servers with "no update support". The
  control bar computed the same thing a second time, and for a server whose command list had not
  been fetched yet its version failed open for *every* game — so the detail page offered Update on
  a Call of Duty server, accepted the click as a long action, told the operator to watch the
  console, ran a command LinuxGSM does not have, and discarded the error. One question with two
  answers, and the button had the wrong one; it asks the model now.
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
- **A tag named like a branch can no longer stand in for it, and a commit main only reached
  through a merge no longer counts as main.** git reads a bare `origin/main` as a tag called
  `origin/main` before the branch, and the installer's clone, its fetches and the panel's branch
  list all bring tags along. So once a tag pushed under that name had been fetched, the next update
  reset the checkout to a commit that was never on main, and the panel's update card, branch list
  and verified target all read the same tag. The installer and the panel now name the branch in
  full, both when they read it (`refs/remotes/origin/main`, and only after confirming that ref
  exists — a missing one falls through git's lookup to a tag named `refs/remotes/origin/main`) and
  when they fetch it (`+refs/heads/main:refs/remotes/origin/main`, where a bare `main` fetched a tag
  of that name instead). Naming the destination also fixes a single-branch clone tracking another
  branch, whose remote-tracking ref was never created, so the update card said "up to date". The
  branch list no longer fetches every tag, and the switcher confirms a branch by its exact name,
  where `dev` used to be "found" by a branch called `feature/dev`.

  "On main" now means main's own first-parent line, not "an ancestor of main". A pull request
  merged with a merge commit brings all its commits into main's ancestry, including an intermediate
  one whose change was reverted before the merge. The update card offered such a commit as the
  verified target while the merge was still being checked, the installer accepted it as a pin, and
  root staged the helper from a checkout sitting on one. All three, and the auto-deploy, now accept
  only a commit on main's first-parent line, never the side of a merge. That line holds the
  commits main's tip has been at and each commit of a multi-commit push or rebase merge, with one
  exception: a push that fast-forwards main onto a branch that had main merged into it (a
  "foxtrot" merge) moves the commits main was at before onto that merge's second parent, and they
  are no longer accepted as a pin or deployed by a re-run. The installer and the deploy read that
  line as a stream, so neither a long history (a here-string of it needs a temp file past 64 KiB,
  which fails on a full or read-only /tmp) nor an early match (`grep -q` in a pipe kills
  `git rev-list` with SIGPIPE) can make a commit on the line read as off it.

  The installer's "never move backwards" rule, which keeps a newer checkout where it is when handed
  an older verified commit, asks only whether that checkout is an ANCESTOR of main: it is what
  the host already runs, not something being verified, and a host left off the first-parent line by
  a foxtrot push must not be reset backwards. The full update path (taken when the venv is stale) also
  honours that rule now; it had been resetting a current checkout back to the older commit. And a
  pinned commit the installer cannot verify is no longer replaced by main's tip, which nothing had
  verified: a checkout on main stays where it is, with a warning, and any other stops the update
  with an error that names the pin, having changed nothing.

  The CI auto-deploy had the same gap one step earlier: its trigger compares the branch's short
  name, and GitHub compares it ignoring case, so any ref whose short name matches main
  case-insensitively passes — a pushed tag `main`, a branch `Main`, a tag `MAIN`. It now requires
  the name to be exactly `main`, fetches main's history, proves the commit is on main's
  first-parent line before taking its installer, and refuses a commit with no installer or an
  empty one with a stated error. All of that happens before the job joins the tailnet. The job
  also logs in to Tailscale with OIDC workload identity instead of an OAuth client secret: no
  secret is stored, and Tailscale accepts only a token GitHub signed for this repository's
  `production` environment, which only the branch main may use. The old secret was a repository
  secret any branch or tag could read (the header of `deploy.yml` has the one-time setup).
- **The panel's Python dependencies are installed by hash.** `requirements.txt` is now pip-compile's
  lockfile for a new `requirements.in`: the same 33 versions as before, each with the hashes of its
  published files. pip refuses any download that is not byte-for-byte what was locked. The installer
  gets this with no change, because pip checks hashes whenever the file has them. CI and the fuzz
  image also install wheels only. Packages already installed on a host are kept as they are; the
  check applies to whatever pip installs from now on.
- **Preparing a remote host no longer runs NodeSource's setup script as root.** The add-host
  bootstrap piped `https://deb.nodesource.com/setup_lts.x` into a root shell, so anyone able to
  serve that one URL could run code as root on every host being prepared. It now does what
  `install.sh` already does on the panel host, through a new `nodesource-setup` verb. Only the
  signing key is downloaded, and it is trusted only if the file holds exactly one key with the
  pinned fingerprint. The apt source and pin are then written directly, and nothing downloaded is
  executed. The key, Node.js major (24) and paths are `install.sh`'s, and a test keeps the two
  copies equal. A remote that already has Node.js 18+ keeps it, as before. npm is now installed
  only when a Node.js 18+ is present, as `install.sh` does. Before, a failed NodeSource setup on
  22.04 went on to install the distro's npm, and with it Node 12, which gamedig cannot run on. The
  panel host's helper refuses the verb: `install.sh` sets up NodeSource there. `SECURITY.md` had
  said this step could not be narrowed; it now describes what replaced it.
- **A ban now closes what the banned address already had open.** A ban refuses new connections, at
  the firewall or, behind Tailscale Funnel, at the panel's own gate. A live console or a host
  terminal opened before the ban was not a new connection, so it kept streaming for as long as the
  browser stayed. Under Funnel that always happened; on a direct connection it happened under a UFW
  deny, because ufw passes established traffic before its own rules. Every new ban reading now
  disconnects the sockets whose client it names, which also closes that terminal's shell.
  Whitelisted addresses and tailnet peers are left alone.
- **API-token guessing reaches fail2ban.** Failed bearer-token attempts were throttled inside the
  panel and written nowhere else. So fail2ban never banned them, the 7-day auto-block never counted
  them, and the Funnel gate never refused them, while password guessing met all three. Once the
  token throttle refuses an address (20 misses in 5 minutes), each further attempt is written to
  `data/auth.log` as a line the panel-login jail counts, and the block is audited once per window.
  Individual misses are not logged, so a script with a stale token that retries now and then is not
  banned at the firewall for a config mistake. The jail's filter is rewritten on start to match
  the new line.
- **The whitelist protects every jail on the panel's own host.** Remotes got the whitelist on all
  of their fail2ban jails, sshd included. The panel's own host had it on the panel-login jail
  alone, so a whitelisted admin could still be banned from SSH on the machine the panel runs on,
  while the Security page said "never banned or blocked". The same drop-in is now written there. It
  is not created for an empty whitelist, since it would replace a `[DEFAULT] ignoreip` you set
  yourself. The remote copy is built by the same code, which drops an IPv6 zone-id entry that could
  carry a newline into the file.
- **Tailscale peers are never banned from the panel login.** The panel-login jail exempted the
  tailnet only when it banned on every port (a proxied panel). On a panel reached directly, five
  mistyped passwords from an admin's own laptop banned that tailnet address from the panel for an
  hour, despite the README's promise. The panel's own login throttle still applies to them.
- **Values written into page scripts are JSON-escaped throughout**, and a test fails the build if
  one is not. The language code, the CSRF token and a server page's mount prefix were written into a
  quoted string with HTML escaping, which is the wrong escaping inside a script. None was
  exploitable, since each value is either generated or validated, but the protection rested on
  that. The audit log's sort header no longer emits raw attribute text. All 45 Semgrep findings
  were triaged: those fixes, plus a stated reason beside each false positive.
- **A client banned for failed logins is refused when it arrives through Tailscale Funnel.**
  fail2ban and the auto-block ban at the host firewall, and Funnel traffic never reaches it:
  tailscaled connects to the panel from `127.0.0.1`, so a banned client carried on at eight guesses
  per five minutes while the panel announced the ban. The panel now keeps the current ban set —
  fail2ban's jail plus UFW's denies — in memory and answers a proxied request whose forwarded client
  is on it with a bare `403`, ahead of everything, the console socket included. The security
  whitelist and tailnet peers are never refused, and an IPv6 ban covers its /64. On a dual-stack
  `::` bind, tailscaled appeared as `::ffff:127.0.0.1`, so every Serve or Funnel client was keyed as
  loopback and one attacker's failures throttled everyone; those sessions may be signed out once
  after the update. `X-Forwarded-Prefix` is now believed only under `trust_proxy`, so a proxy on the
  same host that mounts the panel under a sub-path must set it (the documented nginx and Caddy
  setups do). A socket already open when its client is banned stays open until it closes.
- **The game-account group cannot be used to reach root.** The sudoers grant lets the panel become
  any member of `lgsmpanel-games`, so enrolling an account that can already `sudo` would make it
  `NOPASSWD:ALL` with one hop — and the installer's sweep over `/home` meets exactly those accounts,
  since LinuxGSM's own docs run it under the operator's account. The check looked for one English
  phrase in `sudo -l`, so an unknown user, a missing sudo or a non-English host all read as safe. It
  now answers yes, no or unknown, and only a definite no enrols. It also refuses members of
  `docker`, `lxd` and `disk`, and sudo reached through a group or an alias; asks every sudo present
  when accounts come from LDAP or SSSD (Ubuntu 26.04's sudo-rs ignores those, the classic `sudo.ws`
  beside it does not); and trusts a cached "not allowed" only while SSSD's sudo responder answers.
  An "unknown" no longer evicts existing members during an update, and a sudoers rule for `ALL`
  users is refused with a message saying to narrow it.
- **A compromised panel account can no longer choose what root runs.** On a root install the panel
  runs as `lgsmpanel` and reaches root only through the helper, and several paths let that account
  steer root anyway. The self-update ran the panel-owned venv's Python on a panel-owned script
  before fetching anything, and ran that venv's `pip` as root. The helper, `db_maintenance.py`, the
  installer and the recovery command were installed from a checkout whose `origin`, index flags and
  git filters the panel controls — and deleting the helper file widened the grant to `NOPASSWD:ALL`.
  Root now stages them from its own clone (`/usr/local/lib/linuxgsm-panel/.source.git`) or an
  operator's root-owned tree, pip runs as the checkout's owner, the grant narrows only while the
  helper really exists root-owned, and an unfamiliar `origin` withholds every root-owned install,
  the recovery command included, and says so — a fork is still a legitimate thing to run. Every
  root-run Python in the installer and uninstaller runs isolated (`-I`), since a self-update runs
  them from the checkout, where a planted module would have been imported as root.
- **Secrets the panel cannot read, or should not expose.** With a `cred_key` that did not match
  (rotated, restored or replaced), the backup passphrase read as "none set", so backups — which
  carry `panel.db`, `secret_key` and `cred_key` — were written unencrypted without saying so; they
  are refused now. The same mismatch made a stored SSH host-key pin read as empty, so the panel
  accepted whatever key a host presented and pinned that instead; it refuses, and the fingerprint
  reads "unreadable (cred_key mismatch)". The connection test run against existing hosts accepted
  any host key, and a password host whose credential could not be decrypted fell back to the panel's
  own `~/.ssh/id_rsa`. The Ubuntu Pro token and the Tailscale auth key were command-line arguments,
  readable from `/proc` by any local account on the target host while the command ran; they travel
  on stdin now, and the helper refuses them as arguments.
- **SSH hardening takes effect on cloud images.** sshd keeps the first value it reads for each
  keyword, and Ubuntu's `sshd_config` includes `sshd_config.d/*.conf` first — so writing
  `PasswordAuthentication no` into `sshd_config` changed nothing where a cloud-init drop-in says
  yes, while the panel and the bootstrap reported the host hardened. It now writes
  `00-panel-hardening.conf`, which sorts first, on the panel host and on remotes, and only where
  sshd reads that directory.
- **The weekly root cron no longer upgrades npm**; it installs a pinned `gamedig` with install
  scripts disabled. On the panel host, NodeSource's repository is set up with its signing key
  pinned, instead of by running NodeSource's setup script as root (remote hosts: see above).
- **Auto-block cannot cut off your tailnet, or take over your own rules.** When the Tailscale probe
  failed, tailnet addresses lost their exemption and could be denied at UFW position 1, above the
  `tailscale0` allow; an address that cannot be confirmed is now exempted. Auto-block replaced, and
  later released, an operator's own `ufw deny`, and counted a deny sitting below an allow as a
  block. IPv6 offenders can now be blocked.
- **Hostile input can no longer freeze the panel.** A crafted `?next=` backtracked exponentially;
  password hashing ran on the event loop, stalling every request during a login; a silent or
  flooding remote host could hang or exhaust the panel, as could one hostile line in the cron
  journal or an encrypted backup whose header asked for a minutes-long key derivation. Transitive
  Python dependencies are pinned too.
- **A delegated admin can no longer take over an account that reaches more than they do.** Holding
  "manage users" was enough to reset a more privileged account's password — the new password comes
  back in the response — and clear its 2FA, or to do the same to a peer with identical permissions
  but hosts the admin was never granted. An admin may now administer only an account whose
  permissions and hosts are a subset of their own. Granting a group whose permissions they already
  held handed over that group's hosts; deleting a group skipped the escalation guard the edit path
  applies; the default group could be deleted by a direct POST; and a delegated admin could add or
  repoint a host onto the panel's own SSH keys or tailnet identity — such admins can now add only
  password-auth hosts, and changing a host's address, user or auth needs the new password in the
  same request. An invite outlived its creator once the next account took their id, and its group
  grant outlived its creator's demotion; revoking one in the instant it was redeemed no longer
  reports a revocation that did not happen.
- **Delegated admins and viewers see only what they can reach.** The groups page offered every host
  and server on the install as a tick box (a tick outside their reach was silently dropped), and the
  sidebar, `/api/tags`, the group summaries, the users page and `/tailscale` each showed hosts or
  servers beyond the viewer's grants. The audit log showed any holder of "view logs" the whole
  install's trail — other servers' console commands and every admin's sign-in address among it; a
  delegated viewer now sees their own rows and those about the servers and hosts they can access.
- **Session protection is enforced.** The default `strong` setting did nothing; a session is now
  bound to its client's address and User-Agent. Existing sessions are bound on their first request
  after the update rather than signed out, and behind Tailscale the bound address is the device's
  tailnet IP, so a phone changing networks stays signed in. Toggling a phone browser's "Request
  desktop site" changes the User-Agent and signs you out; choose `basic` in Settings if that gets in
  the way. A database error while loading a session also skipped the revoked-device and remember-me
  expiry checks and let the request through; it now refuses.
- **The privileged helper no longer follows links, or accepts content the panel does not write.**
  Root copied restore files through symlinks planted in the staging directory (reading
  `/etc/shadow`, or writing into `/etc/cron.d`); the GMod content verbs chowned a symlinked
  `~/serverfiles` to the content account, chmodded every symlink's target to 0777, printed any
  root-readable file through a symlinked `mount.cfg`, and followed a symlinked `serverfiles` when
  removing content; `content-cron-write` put any line into `/etc/cron.d`, one running as root
  included; the offline database repair, the self-update log and the port picker wrote through names
  the panel user could plant; and a restore gave root-created files the staged set-id bits. Files
  are opened without following links, created fresh with a fixed mode, and read as the game account
  where they live in its home. `write-file` accepted any numeric sysctl or `APT::` key and fail2ban
  content that could run a command; both are exact allowlists now. The per-account verbs, which
  reached any non-root account, are limited to the game-account group on a hardened host, and
  imports are enrolled automatically. A restore no longer leaves a plaintext copy of the panel's
  keys behind. The helper is root-owned and outside the checkout, so these reach a host when
  `install.sh` runs as root.
- **A game server can no longer be pointed at an account that is not its own.** A server named
  `lgsmpanel` made root run `userdel -r` and `rm -rf` over the panel's own home — database, both
  keys, config and every backup — for anyone with "manage servers"; the panel's account is now
  recognised by what its home holds, even when `panel.conf` is unreadable. An install could take
  over or delete an account that already existed, `root` included. Importing took the account name
  from the request, so naming `root` created a server whose game commands then ran as root; it
  accepts only what the scan found. And the remote rendering of `userdel -r`, `pkill -u` and
  `crontab -u` accepted `root` where the helper refused it.
- **The login throttle can no longer be dodged by choosing a header.** The client's address keys the
  login and API-token throttles, the audit log and `data/auth.log`, which fail2ban reads. It came
  from the first `X-Forwarded-For` hop — the one a client always controls — so twenty failed logins
  with twenty values were never throttled, and fail2ban banned whichever address the attacker named.
  The first fix preferred `X-Real-IP`, which Tailscale Serve, set up by the panel itself, passes
  through from the client untouched. The address is now the last `X-Forwarded-For` hop, with
  `X-Real-IP` only when there is no `X-Forwarded-For`, and neither is used unless it parses as an
  address; a local account can no longer forge its login address either, and the README's nginx
  example sets both headers. Behind a proxy the panel-login ban covers every port, not only the
  panel's backend port.
- **Session cookies and the console socket are tied to the right origin.** Behind a reverse proxy —
  the setup the README recommends — the session and remember-me cookies were issued without
  `Secure`, and a captured remember token is a working login for `remember_days`; a `site_domain` on
  a plain-HTTP panel did the opposite, marking them `Secure` so the browser dropped them and login
  looped forever. The CSRF exemption for API-token requests also covered a request signed in by the
  remember cookie, so a logout carrying no CSRF token went through. `X-Forwarded-Prefix` could point
  every link and redirect off-site with `//host`, and `/panelserver/1` was treated as under a
  `/panel` mount. The console and terminal socket now accept only the panel's own origin, port
  included, or `site_domain` — another node on the same tailnet is refused — so a reverse proxy that
  rewrites `Host` to loopback and forwards no host needs `site_domain` set.
- **The setup wizard cannot be finished, or reopened, by someone else.** On a fresh install an
  unauthenticated POST could jump to the last step and close setup before any admin existed, leaving
  a panel nobody could sign in to and reconfiguring Tailscale Serve on the way; completion now
  requires a superadmin. The wizard stayed open after the admin account existed, its join-my-tailnet
  step included. And it stored the panel's bind address unchecked — `0.0.0.0; rm -rf /` was
  accepted, and the panel would not come back up.
- **Two-factor authentication is harder to get around.** Turning 2FA off needed only the password —
  a weaker gate than changing the password, which already asked for a code; it now needs a current
  code or a backup code, and a backup code is not spent on a request that fails for another reason.
  The code that turned 2FA on could be replayed at login within its ~90-second window. Generating an
  API token needed only a session; it now asks for the password and, with 2FA on, a code, and a
  password change or "sign out everywhere" now revokes API tokens, which survived both.
  `manage.py`'s 2FA disable clears backup codes too, a pending 2FA secret no longer sits in the
  session cookie, and a mistyped code no longer costs a bcrypt per backup code.
- **Routes and sockets that did more than their permission allowed.** A custom command's
  `argument_pattern` was never enforced — one restricted to `^(easy|normal|hard)$` sent `9999` — and
  a pattern over 200 characters was stored truncated, which can turn it into "accept anything";
  over-long patterns are refused now. "Refresh commands" needed only access to the server.
  `playerlist?console=1` typed `status` into the game console for anyone who could see the server;
  it needs console permission. The Tailscale install, up and serve endpoints act on the panel host
  and now need superadmin, as do the install-wide whitelist and auto-block threshold on the remote
  pages. Opening a game port needed only "install server" and took any port; it needs "manage
  remotes" and a port a game server on that host uses. Dismissing an install card had no permission
  check, and switching language wrote the stored preference on a GET any site could trigger. Console
  access was checked once, at join: a viewer whose access, permission, session or account was
  revoked — or who was told to change their password — kept watching. It is re-checked every poll
  now.
- **What players type can no longer steer moderation or Discord.** A Source `status` row puts the
  name before the SteamID, so a player named `STEAM_0:1:11111111` had that ID on their row, and a
  Ban click banned that third party — fleet-wide under "all servers", and into the global ban list.
  A player named `my uniqueid` could blank the player list. A Minecraft kick of a name containing a
  space could reach someone else; it is refused now. And Discord replies parsed mentions in player
  names and console text, so a player could mass-ping the operator's Discord whenever an admin ran
  `!players`.
- **Stored values can no longer change where or how a command runs.** A remote's `auth_method`
  selects its transport and was stored unchecked, so a forged `local` sent every command for that
  host — console input, file writes, privileged verbs — to the panel's own machine; it is checked
  against the three methods the form offers, and clearing a field on the edit form no longer stores
  an empty host or user. Every security validator was anchored with `$`, which accepts a trailing
  newline — `linuxgsm_user = "lgsm\n"` ran the panel's commands as the SSH login instead; they use
  `\Z`. The root `apt-get` for game dependencies took package names unvalidated from a
  panel-writable cache file, and the crontab rewrite put an unquoted account name into a root
  pipeline.
- **`linuxgsm-panel-recover` picks the right install, or asks.** Run as root during a lockout, it
  took the alphabetically first per-user install under `/home` — where every game-server account
  lives — so one could plant a fake panel and be handed the new superadmin password the operator
  typed. It now refuses when there is more than one candidate, names them, takes `PANEL_DIR=` to
  settle it, and prints which install it is using before asking for anything. It is installed
  root-owned rather than linked to a panel-writable file, no longer pairs one install's directory
  with another's service user, and a `panel.conf` it cannot read no longer ends the run.
- **Smaller hardening.** The Tailscale Serve mount reached `tailscale serve --remove` unvalidated,
  where a value starting with `-` is read as an option; ssh control sockets were trusted in a `/tmp`
  directory anyone could create first; a remote host's `uptime` output reached the page as markup;
  names from host discovery could forge a record; the delete guard let a path climb out and back
  into `lgsm/`; and live metrics interpolated a stored game-user name unchecked.
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
