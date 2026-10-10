# Changelog

All notable, user-facing changes to the LinuxGSM Panel. The project is alpha — see the README
disclaimer. A version is the date of the commit, in UTC, written YYYY.M.D (`2026.9.26`) and shown
with the short commit; the numbered sections below (0.8.0 to 0.10.0) are from before that. The
panel's in-app "update available" check compares git commits, so you always get the newest
CI-verified commit regardless of this file — this changelog is for humans.

<!-- Every release repeats the same Added / Changed / Fixed / Security headings, as Keep a
     Changelog lays them out, so MD024 is asked only to keep two SIBLING headings apart. -->
<!-- markdownlint-configure-file { "MD024": { "siblings_only": true } } -->

## [Unreleased]

### Added

- **Rename a file or folder in the file browser.** Every row that can be deleted now has a Rename
  (pencil) control, at every width. It turns the row's name into a field holding the current name,
  with the part before the extension selected, so typing replaces `notes` and keeps `.txt`. Enter or
  Rename sends it, Escape or Cancel puts the row back, and when the panel refuses, the reason shows
  under the field so you can fix the name where you typed it. It covers renaming something you just
  uploaded, and a file open in the editor follows its new name. A rename stays in its own folder,
  and the same rules guard it as Delete. The new name must be a single name: no `/`, not `.` or
  `..`, at most 255 bytes, and no character that would make it read as another name (control
  characters, line or paragraph separators, text-direction controls, or a space at either end:
  `server.cfg ` looks exactly like `server.cfg`). The name is sent as typed and never trimmed; a
  name the panel refuses comes back with the reason. Protected LinuxGSM paths cannot be renamed, and
  no other name can be renamed onto them. Nor can the live console's log or the `log` and
  `log/console` folders it is in, also when the logs are reached through a symbolic link, because
  the console would stop until the server restarts. A path reached through a symbolic link to a
  folder is refused, not followed. An existing name is never replaced, including one that appears
  while the rename runs; there is no "replace" option. A game account that can become root is
  refused, as it is for every other file write. Every rename request from someone allowed to manage
  files is in the audit log (`rename_file`): renamed, refused (with the reason, including a name
  refused for its form) or unconfirmed. If the host doesn't confirm the rename, the panel says
  exactly that and asks you to reload, rather than guessing whether it happened.
- **Clean host reboots: running game servers are stopped first and come back after.** Every reboot
  the panel makes — a host's Power card (the panel's own host too), the reboot-needed banner, the
  command palette, "reboot when everyone has left", `POST /api/remote/<id>/reboot` and `POST
  /api/server-management/reboot` — now stops the host's running game servers with LinuxGSM's
  graceful `stop` first (verified by the tmux session, never the exit code), reboots, and brings
  back exactly the servers that were running. Before, the reboot's SIGTERM killed them ungracefully,
  and a stop beforehand would have deleted LinuxGSM's monitoring lock, so nothing came back. Now the
  lock is moved aside for the stop and put back before the reboot — at a second of the minute no
  `*/5 monitor` run can read it, with no LinuxGSM command in flight — so Autostart servers come back
  by LinuxGSM's own monitor exactly as after a plain reboot, even with the panel down. Running
  servers WITHOUT Autostart are started by the panel once the host is back (a new setting turns that
  off); stopped servers stay stopped. One summary notification (a new `host_reboot` event) says how
  soon after the reboot was sent the host's new boot started and its servers were running again
  (by Autostart, started by the panel, or found already running), how many stayed stopped and why,
  which have not come back (one left to LinuxGSM's monitor gets 12 minutes from the host's new
  boot), and how many running servers could not be read (the panel neither stops nor restarts
  those). A reboot that did not happen —
  refused by the host, or a panel restart before it was sent — is undone: every server is put back
  as it was, including one restoring would have left stopped (only a queued stop stays stopped),
  and you are told.
- **With players on, the reboot asks.** The dialog lists who is on each server (and which counts
  can't be read) and offers **Wait: reboot when everyone has left** or **Reboot now**. A forced
  reboot warns players in-game at 60, 30 and 10 seconds where the game can show a message (Source,
  GoldSrc, idTech3 and Minecraft consoles). Work a reboot would cut off (an install, a backup,
  LinuxGSM maintenance, a package upgrade, a panel update) refuses "now" and can be waited for.
- **The wait is visible and bounded.** A pending "reboot when everyone has left" shows on the
  host's Power card and in the banner (with who it is waiting on and a Cancel button) even when no
  reboot is required, gives up after 24 hours (setting `reboot_wait_max_hours`, 0 for no limit) with
  a notification, reminds you once when a server's count has been unreadable for 30 minutes, re-checks
  each server right before stopping it (a player who joins in that moment puts it back to waiting),
  and is cancelled with a notification when the panel restarts.
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

- **A documentation-only pull request no longer runs the whole CI.** CI only. When every file it
  changes is `*.md`, `docs/`, `LICENSE` or a git/editor dotfile, the heavy checks pass at once under
  their required names; secret scanning, Dependency Review and the unit suite (it reads the docs)
  still run. Anything else, or a file list that cannot be read, runs everything. Pushes are unchanged.

- **CodeQL now reads the whole smoke test suite.** The 1 MB suite is split into a runner and six parts
  (`tests/smoke/`), running the same 1,636 checks in the same order; CodeQL had skipped it for time.
  The complexity gate judges a file split out of another together with that file, so moved code is not
  counted as new. CodeQL uploads an analysis only when it completed, and the alert gates never count a
  failed or cancelled run's empty upload as a commit's analysis.
- **The security scanners now read the tests too.** CI only; nothing on a panel changes. Bandit,
  Semgrep and CodeQL used to skip `tests/`, so a mistake in a test, such as a check that can never
  fail, went unnoticed. They read it now, and the first scan found a few. One check read a value
  only after the next step had already reset it, so it could not fail. Three refusal checks counted
  any crash as a refusal. The inline-script checks missed an upper-case `<SCRIPT>` tag. All are
  fixed. Semgrep had also been silently skipping files over 1 MB and stopping rules early on the
  largest suites. It now reads every file in full and fails if it can't. CodeQL now fails its run
  if the root-run helper, `tools/panel-helper` (a Python file with no `.py` extension), is missing
  from what it analysed. CodeQL skips one 1 MB test file, which takes it 24 minutes to read.
  Bandit, Semgrep and SonarCloud still read that file.
- **Two more CI scanners: zizmor on the workflows, and Harden-Runner in every job but deploy.**
  CI only; nothing on a panel changes, and no panel is offered an update for it.
  - *zizmor* audits the GitHub Actions setup itself: template injection, over-wide token
    permissions, credentials left behind by checkout, dangerous triggers and, online, impostor
    commits and action versions with a known advisory. A new workflow, `Security scan (workflows)`,
    runs it on every pull request, on pushes to main and weekly, at its pedantic persona, and
    uploads the findings to code scanning, where both alert gates wait for them as they do for
    CodeQL, Bandit and Semgrep. The scanner runs with a read-only token; a second job uploads.
    Its first run found 19 things at the strictest persona. Fixed: a version comment that named no
    tag, five permissions with no comment saying why and one (`actions: read`) that nothing used,
    two unnamed jobs, an optional Codacy token readable outside a main-only environment, and a
    coverage upload that two runs for one commit could interleave. Accepted, each marked beside the
    code with its reason:
    the three `workflow_run` workflows, and five workflows whose check lands on main and so carry no
    concurrency group on purpose. A unit check names every accepted finding.
  - *Harden-Runner* (StepSecurity) is the first step of every job but one, in audit mode. Audit mode
    applies no allow-list, but it is not passive. It routes each job's DNS, docker's included,
    through its own proxy. It blocks any host on StepSecurity's global blocklist, which it fetches
    when the job starts, so the list can change without a commit here. It prints what it saw into
    the job's public log: each address the job connected to, and the command line of each process
    the job ran as root. The same records go to StepSecurity. A job fails if the agent's download or
    start fails. The deploy job is the exception. It holds the tailnet identity that reaches the
    live panel, so a deploy does not depend on StepSecurity's runtime blocklist, and its log does
    not list the deploy host's address or every command it ran as root.
- **A reboot request with no mode and players on now answers 409 instead of rebooting.**
  `POST /api/remote/<id>/reboot` with no body used to reboot at once; with players on (or a count
  nobody can read) it now answers `{"error": "players_online", "needs_choice": true, "choices":
  ["when_empty", "now"], ...}` and the caller asks again with `{"mode": "now"}` or
  `{"mode": "when_empty"}`. `{"when_empty": "false"}` no longer arms a wait (a string was read as
  true), and an unknown mode is a 400.
- **Host reboots from a bootstrap or install.sh never reboot a host with game servers on it.** They
  leave the reboot-needed banner and say to reboot from the host's Power card, where the servers are
  stopped cleanly and brought back.
- **While a host is being rebooted, actions on its servers wait.** Start, stop, restart, update,
  Autostart, installs, OS updates, a bootstrap and the panel's self-update are refused for that host
  until the reboot is sent, and the queued-restart and backup sweeps skip it. After that, an
  operator's own Start or Stop takes the server out of the restore. While the reboot runs, the
  panel's own "server offline / back online" and "host unreachable / back online" alerts are held
  for the servers and hosts it took down, also when the panel restarts in the middle of it (it
  always does when the host is its own); the summary reports on every server the plan held. Once
  the summary is sent, the monitor holds it to its word: a server it counts as running again whose
  port is still shut three minutes later (12 more minutes for an Autostart server after a reboot
  that did not happen, which LinuxGSM's monitor restarts), or that crashes, pages "went offline
  unexpectedly"; one it reports as not back pages "back online" when it returns, if that alert is
  on. A running server whose state could not be read is not in the plan: the notices count it, and
  on a remote host one still down eight minutes after the panel began stopping the host's servers
  pages "went offline unexpectedly" (on the panel's own host the panel restarts too and does not).
- The panel host's helper now runs LinuxGSM as `./<script>` from the game home instead of by its
  absolute path, so LinuxGSM's own monitor can see a start or stop the panel is running there and
  backs off instead of starting a second copy.
- **The panel makes far fewer privileged calls, so the host's journal stops being mostly its sudo
  lines.** Every `sudo` writes three journal lines (and three to auth.log). On a host with three game
  servers the panel made about 580 such calls an hour, and they were 99% of its unit's journal. Each
  of these now skips work it did not need. On some hosts the restart banner can now appear later
  than before; that is named below. (A server the panel cannot query can also read "unknown" for a
  minute where it read 0; see the `details` entry under Fixed.)
  - The metrics history no longer looks up each running server's map every minute. It stores no
    map, so the answer was thrown away.
  - The player poll reads the map in the same gamedig reply as the player count. The dashboard
    uses that answer instead of running gamedig again, and two pages asking at once share one
    lookup.
  - The player poll runs one gamedig command per host instead of one per server. It runs as one of
    that host's game accounts, never as the panel's own account or the SSH login, and on the
    panel's host never as an account in an administrator group or one that is root by another door
    (docker, lxd, incus-admin, libvirt, disk). A server that command could not read is asked on its
    own, as before.
  - The server page's player list is read only while the Console tab is showing, and two viewers
    polling within ten seconds share one read. Refresh, and the re-read after a kick, always ask.
  - The priority keeper checks nice values without privilege. It renices only the game accounts
    that drifted, instead of every account on every host every two minutes.
  - The ban watcher reads the UFW rules only when ufw's rule files have changed, and at least every
    15 minutes. Blocks the panel makes itself are still read at once. fail2ban is read every 90 s as
    before.
  - The restart-banner flags are read every minute only for a host where daily restart is on or a
    banner is showing. Other hosts are read every 10 minutes, and a host with no servers is never
    read. So on a host without daily restart, a restart banner from a crontab the panel does not
    manage (an imported server, an edit in the terminal) can now appear up to 10 minutes late
    instead of within a minute.
  - The live console reads the log's size and its new lines in one command instead of two.

  The saving is a model, not yet a measurement of a running panel: one pass of each background
  loop, with every host command stubbed and counted, multiplied by each loop's period on the live
  host. For three servers the model gives about 9 privileged calls a minute before (the live host's
  report measured about the same) and about 2 after.

  A console you are looking at still costs one call per two seconds; apart from merging its two
  reads, the console was left as it was. A console tab left in the background no longer costs
  anything (next entry).
- **A console tab left in the background stops costing the host a privileged read every two
  seconds.** Once a server page's tab has been hidden for 30 seconds it leaves the live console, and
  the panel stops reading that log when nobody else is watching it: one sudo call every two seconds,
  about 1,800 an hour, for each console left open in another tab, a minimised window or a locked
  phone. A quick switch away costs nothing. Coming back rejoins straight away and fills in what was
  written in the meantime from the log file, each line once and in order, along with the panel's
  own lines that went to the console meanwhile, such as an update's result. The panel works out
  where the page left off by its position in the log file, not by matching text, so lines the
  game repeats word for word, such as a heartbeat or an autosave notice, are neither dropped nor
  shown twice. That includes a return whose connection dropped while the tab was away, as it does
  on a phone that slept. A tab whose connection was already down when it left, and that had been
  sent no new line since it last read the log, has no position to go on and is still matched by
  text. The catch-up shows at most 2,000 lines. If more was written, or the server
  was restarted while the tab was away (a restart starts a new log file, and the catch-up reads the
  current one), or the host never answered the catch-up's read, the console says that some output
  is not shown, at the point where it is missing. Lines filled in this way have no time beside them
  unless the log itself stamps them, since the panel did not see when they were written. A tab
  stays in while an update or another long panel action it saw start is still running, so that
  action's output keeps arriving as it is written.
- **The debug report says what is wrong, covers far more of the panel, and is safer to post.** It
  now opens with **At a glance**: every problem any section found, failures first, and the sections
  that could not be read. Below that is one verdict line per area. Diagnostics are sorted worst
  first. Each section heading says how long it took. A section that failed or ran out of time says
  so in its heading. It is never left out or shown as "(none)", which read the same as "nothing
  there". The whole report has a 20-second budget, and the header gives the time it took.

  New sections cover:
  - **the panel process**: systemd's own view of it (automatic restarts, memory, linger), how far
    the event loop has lagged, what it is listening on against config.json, whether HTTPS really
    started at boot, and unit-file drift from what install.sh writes;
  - **background workers**: each loop's last pass beside how often it should run, and supervisor
    restarts;
  - **errors swallowed since start**;
  - **install and privilege**: the install model, the helper asked through `sudo -n`, which sudo
    answers, and root-owned pieces compared with the commit;
  - **updates**: which checks hold an update, the last run judged by its exit status, the update
    history, and installer warnings from the whole log;
  - **network and access**: Tailscale, Serve and Funnel, proxy trust, a login-loop predictor for
    the session cookie, UFW, fail2ban jail health, and sign-in counts held against auth.log;
  - **hosts and game servers**: transport, reachability and the last probe error per host, Tailscale
    peer state, game-server status from the database against the monitor, port collisions, and
    stranded installs;
  - **the live console**, per watched server;
  - **the database**: pragmas, backups, a table census and an audit digest;
  - **panel backups, notifications, dependencies** (from what is installed), and **Config**,
    showing the file and what the process runs with;
  - **a digest of journal errors** before the recent log, which keeps the newest and most important
    lines instead of cutting at 8000 characters. On a system install the panel's own privileged
    calls (about three a minute, three journal lines each) used to fill the whole log. They are now
    counted by helper verb ("restart-flags ×714, …") and left out, so the log shows the panel. A
    refused `sudo` still shows.

  The header's commit is now the code this process is running, not the checkout. When the two
  differ, the header says RESTART PENDING. "Open a GitHub issue" puts the "describe the problem"
  prompt first, and its prefill is sized to the length of the encoded URL.

  **Privacy.** Known names are replaced with tokens that are the same in every section, such as
  `[host-3]`, `[server-5]` and `[user-2]`. This covers hosts, game servers, panel users, OS and SSH
  accounts, tags, groups, Tailscale node, peer, tailnet and login names, and notification chat and
  topic ids. IP addresses print as their class, such as `[ip:public]`. Paths print as `<panel>`,
  `<data>` and `/home/[user]`, and a traceback frame keeps its module. A Privacy footer counts what
  was replaced and says what the pass cannot cover. The old "contains no secrets" claim is gone, and
  the report asks you to review it before posting. This closes leaks the old report had:
  - Config printed bind_host, site_domain and site_title.
  - The Data directory check printed the absolute path, and with it the account name.
  - The log tail, the last update's installer output and the Discord gateway text were printed as
    they were.

  **Fixes the report brings with it.**
  - **Security card (panel host).** A stopped fail2ban read as "no jails", and a UFW whose status
    could not be read read as disabled. The card now says "Could not read fail2ban on this host".
  - **Journal fallback.** It never ran, because journalctl prints "-- No entries --" and exits 0. It
    could also run `sudo` without `-n`. It now reads the user journal, then the helper, then the
    system journal filtered to the panel's own uid, and it never prompts.
  - **Hub stall.** Generating the report froze the whole panel for as long as two SQLite integrity
    checks took. Both ran on the event loop. It now runs one read-only check, off the loop and
    bounded. A locked database is "not checked", no longer reported as damage.
  - **Diagnostics corrections:**
    - Service is read from systemd's state, not from a unit file existing.
    - TLS says whether the panel uses its certificate, and a TLS start that failed at boot is a
      failure.
    - Database integrity says whether a restart would restore a backup or start EMPTY.
    - Data directory shows its owner and mode, not its path.
    - File integrity names the changed files and the paths hidden from git.
    - Privileged helper tells "refused" from "timed out".
    - A new **Host credentials** check says whether stored credentials decrypt.

  The panel's own warnings, and the notification service's, now reach the journal as
  `WARNING <logger>: <message>`.
- **CI now catches on a pull request, or on main, what it used to let through.** An audit held
  every CI configuration against its vendor's documentation and fixed each gap it found. CI only;
  nothing on a panel changes.
  - *Code scanning.* The pull-request alert gate waits until Bandit and Semgrep have analysed this
    merge commit, as well as the three CodeQL languages, and fails naming any category that never
    arrived. Before, it judged whichever analyses had landed. The main gate no longer sends a `sha=`
    parameter that the API ignores: it checks that every category's newest analysis is this
    commit's. The weekly CodeQL scan is now judged on main, so its findings no longer surface first
    as a red check on an unrelated pull request.
  - *Dependencies.* osv-scanner now audits gamedig's npm tree, which every host installs, and every
    CI tool's pip lockfile, at any severity. It fails when a lockfile yields no packages. pip-audit
    now runs `--strict --disable-pip`; it had audited `requirements-bootstrap.txt` as 0 of 1
    packages. Dependency Review now blocks low and moderate advisories, not only high. Dependabot
    waits 7 days after a release, as Renovate already did. Semgrep installs from one hash lockfile
    with a fixed PyJWT. gitleaks uses its current `git` command and `[[allowlists]]` table.
  - *Codacy and SonarCloud.* The main Codacy gate asks for High as well as Error issues. It fails
    when an accepted finding vanished only because Codacy stopped reading a file over 150 KB. The
    complexity check runs Codacy's Prospector over those large files on every pull request. A new
    `SonarCloud open issues (main)` check fails on any issue open on main that is not known. Those
    include issues a pull request leaves on lines it did not change, which Sonar's pull-request
    check does not report. A test pins `.sonarcloud.properties`, so widening an exclusion fails the
    build.
  - *Fuzzing.* ClusterFuzzLite keeps its corpus and builds as Actions artifacts, so batch fuzzing,
    corpus pruning and coverage run. Before, they were off waiting for a storage repository.
    "Fuzz the diff" gets the vendor's 600 seconds, and its harnesses start in about 2 s instead of
    about 10 s, so its targets fuzz instead of timing out. Every job that reads a stored fuzz
    artifact first fails if any was not made on this repository's main. A fork pull request could
    otherwise plant a build that a privileged job unpacks and runs.
  - *The rest.* The unit checks that only run as root now run as root on every CI leg; one fixture
    they use had broken unnoticed. actionlint fails if its shellcheck pass is not running, and
    fails on an unknown `vars.*` name. The deploy job's Tailscale client is pinned by version and
    sha256, with the action's unverified cache turned off. A test fails any `uses:` not pinned to a
    full commit SHA.
- **SonarCloud is told what it was guessing.** `.sonarcloud.properties` answers its three analysis
  warnings: the Python versions the panel supports (3.10 to 3.14), `tests/` as test code (it was
  running production rules on the suites), and UTF-8 throughout, with the vendored minified bundles
  in `static/vendor/`, every image and font, and the fuzz corpus left out of the analysis. The
  encoding warning was two literal replacement characters (U+FFFD) in tests, which SonarCloud's
  scanner reports as invalid in any file; they are written as `\ufffd` now. A test fails the build
  if a file it reads is not UTF-8 or holds a U+FFFD or a NUL.
- **Every scanner's verdict is a merge requirement, on every pull request.** Actionlint, Dependency
  Review and the two fuzzing workflows ran only when their files changed, so they could not be
  required, and a red one would not have held a merge. They run on every pull request now (the fuzz
  jobs pass at once when a change touches nothing they fuzz) and are required. And SonarCloud's free
  plan keeps the "Sonar way" gate, which lets new code smells through: a new required check,
  `SonarCloud new issues`, waits for SonarCloud's analysis of the pull request's head and fails on
  anything new.
- **A pull request cannot merge into main until its checks pass.** Before, only the secret scan
  was required; tests, CodeQL, Codacy, SonarCloud, Bandit, Semgrep and pip-audit were waited for by
  habit, not enforced. `.github/required-checks.txt` lists what main's ruleset now requires, and a
  test holds it to the workflows: every one runs on every pull request (the four main workflows no
  longer skip docs-only ones), and a new job is required or the build says why not.
- **A new check catches what Codacy's pull-request check misses.** Codacy counts an issue as new
  only on a changed line, and it files a function's complexity and length on its `def` line and a
  file's length on line 1, so a function that grew past the limit passed as "0 new issues" and the
  issue appeared on main (23 by 2026-09-30). `complexity (Codacy limits)` compares every changed
  file before and after with Codacy's limits, files over 150 KB included (Codacy skips those), and
  fails on what the change adds. It found one at once, in the update check's own new code, fixed
  here.
- **Renovate proposes updates to the release binaries CI downloads.** gitleaks, actionlint and the
  Codacy coverage reporter are pinned by tag and sha256, which Dependabot cannot see, so they were
  bumped by hand. `.github/renovate.json` runs only a regex manager over those pins, and Dependabot
  keeps everything else. A release must be 7 days old before it is proposed, and each proposal
  carries the new tag and the new release's sha256 together. CI only; nothing on a panel changes.
- **The version is now the date of the commit the panel runs.** It reads `2026.9.26`: the
  commit's date in UTC, with no leading zeros, and always beside the short commit (the footer, the
  update card, the Telegram and Discord messages and the installer's "Code updated" line), because
  every commit made on the same day shares the date. It comes from git, so nothing has to be bumped
  by hand any more, and the hand-kept 0.x numbers stop at 0.10.0-alpha; the sections below keep
  them. A copy downloaded as a ZIP from GitHub has no git history, so its `VERSION` file carries the
  commit's time, filled in by git when the archive is made. The Release workflow, which only ran
  when `VERSION` changed and never cut a release, is removed. The update that brings this change
  in is offered and run by the code the host already has, which reads `VERSION` as text, so for
  that one update the card offers `v$Format:%ct$` and the installer's log names it the same way;
  once it has landed, the panel and the installer show the date.
- **Deleting a host says what stays on it.** The delete makes the panel forget the host and never
  connects to it, so gamedig (`/usr/local/lib/linuxgsm-panel/gamedig` and its two links) and the
  weekly root cron that re-runs its install script (`/etc/cron.d/lgsm-node-tools`) stay there,
  and the confirmation did not say so. It does now, and README has a "Removing a host" section:
  what the panel put on a remote host and the commands that remove it, with the one case where
  not to run them (a host that runs a panel of its own).
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
- **The update card answers one question: is there something to install?** It shows "Update
  available" or "You're up to date" (with the running SHA), and nothing else: no line saying a
  commit is still being verified, could not be verified, could not be fetched, or is only docs. It
  offers an update exactly when one would be allowed to install — still the newest commit that has
  passed CI — and that changes a file the panel runs. A verified commit below a tip that is still
  being checked is still offered, and the commit count and the list come from the same set. Commits
  that touch only docs, CI, tests or tooling are not an update: they arrive with the next one that
  is. (For eleven days they were offered too, and a CI-only merge put "Update available" on every
  panel for an install that changed nothing.) Every file in the repository is named as one a host
  runs or one it does not, and the build fails on a new file named as neither, so neither mistake
  can slip in: a file a host runs never goes un-updated, and nothing else raises an update. The
  build also checks that every module the panel imports and every file the installer reads is on
  the runs side.
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

- **The Tailscale page no longer shows "12/31/1" as the last-seen time of every connected
  device.** Tailscale reports a placeholder for "no time" for a device that is online now, and the
  page printed it as a date in year 1. Connected devices now show a dash; offline ones keep their
  real last-seen time.
- **A game server the panel starts on its own host now writes its files group-writable again (664),
  as it does when LinuxGSM's cron or a login starts it.** Since game servers were given a scope of
  their own, the privileged helper ran LinuxGSM (and a scheduled task's "Run now") with the panel
  service's umask, 0022, so new console logs and lock files were 644. It now uses the umask the
  account's own session gets — login.defs' `UMASK` with Ubuntu's user-private-group rule, 0002 for a
  game account — computed the way pam_umask does. Remote hosts already got it through `sudo -u`.
- **"Reboot now" no longer misses a LinuxGSM action that a newer one on the same server displaced.**
  The reboot check read only the newest registered action, so in the moment that action was ending
  (its last output still being read), an older update or validate still running beneath it was not
  seen, and the reboot could stop the server under it. Every action still running is now counted.
- **The live console no longer shows a few lines twice when a server's page opens**, and no longer
  drops the lines written while it loaded. The page now learns where in the log its first window ends
  and is caught up from there, as a return from a background tab already was, so new lines are placed
  by their position in the log, not by their text. A line the game repeats word for word still shows.
- **A backup that LinuxGSM reports as finished is "Backed up" only when its archive reads whole.**
  LinuxGSM exits with success even when the archive failed, if it restarted the server afterwards; the
  panel then removed a good old backup to make room for the broken one. Now it says the backup is not
  confirmed and keeps every old backup. After a backup that failed, the partial archive it left is
  removed, but only when it is certainly that run's and the run has certainly ended; after a timeout, a
  lost connection or a lock refusal nothing is removed. The message says when an archive was removed.
- **The file browser's editor, the Config card's Raw tab and uploads refuse a LinuxGSM config that
  turns `logtimestamp` on**, which freezes the live console. Turning it off, and commented-out lines,
  still save.
- **Findings from a full code review (2026-10-08): fixes.** Every item below has a check that fails
  without its fix.
  - **Game servers and alerts.** A batched player poll counted bots and reserved slots instead of
    people, so a Bedrock server with players on read 0 and sent a false "server emptied" alert. A
    failed backup no longer runs the cleanup, which deleted one more good backup each time. Server
    actions, single or bulk, now skip a server that is still installing. During a remote reboot, a
    server whose state could not be read no longer pages "went offline unexpectedly" before the
    host is back. In "reboot when everyone has left", an unreadable player count is not "a player
    joined", and an earlier plan still restoring is not taken for a rollback. The Power card's
    colour comes from the outcome, not from the words in it.
  - **The live console.** After a dropped connection, the console catches up from its own place in
    the log, as a tab returning from the background does. It used to add the last 250 lines a second
    time. A line that arrived while the first window was loading is no longer lost, and "Load older"
    is not reverted by the next poll. A game line that happens to be exactly "Done" or "Saved" is no
    longer translated.
  - **Files and settings.** A folder that is a symbolic link (LinuxGSM's own `log/server`, or a
    `serverfiles` moved to another disk) is listed and opened as a folder. Saving or uploading onto a
    folder's name fails instead of moving the file inside it. Deleting or renaming a link that leads
    outside the home acts on the link. Deleting a folder closes an open editor inside it. The Config
    form no longer offers `logtimestamp`, which freezes the console, and the config writer refuses
    turning it on. A config save sets every line of a key written twice, so the copy LinuxGSM reads changes too.
    "Run now" on a remote records its result when the command ends in a `#` comment.
  - **Hosts.** The firewall lockout guard protects the port sshd really listens on, not a leftover
    22 rule. A mistyped timezone or an over-long account name is refused before host setup starts,
    instead of stopping it halfway with the firewall and SSH hardening unapplied. Host setup no longer
    locks an account it could not confirm it created, and no longer reports a reboot that never
    happened as "back online". A reboot that was never sent is not waited on. One server with a
    non-numeric port no longer breaks metrics for every host. The GMod content mount fails when the
    read grant fails, instead of saying "Mounted".
  - **Panel.** Renaming the default "Everyone" group no longer creates a second default group with
    console access on the next restart. The database repair stops if it cannot first keep a copy of
    the original. A fail2ban reconfigure that could not write its files says so, instead of reporting
    the old jail as updated. A git, sudo or `systemctl` timeout is reported as a timeout instead of an
    error page. The auto-block watcher survives a bad setting and logs it. The Ubuntu Pro cache no
    longer expires early or late on a host not set to UTC. The first-run wizard applies the same
    username rules as everywhere else. Group ids in the user and invite forms are parsed safely. A host that cannot reach GitHub no longer
    waits up to 10 seconds for the game list on every page that needs it.
  - **Debug report.** A service read that times out no longer fails the whole Diagnostics section,
    and is not reported as "no unit file". A group or tag named with one of the report's own words
    no longer rewrites its text. The journal read without the helper no longer scans the whole
    journal, and the SSH failure count includes the rotated log.
  - **Pages.** The GMod Apply button, the Power card's reboot polling, the Install Tailscale button
    and the setup wizard's Tailscale step recover from a failed request. A Tailscale host's edit form
    hides the credential field from the start. An invite link is no longer presented as a one-time
    password. Enter in the Tailscale mount-point field no longer reloads the page.
  - **Install and uninstall.** The install banner no longer calls a blocked port open. The
    uninstaller removes a rate-limited (`LIMIT`) panel port rule and names the NodeSource repository
    it leaves in place.

- **The file browser fits a phone inside a folder with a long name, and its path shows a name's
  spaces.** The path and the Upload / Upload folder buttons shared one row that could not wrap or
  shrink. On a 375px phone, inside a folder named `hang44-wwwwwwwwwwwwww`, Upload folder ended 8px
  past the screen, so the whole page panned sideways and taps landed off target. With a 40- or
  80-character folder name the buttons were off screen altogether (the page was 587 and 957px wide).
  An 80-character name pushed a desktop page 20px wider than the window too. Now, below 992px, the
  buttons move to a row of their own when the path needs the room; from 992px up they stay beside
  the path, as before, and a deep path wraps next to them. A name too long for the card wraps inside
  the path and is shown whole, never cut short. Measured at 320, 375, 414, 768, 992 and 1280px over
  17 paths (names of 21 to 80 characters, with spaces, hyphens and Japanese, and paths up to nine
  levels deep): the page is never wider than the window, and both buttons stay whole. Each folder
  in the path is now a target at least 24px wide and 24px tall. It was as narrow as 3px (`i`) and
  14px tall. So a path of short names such as `serverfiles/tf/cfg` is a little wider, and a path
  that wraps onto two lines is 8px taller. Separately, the path and the "Drop files … to upload to"
  label collapsed the spaces in a folder's name, so `a  b` read as `a b` and ` x` as `x`. Both now
  show each name exactly as it is, as the file list does, including a space at the end. Found by
  the real-browser check of file rename on the test VPS.
- **An imported server is stored on the port it really uses, read on its host.** Importing a
  discovered server stored the port the browser sent, and 27015 when it sent none. Discovery read
  the first `port=` line it found in three of LinuxGSM's config files, and 46 of the 140 games
  LinuxGSM lists keep their port in the game's own config instead (Minecraft and PaperMC in
  `server.properties`, Teamspeak 3 in its `.ini`, 7 Days to Die in its `.xml`, and so on), so for
  those the card showed "—" and the import stored 27015. On the test VPS that is Garry's Mod's port:
  an imported Minecraft server read as up whenever Garry's Mod was, so its crash never paged, and
  Start was refused as "already running". Its player count, its "when empty" actions and its restart
  cron asked the wrong server, and 27015 stayed reserved for it, so a later install could not use
  it. Now:
  - Discovery reads the five config files in LinuxGSM's own order, secrets files included, takes
    the last `port=` (as bash does), and counts it only when the game's start line passes
    `${port}`. San Andreas MP's `port="7777"`, which the game never sees, no longer counts. It
    reads only regular files, never a symlink or a fifo, at most 1 MiB of each, and keeps only the
    two lines it needs: a fifo or a huge file in a game account's config folder can no longer
    stall the scan, or fill the memory of the root shell it runs in on a remote host.
  - The import stores the port its own scan read, never one sent with the request. When the scan
    has none, it asks LinuxGSM's `details`, which reads the game's own config. A server whose port
    still cannot be read is not imported, and the reason says what was seen: LinuxGSM did not
    answer (try again), or the game's own config is missing or does not set the port (set it there;
    a game that writes that file itself when it first starts, such as Vintage Story, needs one start
    first). A port that is the host's SSH or the panel's own is refused.
  - A server set to the same port as another server on its host is still imported on that port,
    because it is the port its config sets: on the test VPS, PaperMC's `server.properties` sets
    25565, as Minecraft's does. The import now says so, under "Import selected" and in its reply:
    it names each shared port and the servers on it, whether the other server came in the same
    import or was already in the panel, and says that no two of them can run at the same time
    unless one uses only TCP on that port and the other only UDP (LinuxGSM's Terraria and ARK both
    default to 7777, one TCP and one UDP), or each is bound to its own IP address. It also says
    that while one runs, the panel cannot tell them apart by port, so a stopped one may read online.
    A server on another host does not count. That note, the ones for servers not imported and for
    accounts not added to the game-account group, and the "—" port's tooltip are now in the
    viewer's language. The card holds account names, so the page's translator is kept out of it,
    and they had stayed in English.
  - Servers imported before this are re-read a minute after each panel start: the panel reads
    every installed server's port from LinuxGSM again and stores it where it differs (audited as
    `port_resync`). When the stored port is certainly not the server's — another server's, or one
    something else listens on while the server is stopped — the new port is stored even when
    another server shares it, as the import itself allows (Minecraft and PaperMC both default to
    25565), and its audit row then says so in the import's words. The audit rows are written once
    the host's moves are done, so the share they name is the one the pass leaves: a server moved
    onto a port that another one is leaving in the same pass (its config was changed to end the
    clash) is not said to share it. Otherwise the new port is stored only when it is free: in no
    other server's block and not listened on, because LinuxGSM says STARTED even for a game that
    failed to bind. SSH's and the panel's ports are never taken. A
    server that does not answer, or whose new port is not free, keeps its port until the next
    start, with the reason in the log; "Open all ports" on the host's Firewall page reads it again
    on demand. A move also points the server's restart-when-empty check at the new port, keeps the
    monitor from paging the move as a crash, and closes this server's own firewall rule on the old
    port when no other server can need it. It opens no firewall rule: "Open all ports" does that.
  - The same gap on the install side: when LinuxGSM reported no port before the first start, the
    install kept the port the panel chose as if it were confirmed. It now reads the port again after
    the first start and adopts it when nothing else held it before the start. When the host's
    listening ports could not be read before the start, it is not adopted, because the panel can't
    tell. If the port still can't be read, or is not adopted, the install says which and why,
    instead of promising the server will show as online "once it opens" a port the game may never
    use.
- **The file browser lists every file under its real name, including one whose name ends in a
  space or holds a line break.** The host's listing ended each entry with a newline, and every
  connection type (local, Tailscale, SSH) trims the whitespace at the end of a command's output. So
  when the entry listed last was a name ending in a space, the space went with the newline:
  `server.cfg ` was listed as `server.cfg`. Rename on that row said the file was no longer there,
  and Delete answered "Deleted" and left it in place. Worse, beside a real `server.cfg` both rows
  pointed at the real file, so Rename, Delete or Edit on the spaced row acted on the real config.
  Separately, the listing was split on every kind of line break Python knows, so a name holding
  U+2028, U+2029 or U+0085 (an upload can create one) showed cut short, under a name no file has.
  In each case, uploading a file of that name was not flagged as replacing it. Both listings now end
  each entry with a NUL, which no filename can hold and the trim leaves alone, and are split on that
  alone. Found by the real-browser check of file rename on the test VPS.
- **Bootstrap and install.sh rebooted hosts with game servers running.** Their "are game servers
  running?" check was `pgrep -x tmux`, and tmux renames its server process `tmux: server`: on the
  test VPS, with four LinuxGSM servers up, it found nothing, so a bootstrap re-run or an install.sh
  update that needed a reboot rebooted the busy host. Both now match the server's real name, and the
  bootstrap also counts any server the panel last saw online.
- **The Power card said "Autostart servers come back on their own"** and the reboot banner's
  "Reboot now" skipped the player check the Power card made. Both open the same dialog now.
- **Every Stop from the panel paged "went offline unexpectedly" about four and a half minutes
  later** (since #346, on by default). A server the panel stopped stayed recorded as running for the
  three minutes the panel expects it offline, so when that window ended with the server still
  stopped, as intended, the monitor declared it down and sent the alert. A Stop (the button, a bot,
  the palette, bulk, or a queued "stop when empty") is now recorded as down at once with no alert,
  and its return isn't announced either. Its window ends with a Start from the panel, or once the
  monitor has seen the server down, so a crash after that alerts as usual. A Restart (the button, a
  bot, the palette, bulk, or a queued "restart when empty") is meant to come back: nothing is sent
  while it does, but a server still down when its three minutes are up, or one that came back and
  crashed within them, pages "went offline unexpectedly" then, as the Restart button already did.
  A crash outside these windows alerts exactly as before, and its return still pages "back online"
  if that alert is on. A queued "stop when empty" was not marked as the panel's own at all, so it
  paged as a crash within about two minutes of running; a queued restart that leaves its game dead
  now pages when the Restart's three minutes are up, where it paged about two minutes after it ran.
  A server the panel first sees down after it starts (an update, a reboot of its own host) was
  never announced as down, so its return isn't announced either; it used to page "back online".
- **An update's output no longer appears twice in the live console.** On a server page opened
  before any panel action had run, an update's lines showed as they came, and a later console poll
  appended the whole update again beneath them.
- **An update that ran with no console open keeps its result.** The panel reads a long action's
  output only while someone has its console open. An update started from the dashboard, by a bot,
  or with the console closed got one read when it ended, of its first 64 KB, so a long one lost the
  lines that say whether it worked. The end now reads the last of the output in one read, as much
  as the console's history keeps (its last 598 lines, within 255 KB, whole lines only), so opening
  the console afterwards shows how it ended. When that leaves earlier lines out, a line above them
  says so and names the file on the host that holds all of the output. An action someone is
  watching still shows every line it printed, however many it wrote in its last seconds.
- **Player counts work for Counter-Strike 1.6 and 2, TF2, HL2:DM, Left 4 Dead 2, Call of Duty 4
  and Minecraft Bedrock.** The panel asked gamedig for them by names gamedig 5 renamed (`cs16`,
  `cs2`, `tf2`, `hl2dm`, `left4dead2`, `cod4`) or never had (`minecraftpe`), and every query
  answered "Invalid game". Player counts fell back to LinuxGSM's own query, and the daily
  restart-when-empty check could never see these servers empty. They now use gamedig 5's names
  (`counterstrike16`, `counterstrike2`, `teamfortress2`, `hl2d`, `l4d2`, `cod4mw`, `mbe`). Existing
  restart-check lines are rewritten by the daily cron upgrade.
- **A server whose query lists no player names is no longer counted as empty with people on it.**
  The panel counted players by the length of the name list gamedig returns. A Minecraft Bedrock
  server's reply never has that list, only the number of players. A Java server that hides its
  players, or a Source server that does not answer the player-list query, sends an empty one. Each
  read as 0 players whoever was on. The hourly restart-when-empty check then restarted the server,
  a restart or stop queued for when it emptied ran at once, and the reboot warning listed nobody.
  Every count now uses the server's own player number, less its bots, when that is larger than the
  list. The Players panel and the chat bot's /players now say they could not read the list instead
  of "no players connected". Existing restart-check lines are rewritten by the daily cron upgrade.
- **Autostart shows what the server's crontab really has after an install.** A new server's
  Autostart switch read On even when neither of the install's two attempts to write the monitor
  cron line worked, because both attempts' results were ignored. Such a server does not come back
  after a crash or a reboot. The switch now follows what was written and what the crontab reads back
  as, and a failed write is logged. A write that fails changes nothing: a new server starts Off
  until a write or the crontab says otherwise, and a retried install keeps what its earlier attempt
  recorded, because a failed write leaves that attempt's monitor line in place. When nothing can
  confirm the switch, the panel logs a warning. An install that failed before this version was
  created with the switch On before anything wrote the line; the upgrade sets such a server (one
  whose install never finished) Off, once, and its retry's first cron write or read corrects it.
- **The panel is published over Tailscale Serve at one address, and a leftover route to it no
  longer answers 502.** The boot re-point wrote only the configured mount (`tailscale_mount`), so a
  second route to the panel — at "/" beside /lgsm, say — kept the scheme it was written with and
  answered 502 from the next change of the panel's own scheme (a bind change, an update, a restore),
  while the debug report said the re-point was "ok". At each start the panel now also removes its
  own routes at other mounts on :443, one at a time with `tailscale serve --https=443
  --set-path=<mount> off`, reading Serve again right before each. Another app's route, and a route
  to the panel on another listener, are left alone, and nothing is removed when Serve cannot be
  read. A route at the same mount with a trailing slash ("/lgsm/" beside "/lgsm") counts as another
  route, because Serve answers every /lgsm/ page from it. Only a config set with `tailscale serve
  set-raw` can hold both, because every other Serve write replaces the other spelling. So the
  panel's own write at start clears such a route, and the Tailscale page and the debug report name
  it until then. Enable at a new mount does the same, and
  every Serve write uses the scheme the running panel serves rather than the one its next start
  will.
- **The setup wizard no longer publishes the panel twice.** Its finish read the "/" route its own
  Serve step had just written (or one from a hand-run `tailscale serve`) as another app's, and
  published a second route at /lgsm. It now adopts a route that already reaches the panel, and does
  nothing when the Serve step has run. The Serve step no longer publishes at "/" over another app's
  route, and the wizard says "serving" only when the panel itself is.
- **The Tailscale page can remove a leftover route on its own.** Each route to the panel that it
  does not manage is listed with a Remove button, which leaves the panel's address and settings
  alone. Like Enable and Disable, it first makes the panel's account the Tailscale operator, so it
  also works on a host where the route was made by hand. When Enable or Remove takes down the
  route the page was opened through, the page goes to the panel's own address instead of
  reloading into a dead one. Disable removes every route to the panel, where it removed one and
  cleared the mount, so the page in use at /lgsm lost its prefix and a second route stayed
  published.
- **The startup log, the setup-complete page and Recommended Access name the panel's own
  address.** They gave https://<machine name>, the root, which on a panel at /lgsm is another app
  or a leftover route. They now give the route at the configured mount, and only while it works.
- **The debug report names a leftover Serve route and how to remove it.** It said "a route reaches
  the panel with the wrong scheme" with no word on which one, and nothing at all when its scheme
  happened to match. Each route the panel does not manage is now listed with its listener and the
  exact `sudo tailscale serve --https=<port> --set-path=<mount> off` that removes it, and the boot's
  own removal is reported beside the re-point. When no route reaches the panel on the scheme it
  serves, that is still a failure, not a warning.
- **Uninstalling removes the panel's Tailscale Serve route.** It ran `tailscale serve --bg --remove`,
  which no Tailscale accepts, so the route stayed behind after every uninstall (and a reinstall then
  published the panel at /lgsm beside it). It now removes every route to the panel's port, and only
  those, and says what it could not.
- **An update says "this panel now serves HTTPS" only when that is new.** It said so after every
  update of a panel serving its own TLS, with a public address even when the firewall closed the
  port and with "set up Tailscale" when Tailscale Serve was already up. It now compares with what
  the panel served before the update, gives the Serve address when there is one, and gives the
  public address only when the firewall does not close the port.
- **The README no longer gives a `tailscale serve` command to copy.** Its
  `tailscale serve --bg --https 443 http://127.0.0.1:5000` answers 502 on a panel serving its
  default HTTPS. Use the wizard or the Tailscale page. docs/https.md no longer says Serve always
  takes over TLS: it does only once the panel is bound to 127.0.0.1.
- **The debug report's journal sections cover the panel's own output, not its sudo calls.** The
  report read the newest 5,000 journal lines and only then dropped the sudo lines. On a live host
  4,964 of the 5,000 were sudo lines, so the window covered under three hours and the recent log had
  36 lines. The report now asks journald for the panel's own lines by field, over the last 24 hours,
  so the lines it reads are the panel's output and not its sudo calls. The 24-hour window is what
  keeps the read short on any journal: asked instead for the newest 5,000 such lines, journalctl
  walked the whole of a 1.9 GB journal that held fewer, was still running after five minutes, and
  the report showed no journal at all. Each part of the request names something rare on its own (the
  panel's own output stream, a critical message, the unit), so a day on which the panel logged
  thousands of errors costs little more to read than a quiet one. When the window holds more than
  5,000 entries (a traceback is one entry, however many lines it prints), or the filtered read fails
  or runs out of its half of the time, the report reads the newest 5,000 lines as before; when that
  read has nothing either, the report says its lines are the oldest of the window, cut off. Refused
  sudo calls and the panel's warnings are still included. The sudo calls of the last hour are
  counted from a separate read and printed once, under *Errors in the journal*. Each is labelled by
  what it did (`gamedig players`, `console poll`, `console send`, `LinuxGSM config`, `backup prune`,
  `backup lock sweep`, `installed version`, `git` as the panel's own account, `true as root`, and so
  on) instead of "other command". Account names, paths, what was typed into a console and scripts an
  operator ran are never printed. The installer's calls as the panel's own account (the service
  account, or the login account a per-user panel runs as) are counted under their own label, not as
  a game account's; a game server run under that same account still has its gamedig and console
  calls counted as game work. A system install needs an updated helper for this; an older helper
  gets the previous read.
- **A privileged command the panel gives up on no longer keeps running as root.** When a call
  through the helper timed out, the panel stopped it with SIGKILL. That reached `sudo` alone, and
  sudo cannot pass a SIGKILL on, so the helper and the program it ran carried on as root with
  nobody waiting for the answer: on the test host a debug report's journal read kept a core busy
  for five and a half minutes, and every further report added another. The panel now sends SIGTERM
  first, which both classic sudo and sudo-rs pass on, and SIGKILL only after two seconds. The
  helper ends a read, and every process it started, when that SIGTERM arrives, when the sudo above
  it is gone, or after 60 seconds; a process that ignores the SIGTERM is killed even after the one
  that started it has exited. A LinuxGSM `details`, `check-update` or `postdetails` counts as a
  read (with two minutes before its own limit), so a timed-out one no longer leaves the helper
  waiting on it as root. A call that changes the host (apt, a firewall rule, a new account, a
  LinuxGSM start) still runs to its end when the panel stops waiting, as it always did, even
  after the sudo above it is gone: stopping it halfway would be worse. An update installs the new
  helper.
- **Call of Duty servers show the capacity the game reports.** gamedig gives cod's `maxplayers` as
  text ("16"). The panel threw it away and showed the LinuxGSM config's number instead.
- **A running game the panel cannot query no longer runs LinuxGSM `details` every 45 seconds.**
  This covers a game outside the gamedig list (Factorio) and one gamedig cannot reach. The `details`
  run (several `du` passes over the server's files) and the config reads came every pass. For a
  server the monitor sees listening, the player count is now "unknown" without asking. For up to a
  minute after such a server stops (until the monitor's next pass), it can show "unknown" where
  `details` would have said 0, and a reboot-when-empty or notify-when-empty waits for that pass.
  LinuxGSM's query settings, and a config that names no capacity, are re-read every 10 minutes
  instead of every pass.
- **The debug report no longer calls a systemd unit an email address.** A unit started from a
  template is written `name@instance.service` (`user@1000.service`, `getty@tty1.service`), and the
  report's email rule printed it as `[email]`, in cgroup paths and journal lines alike; so did an npm
  `package@1.2.3`. Neither is replaced now. Addresses still are, an address written after a unit
  name included.
- **The debug report's installer lines keep their paths and the commit they name.** Installer
  output was redacted before its paths were shortened, so on the usual install the data directory,
  the helper and gamedig all printed as `/[redacted]`, the verified commit an update moved to as
  `verified commit [redacted]`, and every address as a bare `[ip]`. They now print as `<data>/…`,
  `<panel-lib>/…` and `<gamedig>/…`, the commit as its first 12 characters, and an address by its
  class, as everywhere else in the report. The "Installer said" list no longer repeats a line the
  log tail below it already shows; its warnings are always listed.
- **The debug report's Privacy footer counts everything it replaced.** It counted only the names
  and addresses it pseudonymised, so a report with `[email]` and `[redacted]` in it said "nothing
  matched". A new "Redacted" line counts email-shaped strings, long tokens, key=value secrets, URL
  credentials and SQL parameter lists, each counted once however often it appears, and the domains
  and certificate issuers that Tailscale's health messages print as [domain] and [issuer withheld].
- **The debug report pseudonymises an account written before an address.** In `name@<IPv4>` the
  address rule ran first, so the email rule no longer saw an address and the account printed
  (`alice@[ip:tailnet]`); `name@<a known host>` was the same. The account is now an [account-N]
  token, the same one wherever else the name appears, a mention earlier in the same text or in the
  summary included. Names the report keeps everywhere, such as root, are kept here too, and so is a
  word no account can be named (one starting with a digit, such as a year). An email address whose
  local part is a name the report knows (an OS account, a panel user), or whose domain starts with
  a known host's name, is now `[email]`; the name was replaced first, so the address was no longer
  recognised, and its domain (or the name before the @) printed.
- **The debug report no longer says a self-update that completed DIED.** It read a log with no
  "installer exit" line as a run killed mid-update, and raised a [fail] at the top of the report.
  The panel's helper wrote no such line until its version of 2026-09-26, so every self-update an
  older helper ran ended without one, finished or not. When the log holds install.sh's own ending
  ("Update complete", "Already up to date", "Not updated") with no error after it, the report now
  gives that outcome, says the exit line is missing, and names what can leave it out (an older
  helper, or a run stopped after install.sh's ending) without claiming which one did.
- **The debug report prints Tailscale's health messages, not only how many there are.** Each one
  is on its own line, with node and login names, addresses, a self-hosted server's domain and a
  certificate issuer replaced, as the rest of the report replaces them; file paths and Tailscale's
  own help links are kept. A self-hosted control server's full host name is added to the names the
  report replaces everywhere.
- **The debug report says "node key expiry disabled" for a node whose key does not expire.**
  Tailscale leaves the expiry out for a tagged node or one with expiry turned off, and the report
  read that as "not recorded". A node that is not in the network map yet (it needs login) says the
  expiry is unknown instead, rather than claiming either.
- **The debug report's update lines say what was actually checked.** With nothing newer to install,
  the CI gate line read `ci_state=passing · target ?` although no CI was asked; it now says it was
  not consulted. An unverified newest commit is named as one, not as the "target". While newer
  commits are still being verified, the commit on offer is labelled "offered" rather than printed
  as origin's tip. And "Last 'update available' notification" says "none" when there is none,
  which is the usual state once an update is installed; it printed `?`.
- **The debug report no longer says a background job never ran when it is not due yet.** Several
  jobs wait before their first run (the monitor 60 s, the update check 30 s, auto-block an hour),
  and a report taken just after a restart said each had "never completed a pass". It now says when
  the first run is due, and for one that was due and has not finished, when it was due. "Not yet
  probed" hosts say that the monitor has not made its first pass yet, and when it will.
- **With `trust_proxy` off, forwarded headers from a local account other than root are logged and
  counted.** They were already refused, but nothing recorded it, so the debug report's "Forwarding
  headers ignored, last hour" always said "none". The log line no longer suggests editing
  `trusted_proxies`, which does nothing without `trust_proxy`. The report's "forwarded headers
  believed" line also names why: Tailscale Serve on loopback, or a proxy you declared.
- **The Backups page and the debug report no longer read the "Back up game servers now" button's
  last run as the automatic schedule's.** Automatic game-server backups keep one clock per server;
  only the button writes the time both of them showed. So an install whose weekly backups had run
  every week read "Never run" right beside the Automatic backups switch, and one whose button was
  pressed yesterday read "Last: 1d ago" there however overdue the schedule was. The button's own
  line now sits under the button and says whose it is, and the schedule's row shows the newest
  automatic backup from the audit log ("Last automatic backup: 2d ago", or that it failed — and when
  the newest failed, the newest that worked first, so one failing host does not hide the rest). The
  debug report prints the schedule per server (by id and game: interval, whose setting it is, the
  clock's age, "due since", "clock not started"; a clock the install or the schedule's first look
  at a server only started says "no backup yet" and when the first is due, where it said "last 0 s
  ago"), what the unattended backups recorded in 30 days,
  and the button's run under its own name. A default interval of 0 reads "default: off", because a
  server's own setting can still back it up. Unused code that would have backed every server up
  twice (`full_backup_due`) is gone.
- **"Back up game servers now" moves each server's schedule clock.** It did not, so every server it
  archived was still due to the hourly schedule, which archived it again at its old time: another
  stop and restart, another archive, and the prune evicting an older restore point early. A server
  it skipped (players online) or that failed stays due, as before.
- **A server that always has players on is no longer silently never backed up.** The schedule
  skips a server with players online and retries hourly, which is right, but a server never empty
  at the top of an hour was skipped for good with no record anywhere. Once it is a whole interval
  overdue (twice its interval since its last backup) that is audited and alerted, once — it is
  remembered in config.json, so the panel's daily restart does not repeat it — and again only after
  the server has been backed up. A "wait until empty" backup on a server whose own schedule is off
  is reported the same way after a week of waiting; pressing the button again does not restart that
  week. The report says how old the server's backup clock is and that players were on at that
  attempt, not that they were on at every attempt: the clock is also that old after a schedule was
  off, or a host's backups failed, for days. It is filed as its own audit action, so it does not
  read as a failed backup. No player is ever disconnected for it.
- **A backup host that is down sends one alert, not one an hour.** A scheduled or queued backup
  that raised (a direct-SSH host that is down, or a key it now refuses) is retried hourly, and every
  retry alerted again — twice an hour for a server both due and queued. The first failure of a
  streak alerts; the retries are still on the audit log. The next failure after a backup that
  reached the host alerts again. An audit-log write that fails (a locked database) no longer takes
  the alert with it, nor stops the rest of the sweep.
- **A failing daily panel backup no longer stops the game-server backups.** The hourly backup pass
  ran the panel's own daily backup and both game-server sweeps under one error handler, so a daily
  backup that raised skipped the game backups for that hour, every hour, and logged nothing at the
  default level. Each step now runs on its own, logs a failure as a warning naming the step, and a
  pass with a failure is counted as failed in the debug report.
- **A direct-SSH host that never answers can no longer stop every backup.** Waiting for the
  remote's reply to a command request had no time limit, so a wedged or hostile host held the
  caller for ever — and a backup sweep holds the one lock every backup on every host shares, so
  all scheduled and queued backups stopped, silently, until the panel restarted. That wait (and the
  channel open, for long commands) is now bounded at five minutes, for commands and for the backup
  and file downloads, and the connection that did not answer is dropped, so the next command on
  that host reconnects instead of waiting five minutes again. Hosts on the panel's own machine and
  over Tailscale were never affected.
- **A daily panel backup that cannot make its temp folder no longer leaves an empty "backup".** The
  archive's name was claimed before the temp folder was made, and a failure there left a 0-byte
  file that counted as the day's daily backup — so none was taken for 23 hours, and the Backups page
  listed one that cannot be restored.
- **The debug report names the notification events that are off.** It printed only a count ("15
  of 19"), so whether "A backup fails" was one of them could not be told. It now lists them by key.
- **Restarting or updating the panel no longer kills the game servers it started.** Every server the
  panel started on its own host — Start, Restart, an update, validate or backup that restarts it, a
  scheduled task's "Run now" — ran inside the panel's own systemd unit, and every panel stop,
  restart, crash or self-update sent it the same signals. On a root install that killed them, with
  nothing in the journal naming them, until LinuxGSM's monitor cron brought them back up to five
  minutes later (or never, with autostart off). On a per-user install it killed servers running as
  the panel's own account and filled the journal with "Failed to kill control group" for the rest.
  The privileged helper now starts each of them in a transient scope of its own, beside
  `cron.service` in `system.slice`, before it drops to the game account. On a per-user install, the
  servers an earlier version started under other accounts outlive the panel's stop, and are moved
  out once when it starts again. On a root install the stop that installs this update still ends
  them, as before; LinuxGSM's monitor cron brings back those with autostart on, and every start
  after that is in a scope. A per-user install without the helper uses its own user manager
  (`systemd-run --user --scope`); a host without systemd is unchanged. Measured on the test host:
  Minecraft started from the panel survived `systemctl restart linuxgsm-panel` (before: killed), and
  the panel unit stayed at 21 tasks (before: 61, with 585 MB of the game charged to it).
- **Panel-started game servers run at the game priority, not the panel's.** They inherited the
  panel's low-priority tuning (nice 10, I/O best-effort 6, and its CPU weight of 30 against cron's
  100); the priority keeper could undo only the nice, and only up to two minutes later. A Start or
  Restart now begins at nice -1 with no I/O class, and LinuxGSM's maintenance actions at nice 0 —
  what LinuxGSM's own cron gives the same actions — in a scope of their own. Where LinuxGSM runs as
  the panel's own account, the priority keeper no longer renices the panel itself to -1.
- **Repairing the database, restoring a backup and updating the panel no longer leave a root
  install's panel stopped.** Each ran inside the panel's unit and stopped that unit as its first step,
  which ended the job too: nothing was repaired or restored, the self-update died at step 1 of 6, and
  the panel stayed down until someone ran `systemctl start` over SSH. They now run as transient
  services of their own (as does the OS update, which a panel restart could kill mid-upgrade); a
  second one while the first is running is refused. Measured with the real helper on the test host:
  before, the stand-in panel was left inactive; after, it came back on its own.
  **Updating a root install TO this version: do it from a shell, once** — `sudo bash install.sh` in
  the panel's checkout (`/home/lgsmpanel/linuxgsm-panel`), or the one-line install command. The
  panel's Update button runs the updater the host already has, which is the previous version's and
  has this bug: it stops the panel at step 1 of 6, ends itself with it, and leaves the panel down
  until `sudo systemctl start linuxgsm-panel`. Every update after this one works from the button.
  A per-user install is not affected and updates from the button as usual.
- **An OS update can now restart the panel (root installs on Ubuntu 24.04 and 26.04).** With apt
  running in a service of its own, Ubuntu's needrestart (which on 24.04 and 26.04 restarts affected
  services by default) restarts `linuxgsm-panel.service` like any other service when the update
  replaces a library the panel has loaded. Before, apt ran inside the panel's unit, and needrestart deferred
  that one restart because it would have killed apt itself. The consoles reconnect once the panel
  is back, the OS-update window retries until it answers and goes on following the log, and the
  game servers, no longer inside the panel's unit, keep running through it.
- **Restoring a backup on a per-user install with the helper no longer swaps the files under the
  running panel.** The helper's restore stops and starts the SYSTEM unit, which a per-user install
  does not have, so the panel kept running while its database and its WAL were replaced beneath
  it. A per-user install now restores through its own user manager, chosen by the same system-unit
  test the database repair and the self-update use. That launch is now checked as well: a
  `systemd-run` that fails is reported as "Could not start the restore." and the staged database
  and keys are deleted, where it used to answer "Restoring…" for a restore that never ran.
- **The local web terminal's jobs outlive a panel restart.** A server, tmux or nohup job started in
  the panel host's terminal ran inside the panel's unit and died at the next restart or self-update.
  The terminal's shell now runs in a scope of its own. Uninstalling a root install stops those
  scopes before it removes the panel user, which `userdel` would otherwise refuse while a job left
  in the terminal is still running.
- **The debug report names game servers inside the panel's cgroup.** It listed them as "other",
  printed their memory as the panel's, and raised nothing. It now counts game-server processes (tmux
  servers, what they started, and leftovers older than the panel) with a warning that says what a
  panel stop does to them on this kind of install, splits the unit's memory into anon and file cache
  (the live report's "20976 MB" was mostly page cache), says the peak covers the cgroup's whole life,
  counts processes it could not read instead of dropping them, and explains systemd's "Failed to
  kill control group … remains running after unit stopped" lines in the journal digest.
- **Uninstalling a server removes its account's crontab.** `userdel -r` removes the home but not
  `/var/spool/cron/crontabs/<name>`, so every uninstalled server left its monitor and update lines
  behind; cron logged them as "ORPHAN (no passwd entry)", and the file stayed owned by a uid the
  next new account was given. The crontab is now removed just before the account.
- **Adding a tool's settings file to the repository is no longer offered as a panel update.** The
  update check decides which files the panel runs from a list, and that list lived in the panel's
  own code. Naming SonarCloud's new settings file in it, as a file the panel does not run, was then
  itself a change to the panel's code, and every panel was offered that one line as an update. The
  list is now a data file, `.github/update-paths.txt`, read from the version being offered, and it
  counts as a file the panel does not run. Naming a new tool's file there is not an update any more.
  Anything the list does not name still counts as a change. A test fails the build if any file in
  the repository is left unnamed.
- **Installing a game on a minimal host no longer fails at "Downloading LinuxGSM".** The install
  fetched LinuxGSM with wget, and LinuxGSM runs curl, one step BEFORE the step that installs the
  game's dependencies, wget and curl among them. Ubuntu's minimal and cloud images have neither, so
  every game install on such a host (a remote, or the panel's own) failed there. Dependencies are
  now step 2 and LinuxGSM step 3.
- **An update keeps the panel's systemd unit current, as it does everything else the installer
  put on the host.** The unit was written once, at install, and no update touched it again, so a
  host kept whatever unit it was first given. It is now rewritten when its text differs from what
  this version installs (and only then), and an update that rolls back puts the old one back. A
  test fails the build if a fresh install ever runs a step an update does not.
- **The installer installs wget, cron and ufw when they are missing.** Ubuntu's minimal and cloud
  images leave them out, and the panel runs all three on its own host: every game install downloads
  LinuxGSM with wget, autostart and scheduled tasks are cron jobs, and the Firewall page and
  auto-blocking drive ufw. Installing ufw does not turn the firewall on. An update installs them
  too, on a host that is missing them.
- **A docs, CI or test change no longer brings back "Panel update available" on Telegram or
  Discord.** Merged on top of an update you had not installed yet, it moved the update's target
  commit, and the alert went out again for the same change. It goes out once per change the panel
  runs.
- **A file the panel runs that was moved into `tools/` or `docs/` counts as a change.** Git names
  only a rename's destination, so the move read as docs-only. The fuzz image's build files and the
  JavaScript lint config, which nothing on a panel reads, no longer count as changes.
- **Checking a lost install asks the host once, not once per poll.** When the panel restarted
  mid-install, the Game Servers page asked the host whether the install had finished every 2.5
  seconds, each time with a full `du` of the game files that can take up to 30 seconds — one open
  page stacked about five on the host. There is now one check per server at a time, and the page is
  told it is under way.
- **Retrying a failed install can no longer be overwritten by the background check.** Pressing Retry
  while the panel was still checking the earlier failed install could mark the new install "failed"
  (or "installed") while it was downloading. The check now leaves a server alone if an install
  started, or the server was removed, while it waited on the host.
- **Security tab event times are shown in your own time zone correctly.** Recent security events
  were read as local time instead of UTC, so every ban and failed login appeared shifted by your UTC
  offset.
- **"Panel update available" is sent once per update, not after every restart.**
- **Malformed numbers no longer cause server errors.** A reboot delay or auto-block threshold of
  `Infinity`/`1e400` now gets the normal "not a number" handling instead of a 500.
- **A scheduled-task change can no longer be lost or undone by another one.** Crontab changes for an
  account now run one at a time.
- **A failed crontab read no longer wipes the account's scheduled tasks.** If the crontab could not
  be read, or a temporary file could not be written (a full `/tmp`), the panel installed an empty or
  partial crontab and reported success. Now nothing is installed and the error is shown.
- **LinuxGSM config values with `$`, backticks, backslashes or quotes are saved as typed.** They
  were written unescaped into a file LinuxGSM runs as shell code: a trailing backslash broke the
  config, `$` mangled passwords, and `$(…)` ran as a command. References like `${port}` still work.
- **Broken downloads now fail instead of saving a truncated file.** Downloads that go quiet time
  out, SSH connections are always closed afterwards, and the SSH commands have a connect timeout.
- **A locked database is no longer "repaired" into yesterday's backup.** The startup self-heal
  treated any SQLite error as corruption, including "database is locked" and "unable to open
  database file", replacing a busy but healthy panel.db with the rolling backup. Only real
  corruption triggers the heal now; anything else stops startup with the error.
- **The self-heal keeps the newest writes of a corrupt database.** Its -wal and -shm used to be
  deleted (the check itself deleted them too). They are now moved aside with the corrupt file, and
  if moving aside fails nothing is restored over it.
- **`manage.py` no longer runs the database self-heal** beside the live service.
- **The updater no longer repairs a database it could not read.** A locked or unopenable panel.db
  counted as damaged; the update now aborts and leaves the data alone. The repair's saved original
  now also includes its -wal.
- **A GitHub outage no longer stalls every page that shows the game list.** The game and package
  lists are refetched outside the lock; other requests are served the copy already held.
- **The session and credential keys can no longer be read half-written** on a fresh install by a
  racing process.
- **Uninstalling removes the panel's sudo grants first,** right after the service stops, and deletes
  the `lgsmpanel-games` group.
- **A FIFO in place of the panel's `config.json` no longer hangs the installer or the uninstaller.**
- **The Tailscale login log is created fresh** (`O_EXCL|O_NOFOLLOW`, 0600) instead of being
  truncated through whatever sat at its path.
- **SECURITY.md describes the sudo grant install.sh actually writes,** including the helper's
  `Defaults!` line, its fixed interpreter and environment, and the rules for which accounts may join
  the game-account group.
- **A sign-in that can't be recorded is refused instead of going through half-registered.** If the
  per-device session row could not be written (a momentary database lock), the login went ahead with
  a cookie nothing could expire, list or revoke. The write is retried once, and if it still fails
  the person is asked to try again.
- **One missed probe no longer pages you.** A host or server is now declared down only after two
  failed checks in a row; the dashboard still shows each check as it happens.
- **A burst of alerts arrives as one message instead of dozens.** Alerts go through one bounded
  queue with a single sender, and whatever piles up is sent as one message per channel — no more
  fifty messages at once running into Telegram's rate limit.
- **Changing your password, or signing out everywhere from an older login, never leaves an untracked
  session.** If the new session record can't be written, the device is signed out and asked to sign
  in again.
- **`Infinity` in a JSON body no longer causes a server error** (bulk actions, tag sets, discovery
  import, firewall rules, the SSH port change, backup settings, and the console and terminal
  sockets).
- **Bad Garry's Mod content and config requests get a clear error** instead of a 500 or a silent
  mount.
- **Retry can't start an install into a server that is being uninstalled.**
- **Only one panel restore runs at a time.** Two concurrent restores could combine the database from
  one backup with the encryption key from another.
- **Rebooting the panel host no longer sends "server went offline" alerts.**
- **Blocking or unbanning an address on the panel host takes effect at once** in the panel's own ban
  check.
- **Clicking Update no longer risks aborting the update it started.** The progress card re-checked
  for updates every 1.5 seconds, each check fetching the same git ref the installer was fetching and
  using up GitHub's hourly limit. Checks now run one at a time, none run while an update is
  installing, and the card watches only the update log.
- **Install and bootstrap progress stop polling once their row is gone.**
- **"Still working — reload the page to check." stays put** instead of being overwritten by a slow
  poll.
- **`Infinity` or `1e400` in a request no longer causes a server error** in firewall ports, terminal
  sizes, rule numbers and several other numeric inputs.
- **Opening a second terminal on the same connection now records that the first one closed.**
- **A failed port scan while setting up a Source server's extra ports is now logged.**
- **The panel host's own Firewall card could say "permission denied" with the helper installed.**
  Its rule list was the one firewall read that followed the host row's "sudo" setting, which is a
  remote's SSH option, and on the panel's own host it also decided whether to use the helper. The
  panel creates its own host's row with that setting on and never shows it for that row, but a row
  with it off (one written into the database directly, as the test panel's was) ran `ufw status`
  as the panel's account, which ufw refuses, so the card listed no rules and no rule could be
  deleted from it, while Server Management read the same firewall fine. On the panel's own host
  that setting is no longer read: the rule list is read as root like every other firewall action,
  through the helper where it is installed. A remote still follows its own setting.
- **On a remote host, a fail2ban log just under the 8 MB read limit is counted again.** The panel
  guessed that a remote host's log had been cut short whenever it came within 64 KB of that limit,
  and treated a complete log as unread, so auto-blocking on that host held still. The remote read
  now stops at the limit itself and says when it had to, as the panel's own host already did, and
  only a log that really was cut is treated as unread. A cut log on a remote host now shows as
  unreadable on the Security card, rather than as a smaller count.
- **Storing a host's first SSH key pin no longer freezes the panel while the database is busy.**
  The pin is written by whichever part of the panel made the first contact, often a background
  worker. When another write held the database at that moment, the pin waited inside SQLite, and
  that wait stops the whole panel: the console, every page, and the other write too, which then
  could not finish. After up to 15 seconds the pin failed and the connection was refused anyway.
  Measured with a 3-second wait: a write that would have finished half a second later still froze
  the panel for all 3 seconds. The pin no longer waits for the database at all. If another write
  holds it at that moment, the key is not stored and that one connection is refused straight away,
  as it was at the end of the wait, and the next connection to the host tries again.
- **On Python 3.13 and later (Ubuntu 26.04), a closed terminal could keep its slot until the panel
  restarted.** If the terminal's output reader was still busy a second after the close, for
  instance still handing output to the browser, the close stopped partway. The session stayed on
  the panel's list of open terminals, the page was never told it had ended, and it went on counting
  against the limit of 3 terminals per user and 12 in all. The 15-minute idle close skipped it,
  because it was already marked closed. The cause was a timed wait on a thread, which under
  eventlet on Python 3.13+ raises an error that nothing caught instead of returning. The Tailscale
  transport waited the same way for a command's output. When a command exited while something it
  had started still held that output open for more than five seconds, the error could end the page
  request or background loop that ran the command. Both now wait in a way that returns on every
  Python version. Python 3.10 to 3.12 (Ubuntu 22.04 and 24.04) were not affected.
- **The daily gamedig pass could write to a host that had just been deleted.** It read the list of
  hosts once and then worked through it, a few minutes per host that needed gamedig installed, so
  a host deleted while a pass was running was still on its list and got gamedig and its weekly cron
  put back. Each host, and each game server, is now re-read from the database just before it is
  acted on, and one that is gone is skipped.
- **An older "daily restart when empty" line could restart the server with players on it.**
  Lines written before the fix for "Is anyone on?" (below) kept the old check, which restarted
  whenever the player query failed, because `jq` counts gamedig's error reply as 0 players. The
  oldest of those lines also send the query to 127.0.0.1, which a Source server does not answer,
  so for them every query fails and the server restarts every day, players or not. On the test
  host, gmodserver's line got `{"error":"Failed all 2 attempts"}` from 127.0.0.1 and would have
  restarted at the first :10 past the daily time, while the same query to the host's own address
  answered normally. The earlier heal only added the PATH to such a line. The in-place upgrade
  (run whenever a server's Scheduled Tasks are opened, and daily for every game server) now
  recognises every shape the panel has ever written for this line and rewrites it to exactly what
  turning the setting on writes today: the host's own address, the server's port and query type,
  a restart only on a counted 0, and gamedig's PATH. The line keeps its own schedule, and the
  daily restart time, which is on the separate flag line, does not move. A line the panel did not
  write is left alone; one an operator has edited is not rewritten either, and only gets the PATH
  as before. A crontab whose listing failed is still never rewritten. A game that once had no
  player query, and has one now, gets the player check.
- **The panel's update card now says when an update stopped, or held, instead of spinning.** It
  finished only when the panel restarted, and an update that ends before the panel is stopped never
  restarts it: the update source unreachable, a pinned commit the installer cannot verify, a hold.
  The `[ERROR]` was in the log, and after three minutes the card said "Still working — reload the
  page to check." Both launchers (the root-owned helper, and the wrapper a per-user install runs)
  now end the log with the installer's exit status, and the card reads it: a stop shows in red with
  the installer's own reason, a hold shows its "Not updated: held at …" line, and the buttons come
  back. It trusts that only while the panel answering is still the one that started the update, so
  a run that did restart the panel is judged as before. Each launch removes the previous run's log
  first, so its ending is never read as the new one's. The debug report's "Last update" names these
  outcomes too, where it said "unknown (in progress…)". The helper side reaches a host when its
  installer next re-stages the helper, which every update does.
- **On a shallow checkout the update decided on less history than it then acted on.** The installer
  clones `--depth 1`; the step that picks where to update to fetched only the new tip, and the step
  that resets fetched the whole history first. So an older verified pin (a late deploy) was missing
  and read as "not verified", holding the host with a false warning, and after a foxtrot push a pin
  the host already contained could not be seen to be its ancestor, so the first step chose a
  snapshot and restart that the second then undid by keeping the checkout where it was. The first
  step now unshallows the tracked branch before deciding. That adds history and nothing else — no
  change to the working tree, `HEAD`, other refs or the config — once per checkout.
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

- **Findings from a full code review (2026-10-08): security.** Every item below has a check that
  fails without its fix.
  - **"Disable public SSH" on a remote host could lock you out.** The panel decided that the host
    let SSH in over Tailscale if the word "tailscale" appeared anywhere in its firewall rules, so an
    `ALLOW OUT` rule, a `DENY IN`, or a comment was enough. It now reads the rules in the order the
    firewall applies them, on the host's real Tailscale interface, and answers "not safe" on any
    doubt, as the panel's own host already did. On the panel's own host, the rule list no longer
    drops rows whose comment has parentheses, or IPv6-only rows, so a `DENY` on the tailnet
    interface is seen.
  - **A delegated admin could point a host at another tailnet machine with "Migrate to Tailscale
    SSH".** The new address came from the host's own answer and was never checked. Migration now
    needs a superadmin, as adding a host on the panel's Tailscale identity already did, and the
    button is shown only to superadmins.
  - **The sign-in code step has a per-account limit.** Wrong codes at sign-in now count
    against the same per-account budget every other code check uses, not only the per-address one.
  - **File-browser reads as a root-capable account are refused**, as writes already were. A legacy
    server bound to the host's sudo login no longer hands its `~/.ssh` keys or shell history to
    someone who may only manage that server's files.
  - **Panel-host details stay superadmin-only on the remote-host pages.** The tailnet check, bans,
    top addresses, firewall view, SSH status, update check and Ubuntu Pro status of the panel's own
    host now refuse a delegated admin, as the rest of that host does, and the page no longer shows
    them those cards.
  - **The privileged helper deletes a home folder only for an account it removed**, and only through
    paths it has resolved without following a link the panel user could plant. When it cannot read
    the sudo policy, it no longer assumes the caller is already root.
  - **The uninstaller runs from a root-owned copy.** A root install now keeps `uninstall.sh` beside
    the recovery command in `/usr/local/lib/linuxgsm-panel/`, and the README and the script point
    root there, not at the panel's own checkout, which the panel user can edit. The end-of-install
    lockout hint no longer has root run scripts from the checkout either.
  - **The `curl … | bash` installer only uses the current folder when it is that installer's own
    tree.** Run from an old clone or any other Flask project, it used that folder as the panel's
    source, which could downgrade the panel or install another project as the service.
  - **The Add Remote form hides the SSH password as you type it**, and the browser no longer saves
    it as an ordinary form entry.
  - **The debug report's secret protection now covers the configured secrets themselves**, not
    their encrypted form.

- **A stored server name is never put into the account check's shell text (GHSA-hh39-76g3-wxcx,
  reopened).** The check the panel runs before deleting a server's account, writing its files or
  cron, or importing it asks the host about the account in one shell command, as root on a remote
  with sudo enabled. Since that check arrived it carried the name raw inside a quoted `echo`, where
  `$(…)`, backticks and a `"` still run — and a name from a database older than the name rule, a
  hand edit or a restore is not checked when it is loaded. A name that is not a plain account name
  is now refused before anything is asked; the check passes every name as a quoted argument; and an
  import checks a name before it asks the host about it, not after. Removing such a server now
  removes it from the panel without touching the host, and the message says so without repeating
  the name. Before, Remove asked the host about the name, which ran it, then said "couldn't check,
  try again", so the server could never be removed.
- **A failed firewall step during an install no longer opens SSH.** The install's last step re-reads
  the game's ports after its first start and opens any new ones, minus the ones the firewall step
  had held back (SSH, the panel's port, other servers' ports). If the firewall step itself failed,
  that held-back list was empty and the re-read opened everything LinuxGSM reported, so a config
  naming port 22 as its query port opened SSH. The re-read now works out SSH, the panel's port and
  other servers' ports for itself. When the firewall step failed it opens only the server's own
  port, and the install finishes with a warning that the firewall step failed instead of a clean
  "installed and started". The warning says to ask someone who manages the host when you cannot
  open its Firewall page, and the install's audit entry records the failed step. A port the firewall
  step could not check is no longer re-opened by the re-read when another port was held back in the
  same install.
- **An action's message never carries an internal error's text.** A LinuxGSM action whose argument
  check failed for an unexpected reason answered with that error's own text, which could name a
  path. It now says the panel could not check the action's arguments, and the error goes to the
  log.
- **A malformed stored server name can no longer mute that server's offline alerts.** The check
  for a nightly LinuxGSM update in progress built a process pattern from the stored names, and a
  name like `x|.*` matched every maintenance process on the host. Such names are not probed now.
- **The browser's Socket.IO client is 4.8.4, past two HIGH advisories in the parser it bundles.**
  The panel vendored socket.io-client 4.7.5, whose bundle carries socket.io-parser 4.2.4: affected
  by GHSA-677m-j7p3-52f9 (fixed in 4.2.6) and GHSA-2m8v-j782-fhvr (fixed in 4.2.7), both of which
  name the client too. Every page loads it. The decoder runs in the operator's browser on packets
  from the panel's own server, so the realistic worst case was a browser tab driven out of memory by
  a malicious or intercepted server. The new file is byte-identical to the one in the npm tarball,
  whose integrity and registry signature were checked; its bundle carries both parser fixes, and it
  speaks the same protocols (Engine.IO 4, Socket.IO 5) as the panel's python-socketio 5.17. Pages
  now load it, and every other vendored file, by a URL that changes with the file's contents: the
  fixed URL they used is cached for a week, so a browser would have kept the old client for up to a
  week after the update. It takes the new one on its next page load.
- **Scanners can see the vendored browser libraries now.** No scanner read `static/vendor/`: there
  was no manifest for the dependency graph, and neither Dependabot alerts nor osv-scanner can look
  inside a minified bundle, which is how the client above sat on a vulnerable parser with every check
  green. `static/vendor/package.json` and `package-lock.json` now record each library and what its
  bundle carries, the dependency audit reads the lockfile on every pull request, push and week, and
  a unit gate ties every file to the manifest by sha256 and by the version its own banner states. A
  library carried inside another's bundle is recorded at the version the bundle holds (Chart.js
  carries @kurkle/color 0.3.2, which npm alone recorded as 0.3.4). A change to the two manifests
  alone is not offered to panels as an update: nothing a panel runs reads them.
- **gitleaks catches a Telegram bot token wherever it is written.** Its built-in rule needs a
  `telegr…` name right before the value, so it missed the panel's own `config.json` shape, a bare
  `token = "…"`, a function argument, the Bot API URL and prose; main's full-history scan carried a
  real-shaped value and reported nothing. A keyword-free rule now finds all of them. Its one
  allowlisted value is the historical synthetic fixture, matched exactly. The fixture-shape check in
  the unit suite also caught too little: a token ending in `-` and the Bot API URL form passed it.
- **A pull request can no longer allowlist its own leaked secret.** The secret scan read the pull
  request's own gitleaks config and `.gitleaksignore`, and honoured `gitleaks:allow` on any line, so
  one diff could add a secret and the exemption that hid it, and pass. A pull request is now scanned
  with the base branch's config and ignore file, its own ignore file set aside and `gitleaks:allow`
  ignored, then with its own config too; an exemption has to reach `main` on its own first.
- **SECURITY.md says how to check an install set up before the setup-token fix**
  (GHSA-cwmq-pvg9-jjfx): list the superadmins, confirm which tailnet the host is in and what it
  publishes, and read the sign-ins. Finishing setup did not undo either takeover, so an install that
  was already set up is not thereby in the clear.
- **CodeQL sees Socket.IO input and the commands the panel runs.** CodeQL models python-socketio but
  not Flask-SocketIO, so what a browser emits to the console and terminal sockets was not untrusted
  input to any query; and the command text the panel sends to a host was not a command-injection
  sink: neither SSH transport is modelled (paramiko's `exec_command`, or the `ssh` argument list
  for Tailscale), and on the panel's own host CodeQL takes only the first element of
  `["/bin/bash", "-c", cmd]` as the command. A model pack in
  `.github/codeql/extensions` adds both. The sinks are the text as it enters `run_command`,
  `shell_as_game_user`, `read_as_game_user` and `game_user_cmd`, which covers every transport, plus
  the own-host shell. A value passed through `shlex.quote` counts as safe inside that text; that
  barrier applies to every command-injection sink, so the few places that quote a whole script for
  a second shell (`sudo bash -c '…'`), where a quote hides what is inside it, are listed and a unit
  check fails on a new one. The `py/partial-ssrf` exclusion's justification, which said one
  function was the panel's only outbound request, now lists all six outbound-HTTP call sites, and a
  unit check fails on a seventh until it is reviewed.
- **CI's Semgrep job runs on a PyJWT with no known advisory.** Every PyJWT 2.13 release has
  published advisories (the worst critical, GHSA-ffc3-869f-jxw9), and semgrep 1.178.0 pinned
  `~=2.13.0`, so no lockfile that honoured semgrep's own pin was safe and Dependabot could not open a
  fix. semgrep 1.179.0 accepts PyJWT 2.15, so Semgrep's one hash lockfile now carries PyJWT 2.15.1
  and installs with pip's dependency check on; the interim second lockfile for PyJWT alone is gone.
  This touches CI only: the panel does not use PyJWT.
- **Group forms reject ids that cannot be real ids.** Anyone who could manage groups could make the
  add and edit pages fail with a server error by submitting an extremely long number as an id; such
  values, and non-ASCII digits that were being read as ids, are now ignored.
- **Moving SSH to another port no longer deletes the firewall rule your current SSH depends on.** If
  the move failed, the panel always removed the allow rule for the new port — and when that port was
  one SSH already used (a bind-address change on port 22, or moving to a port sshd already listened
  on) that was the rule the panel's own connection came in on, while the message said "your existing
  SSH still works". Opening the port also turned the bootstrap's rate-limited SSH rule into a plain
  allow. The panel now opens only a port no rule already lets in, removes only a rule it added, and
  refuses a port a firewall rule blocks before changing anything.
- **Deleting a firewall rule by number can no longer hit a different rule.** Rule numbers shift
  whenever the auto-block adds a deny at the top, and that could happen between the safety check and
  the delete. Firewall changes on a host now run one at a time, and the delete holds its place from
  the check to the delete.
- **A password-login host with no usable stored password no longer signs in with the panel's own SSH
  key.** The connection now fails with a clear message, as the Test button already did. A key-login
  host uses only the key it names: no SSH agent, and no other keys from `~/.ssh`.
- **The file browser can no longer delete LinuxGSM's files through a symlinked folder.** The
  protected-path check is now made on the host against the real location, in the same command as the
  delete.
- **A backup code now works exactly once, even when two sign-ins race.** The code is now spent with
  a conditional update that only succeeds if nobody changed the list in between.
- **Only real game accounts can join the panel's game-account group.** The panel's sudoers line lets
  it become any member of `lgsmpanel-games`, but the helper enrolled any account that couldn't
  already reach root: a colleague's login, `postgres`, `www-data`, `nobody`. An account now needs an
  ordinary uid (login.defs' range), only ordinary groups, not to be the panel's own account, and a
  LinuxGSM install or content tree in its own home. Accounts the panel creates are enrolled as
  they're made. The root-equivalence check now also reads doas and polkit, and refuses microk8s,
  lpadmin, kmem, incus, src, systemd-journal, syslog and ssl-cert.
- **The privileged helper no longer takes its interpreter or environment from the caller.** It runs
  `/usr/bin/python3 -I`, it and every tool it starts get a fixed minimal environment, and the
  installer adds `Defaults!<helper> env_reset, secure_path=…` to the grant.
- **Root no longer reads files in the panel's directory through symlinks.** Without a `.git`, the
  installer printed `VERSION` into the update log as root, so a `VERSION` symlink handed any
  root-only file (`/etc/shadow`, SSH keys) to the panel. The installer and uninstaller now read the
  version and `config.json` as the panel's own user, refusing links and FIFOs.
- **Hard links can no longer steer root's chown or chmod** on hosts with `fs.protected_hardlinks=0`.
- **The self-update installer no longer runs inside the panel's checkout.**
- **Remote GMod content and mount operations run as the game account, not root.** The remote chmod,
  removal and `mount.cfg` read followed symlinks the game account controlled; a linked `mount.cfg`
  printed the remote host's `/etc/shadow` into the panel.
- **An update from a local checkout unpacks as the panel's user,** so directory links in the panel's
  tree can't redirect root's writes.
- **Update snapshots and rollbacks no longer run as root inside the panel's own files.** An update
  created `data/.backups/<stamp>` and wrote the snapshot archives there as root, read the panel's
  directory as root to build them, and unpacked them as root on rollback — so a symlink the panel
  placed could redirect root's writes, and a hard link could copy a root-only file into an archive
  the panel can read. These steps now run as the panel directory's owner. Rollback works as before.
- **A stolen "remember me" cookie no longer works from someone else's machine.** With "strong"
  session protection, dropping the session cookie and keeping the remember cookie gave a fresh
  session with no binding, which was then bound to whoever sent it. Every per-device login is now
  checked against the address and browser its session record noted at sign-in (IPv6 by its /64, as
  before).
- **Old pre-upgrade login cookies now die with a password change or "sign out everywhere".** A
  cookie carrying only the account number was accepted whatever the account's epoch; it is now
  accepted only by an account whose sessions have never been revoked, and the live console's
  re-check follows the same rule.
- **A request body sent in chunks is read before the request is authorized, like any other.**
- **"Monitor" now needs the restart permission.** LinuxGSM's `monitor` restarts a crashed or
  unresponsive server, but it required only view-console, so a view-only user could restart a
  server. The maintenance menu now hides it from them too.
- **An authenticator code can no longer sign in twice by racing itself.** The spent-code record is
  updated in one conditional database write, so two sign-ins (or two API-token mints) with the same
  code cannot both pass.
- **Chat bots now check who sent a command, not just which chat it came from.** Any member of the
  configured Telegram group, or anyone who could post in the Discord channel, could stop and restart
  servers, self-update the panel with `/update`, read the live console and `/say` in-game, and the
  audit log named them only by a username they could change. Each bot now has "Users who may run
  commands" on the Notifications page (numeric Telegram/Discord user IDs, up to 50). Anyone in the
  chat can still use `/status`, `/servers`, `/hosts`, `/connect` and `/help`; everything else,
  including `/console`, `/say` and `/players`, runs only for a listed user. **With the list empty
  nobody can run those** — the bot replies with the sender's own ID and where to add it. Audit rows
  record the sender's numeric ID, and a panel update or `/say` from chat now writes an audit row at
  all.
- **The Discord bot no longer risks getting its token reset by reconnecting forever.** It
  reconnected 15 seconds after every session end, including when Discord had refused the token
  (4004) or the Message Content intent (4014) — about 5,400 attempts a day against Discord's limit
  of 1,000. A fatal close code now stops the bot, says why in the log and on the Notifications page,
  and it stays stopped until the token or "Accept commands" changes (retrying every 6 hours). Other
  disconnects back off up to 15 minutes.
- **A stolen remember cookie from before per-device sessions no longer works from another machine.**
  An older login with no per-device record has nothing on the server to check its client against;
  when its remember cookie came back without a session cookie, "strong" protection tied the fresh
  session to whoever sent it. It is now refused, and the person signs in once more to get a
  per-device login. Sessions that are already bound keep working, and "basic" and off are unchanged.
- **Discovery import no longer adopts an account that is root on its host.** Import accepted any
  account a scan found except one named "root", so a delegated admin could import the host's own SSH
  login (in the sudo group) and then, through the file manager or cron, write its `.bashrc`,
  `authorized_keys` or crontab — root on that host. Import now asks the host, and refuses the login
  account, uid 0, members of sudo/wheel/admin/root/docker/lxd/disk, and accounts with sudo rules. If
  the host can't be asked, nothing is imported. On the panel's own host, an account the helper
  refuses to enrol is no longer imported anyway.
- **Uninstall never deletes a host's administrator account.** Uninstalling a row for a root-capable
  account ran `userdel -r -f` on it; now the panel row is removed and the account is left alone,
  with a warning. If the host can't answer the check, nothing is changed.
- **Garry's Mod shared content needs access to the host.** An admin granted a single GMod server
  could remove content every GMod server on the host mounts, or start large downloads onto the
  host's disk.
- **Deleting a tag needs access to every server that carries it.** Tags are install-wide and drive
  alert routing.
- **Current-password and 2FA-code checks are throttled per account and audited.** Password change,
  turning 2FA on or off, minting an API token and deleting a host share the login throttle's budget,
  and every failed attempt is in the audit log.
- **Tailscale peer check is superadmin-only.** It pinged arbitrary addresses from the panel host for
  any Manage Remotes holder.
- **The panel host's firewall can't be changed through the game-port routes by a delegated admin.**
  "Open game port" and "Sync ports" follow the same superadmin-only rule as the panel host's other
  firewall writes.
- **An update whose checks could not be read is no longer installed.** When the panel couldn't read
  GitHub (offline, a private repository, or an origin address it didn't recognise), it treated the
  newest commit as verified and offered it. It now offers nothing and the update card says why.
  Origins using GitHub's SSH-over-443 address (`ssh://git@ssh.github.com:443/…`) are now recognised.
- **An update isn't offered until its code-scanning check has run.** A code commit must now carry
  all of CI, CodeQL and the alerts check; the alerts check now reports on the commit it actually
  judged, not whatever main's newest commit was, and waits for both code-scanning uploads.
- **Semgrep findings now block an update.** They were only printed to a job summary; they now go to
  code scanning like Bandit's.
- **Auto-deploy waits for the security checks, not only CI,** and refuses a commit that failed any
  of them.
- **Switching the panel back to main no longer skips the update checks.** Branch switching always
  installed the newest commit on the chosen branch — for main, possibly one whose checks were still
  running or had failed. Switching to main now installs its newest version that passed its checks,
  and says why when there isn't one. Switching to any other branch still installs that branch's
  newest commit, and the panel now says clearly that this is unverified code for testing.
- **File and cron writes are refused for a game account that can become root on its host.** Import
  now refuses such accounts, but a server row imported earlier (for example for the host's own sudo
  login) could still have its `~/.bashrc`, `authorized_keys` or crontab written from the file
  manager. Every file-manager and cron write now asks the host first; the answer is cached for a
  minute, and if the host can't answer, nothing is written.
- **Only a superadmin can edit or delete the panel host's own entry.** A delegated admin whose group
  included the panel host could rename it, change its SSH user, or delete it, removing every game
  server on that machine from the panel.
- **A firewall rule is deleted by number only while it is still the rule that was checked.** The
  check and the delete now happen in one root step on the host (new helper verb
  `ufw-delete-num-if`), so a `ufw` command typed on the host in between can no longer make a
  different rule — possibly the one keeping SSH open — be deleted.
- **Telegram polling no longer follows redirects.** The bot's message and name lookups followed a
  redirect off api.telegram.org with the bot token in the URL; they now refuse redirects like the
  send path, and failures no longer log the URL.
- **Enabling 2FA spends its code the same way sign-in does.** Two enrolment submissions with the
  same code could both succeed, each showing its own backup codes while only one set was saved.
- **A delegated admin whose hosts include the panel's own no longer gets that host's controls.** The
  firewall, SSH mode and port, OS updates, reboot, fail2ban (block, unban, auto-block, log) and
  Ubuntu Pro actions under a host's Manage page checked only *which* hosts the account could reach,
  never whether one of them was the panel host. The same actions on the panel host's own page are
  superadmin-only, because that machine's firewall and sshd guard the panel itself. They now are
  on every route: a non-superadmin gets a 403 on the panel host, and remote hosts are unchanged.
- **You can no longer reset your own password or 2FA from the Users page.** That form asks for
  neither your current password nor a code, so a borrowed session could hand itself a new password,
  switch 2FA off and sign the real owner out everywhere. Use your Account page, which asks first.
  Resetting *another* account's password or 2FA is unchanged.
- **The login throttle can no longer be raced or reset.** A burst of simultaneous sign-in attempts
  all got through before any of them was counted, and one successful sign-in from an address wiped
  the failures before it — so anyone with an account of their own could keep guessing at another.
  Attempts now count the moment they start (a success gives its place back), and earlier failures
  stay counted after a success.
- **The self-update no longer prunes old snapshots by splitting their names.** It ran as root over
  a folder the panel's account owns, and a folder name containing a space made root delete whatever
  path followed it. It now removes only folders named the way the updater names them.
- **Editing an old Telegram message no longer runs its command again.** An edit arrives as a new
  update, so fixing a typo in last week's `/stop` stopped the server a second time.
- **The first-run wizard now needs a one-time setup token, so a stranger can no longer take a fresh
  install.** Until the first admin existed, anyone who reached the port could open the wizard and
  make themselves the superadmin, which is root on the panel's host. A default install opens that
  port itself. The operator's own browser was then sent to a login it had no account for. The same
  caller could also join the host to *their* tailnet with Tailscale SSH on, through the wizard's
  Tailscale endpoints (a cookie-less request with a Bearer header skipped CSRF, so one request was
  enough). They could also make the panel test SSH connections to hosts of their choosing.
  The installer now ends by printing the wizard's link with a token in it (`/setup?token=…`), read from
  `data/setup_token` (0600, the panel's account). `manage.py setup-token`, or
  `sudo linuxgsm-panel-recover setup-token`, prints it again. Until an admin exists, the wizard and
  every `/api/setup/*` endpoint answer only a browser that has shown the token. Anyone else gets a
  page asking for it. The token is deleted once the admin exists.
  The Tailscale endpoints refuse everyone until then. Two "create admin" requests that raced (the
  password hash yielded between the check and the insert) can no longer both make a superadmin. The
  wizard now follows its own step, so a form cannot skip ahead to a later one.
  Its "add a host" step runs the Hosts page's own checks before connecting. That step also accepted
  `auth_method=local`, which made a remote host read as the panel's own host.
  An install that is already set up is unaffected: the token is never needed there.
- **The wizard's last page no longer calls a panel that is still public "Private tailnet".** The Serve
  step stores a loopback bind, but a new bind applies only from the next start. Until then the panel
  kept answering on its public address, and the page said only your devices could reach it. That page
  was also never shown, because finishing redirected to the login page. It is shown now. It says
  where the panel still answers and offers **Restart now**; nothing restarts on its own, since that
  would cut off an operator who is not on the tailnet.
- **The setup wizard's own steps are on the audit log.** Creating the first superadmin, the bind
  address and port it saves, a host added at its last step, finishing setup and **Restart now**
  wrote no row, so the one flow that runs before anyone can sign in left no record of what it did.
  Each now writes one, by the account signed in to drive the wizard (a superadmin may, once the
  first one exists), or by "setup wizard" when no one is signed in. **Restart now** writes its row
  before the restart is scheduled, since the restart can stop the panel before a later write
  lands, and a restart that could not be scheduled writes a second row saying why. The test that
  should have caught this matched functions by name, and counted these as audited because other
  functions with the same names log. It now follows each call to the function it really reaches.
  The Tailscale Serve the wizard sets up on the way out is audited too, and is stored as set up
  only when Serve accepted it: its result was ignored, so a Serve that failed left the firewall
  page treating the tailnet as the way in, and the public web port's rule unprotected.
- **Tailscale migrate and finalize refuse the panel's own host**, like the other Tailscale actions on
  the Hosts page. They rewrite a remote's record and firewall; migrate also deletes its public
  22/tcp rule.
- **`trust_proxy` believes `X-Forwarded-For` only from the proxy.** It used to read the header from
  any peer, so a panel also reachable directly — or any local account on its host, a game-server
  user included — could send a fresh address with every login attempt (unlimited guessing past the
  throttle) and have fail2ban and the auto-block ban an address it chose. The socket peer must now
  be in the new `trusted_proxies` (default `127.0.0.1` and `::1`), and on loopback the connection
  must belong to root, the panel's own account or one in `trusted_proxy_users` (default `www-data`,
  `nginx`, `http`, `caddy`, `cloudflared`). **If your proxy is on another machine or in a Docker
  bridge network, add its address to `trusted_proxies` in `data/config.json`**; until you do, every
  client is keyed as the proxy (one shared login throttle), and the panel log says
  `ignoring X-Forwarded-For from <address>`. The startup output now warns when `trust_proxy` is on
  and the panel listens beyond loopback.
- **An IPv6 zone id no longer passes as an address.** Python's address parser accepts a zone after
  `%` on any IPv6 address and keeps whatever text follows it, spaces, `$(…)` and newlines included:
  `fe80::1%x panel login failed from 203.0.113.9` parses. The panel used that parse as its safety
  check, so the text got through wherever an address was expected. A delegated admin with
  **Manage remotes** could put lines of their own into a remote host's root-owned sshd or
  `ssh.socket` drop-in through the SSH port's bind address, which is more than that permission
  grants. The same admin could pass the text to `fail2ban-client` as root through **Unban**, on any
  host in their groups (the panel's own included). fail2ban's source shows it logging such a value
  verbatim to `/var/log/fail2ban.log`, and the panel counts that log's lines toward the auto-block.
  Behind a proxy that passes the client's own `X-Forwarded-For` through (nginx setting only
  `X-Real-IP`, say), or from a local account trusted as a proxy, a login client could write free
  text into `data/auth.log`, the audit trail, the session list and admin alerts. fail2ban then
  banned an address the text named, or every address of a hostname, instead of the client. When
  the address's last 64 bits were zero, each new zone was also a new login-throttle bucket, which
  meant unlimited password guessing. Through Tailscale Serve or Funnel, or the README's nginx block,
  a client cannot choose that value. The first-run wizard also accepted a zoned bind address that
  the next start could not bind. Every address, network, ban, whitelist, firewall and bind check now
  refuses a zone and passes on the parsed address rather than the typed text, and the root helper
  checks this for itself. A block, unban, allow-from or whitelist-removal row is audited under its
  address or network, or as `(not an IP address)`; an allow-from row names the source as the rule
  was sent, and a port rule's row names its port and protocol as they were checked, or
  `(not a port)` / `(not a protocol)`.
  A client address that a proxy reports with a zone is read with the zone dropped: Apache and Go's
  reverse proxy write a link-local client into `X-Forwarded-For` that way, and that client is
  keyed, logged and audited as its address alone. Refusing the value would have keyed it as the
  proxy, so fail2ban could have banned the proxy and everyone behind it. That parse is what closes
  the throttle hole: every zone on one address is that address's bucket. The throttle also drops a
  zone itself, as a second guard in case another path ever hands it one. A link-local client that
  the kernel reports with its interface attached is keyed by its address too. A whitelist entry
  stored with a zone before the whitelist refused them still exempts its address from the
  auto-block and the ban gate, as it did before (fail2ban's `ignoreip` leaves it out, as it always
  has); remove it and add the address without the `%zone` to have fail2ban skip it too. Audit IPs
  that an older version stored with a zone lose it at the first start after the update, whatever
  their age and whether or not IP ageing is on: an address keeps the address alone, a row that
  version had already reduced keeps its `/64` without the zone's text, and one that is no address
  at all is blanked.
- **A `"*"` in `socketio_cors_origins` is ignored.** It let a page on another port of the panel's
  address, or on a sibling tailnet node — both same-site, so the session cookie is sent — open the
  console and the terminal as whoever visited it. If you had set it, set `site_domain` or list the
  exact origin (e.g. `https://panel.example.com`); the panel logs
  `socketio_cors_origins "*" is ignored` once.
- **Usernames and group names cannot carry control or format characters.** A delegate with
  user or group management could store ESC sequences that moved the cursor, forged rows or wrote the
  clipboard in the recovery CLI (`manage.py`, run as root); group names had no format check at all.
  The CLI now shows any such character as a visible escape, so names stored earlier are safe too.
- **The chat bots' `!update` can no longer hold every self-update at "still being verified".** Each
  one forced a fresh check against GitHub's anonymous API (60 requests an hour), and a spent limit
  reads as "pending", which blocked the web UI's update too. A status under a minute old is reused,
  a second `!update` while one is running is answered instead of queued, and chat-triggered checks
  are limited to ten an hour across both bots.
- **The post-restart "update complete" message goes only to a channel that is still authorised.**
  It went to the channel that asked even after the bot was switched off or moved.
- **The terminal's input queue is counted, not re-summed on every keystroke**, and dropped input is
  reported once a second rather than once per keystroke.
- **A delegated group admin can edit or delete only a group wholly within their reach.** The
  permission list was filtered to what the editor holds, but nothing asked whose group it was:
  an admin scoped to one host could give another tenant's viewers `use_terminal` and
  `send_command` on a host the admin cannot reach, strip another tenant's admins, or, through
  the default "Everyone" group, give every account a shell in one POST. Deleting a group skipped
  its custom commands, so a group made for a superadmin-authored command could be deleted by
  anyone who held its permissions. Editing and deleting now need all three of: the group's
  permissions, hosts, servers and custom commands within the editor's reach; every member but
  themselves and superadmins someone the editor could administer on Users (the rule `/users`
  already applied); and no live invite naming the group alongside one outside their reach.
  Otherwise the request is refused and audited. The Groups page shows those groups without Edit
  or Delete, with their members, permissions and access still listed. **What changes:** on an
  install with more than one tenant, a delegated admin can no longer edit "Everyone", or their
  own group if someone else in it reaches more than they do. That is the intended rule. A
  superadmin's page and edits are unchanged.
- **An invite no longer outlives its minter, or its expiry, while its form is in flight.** The
  checks that the minter is still active and still holds what the invite grants ran before the
  form was read. A request carrying an `Authorization: Bearer` header and no cookie skips the
  CSRF check that otherwise reads the body early, so a client could send the headers, hold the
  body back while the minter was demoted and deactivated, and still get the account, superadmin
  included. An invite that expired while the body was held was redeemed the same way. Redemption
  now claims the invite only if it is unexpired, and re-reads the minter after the claim, while it
  holds the database's write lock, before creating the account. The password is hashed before
  that lock is taken, so other writers wait less.
- **A signed-in request is authorized once its body has arrived, not before.** Every check that a
  token, an account or a permission is still good ran before the request's body was read, and the
  body is read only when the route first asks for it. So a client could send the headers, hold the
  body back while its API token was revoked, its account deactivated or its permission removed, and
  the action still ran once the body arrived. That was open for every API call made with an
  `Authorization: Bearer` token and for every in-page request with a JSON body from a signed-in
  browser: the CSRF check, which reads a form's body early, skips the first and does not read the
  second's JSON. (A browser's form posts were already safe: that check reads them first.) The panel
  now reads the whole body of a signed-in request before any check, then looks up who is asking
  again, so the checks see the token, the account and its permissions as they are when the body
  lands. An upload still streams to a temporary file rather than into memory, and a request that is
  not signed in is still refused without its body being read.
- **A delegated log viewer sees the rows about their own servers and hosts, chosen by id, not by
  name.** `/logs` matched a row to a viewer's servers and hosts by the row's target name, and
  names are not unique. The same game installed on two hosts gets the same name by default, so a
  viewer granted one read the other's console commands with their arguments (`rcon_password ...`).
  Anyone who could rename their own server or host could rename it onto another tenant's server,
  onto `database`, a branch name or an IP, and read those rows too: another tenant's firewall
  changes, the panel host's own administration, and another account's password or 2FA reset. Each
  audit row now records the game server or host it is about, and a delegated viewer is shown their
  own rows plus the rows about servers and hosts they can reach. Nothing is matched by name. When
  a server or host is deleted its rows let go of the id, so a new server that SQLite gives the
  same id to does not inherit another tenant's history. **On upgrade**, existing rows get their id
  once, only where the action is about a server or host and exactly one server or host has that
  name. The rest stay visible to the person who did the action and to superadmins. Password and
  2FA resets are now treated as account rows.
- **A host's SSH key is pinned from the first connection, whichever part of the panel makes it.**
  A first contact from a background check (the host monitor, a pool worker) had no app context,
  so its pin was never saved. Every later connection was "first contact" again, and a
  man-in-the-middle at any of them was trusted. The pin is now stored from any thread, and a
  connection whose pin cannot be stored is closed rather than used. Adding a host, the setup
  wizard's host step and the **Test** button now pin the key they logged in with. A pin that
  can no longer be decrypted refuses the Test login instead of reading as "no pin" and sending the
  password to whatever answered.
- **Changing a host's SSH port checks that sshd is what answers on the new port.** The move was
  kept once *something* listened there, so a game account that bound the port first took the
  panel's next SSH connections to that host. Each listener on the new port must now be root's sshd
  (`ssh.service`/`sshd.service`, or `ssh.socket` under socket activation); anything else reverts
  the move. fail2ban's sshd jail now covers the new port through
  `/etc/fail2ban/jail.d/zz-panel-sshd.local`. The old edit touched only `jail.local`, which a stock
  install does not have, so the jail kept watching the old port. It is updated only after the move
  is confirmed, and the result says "fail2ban updated" only when the jail is running on the new
  port. Two port changes for the same host at once are refused (409). **Re-run `install.sh` to
  update the privileged helper**; an older helper keeps the move and says it could not confirm
  sshd.
- **The firewall touches only the rules a game server owns.** Uninstalling a server deleted every
  rule on its port by spec, an operator's and another server's included, and "Open all ports"
  replaced whatever rule held a port: another server's, an operator's DENY or LIMIT. Rules are now
  removed by number, only ALLOW rules tagged with that server's name (and untagged ones only where
  no other server's block holds the port), and a rule the panel did not make is never replaced.
  No port is opened or stored on SSH, the panel's own web port, or another server's reserved
  block. "Open all ports" (`/api/server/<id>/sync-ports`) now needs **Manage Remotes** for that
  host, not only Install Server. An install holds back a port something else started listening on
  while its files downloaded, and says so. A port scan that cannot be read no longer counts as
  "every port is free".
  - Uninstall no longer leaves a rule open when the firewall changes during the cleanup. A new
    auto-block rule shifted the rule numbers, the delete was rightly refused, and the rule was then
    given up and the uninstall reported a clean result. The panel now reads the firewall again and
    retries up to three times, and the uninstall message names any rule still open. It also no
    longer deletes a DENY, a LIMIT, a rule for one address, or any rule on the SSH or panel port
    just because it carries the server's name. Those rules stay, and the message lists them.
    "Open all ports" no longer says a port is open when a DENY for TCP or UDP still blocks it. It
    adds an allow only for the protocol no rule covers yet, and names the rule it left each
    protocol to (for example `27015/tcp DENY`).
  - Uninstall also names a rule with no name on it that is still on the server's own ports. The
    rate limit from the Firewall page is one: `ufw limit` writes no comment, so the limit on a game
    port carries no server's name. It was neither removed nor mentioned, so the port stayed open,
    rate limited, after an uninstall that reported a clean result. The rule is still left in place,
    but the message now names it (for example `Left in place on its port: 27015/tcp LIMIT`) and the
    result is a warning. A port another server on the host still uses is left out. The server's
    ports include every port its own rules were on, so a Query port outside the game's usual range
    (Rust's 28017) is covered, and a rule on one interface or to one address is named too. The
    message says only the port and what the rule does, not the address or interface it names:
    whoever may uninstall the server is not always someone who may read the host's firewall.
- **Root `apt` installs only the packages LinuxGSM lists for the game.** A game's install step
  passed whatever package names LinuxGSM's output reported missing to a root `apt-get install`.
  A name is now kept only when LinuxGSM's dependency list for that game and distro names it, the
  panel's common set does, or it is `steamcmd`. Anything else is refused, named in the result and
  logged. Package names must also end in a letter or digit, because `apt-get install foo-`
  *removes* `foo`. A game account on an older LinuxGSM release asks for that release's packages,
  which can differ from the panel's copy (v26.1.0 wants `openjdk-21-jre` and `dotnet-runtime-8.0`
  where the newest release has `-25-` and `10.0`), and a newer release can list a package the
  panel's weekly copy has not caught up with. A name the panel's copy refuses is now looked up
  again in LinuxGSM's own repository: in the list at the release the account's script runs, then
  in the current list, fetched at most once an hour. The account's own copy of the list is never
  used, because the account can edit it; it can pick only which published release is read.
- **A refused SSH connection is now closed.** When a connection to a remote failed its host-key
  check, its login or any other step, the panel left that connection's thread and socket open. A
  real SSH server hangs up after its login grace time, but a man-in-the-middle can keep them open
  for good, and the host monitor added one per host on every pass. The "Test connection" button
  left one open the same way whenever a test failed. Both now close the connection on every failure.
- **A new server or host no longer inherits a deleted one's state when SQLite reuses its id.**
  SQLite hands a deleted row's id to the next row created, and the panel keyed per-server and
  per-host state by that id: console backlog, install and action jobs, cached OS-update lists and
  alert counts. A new server could replay the previous one's console, and its first update alert
  could be swallowed. That state is now dropped when a row is deleted, and again when a row is
  created. A host bootstrap whose id was taken mid-run no longer writes onto the host that took it.
  If the taking host's first SSH contact is stalled, the stale worker no longer pins its own key
  onto it or aims its remaining root steps there.
- **A deleted host, game server, user or group's id is no longer given to the next one, and work
  still running for a deleted row no longer lands on the row that took its id.** The hosts, game
  servers, users, groups, custom commands, tags, global bans, invites and login sessions tables now
  use SQLite's AUTOINCREMENT, so a new row never gets an id a deleted one had. A Global Bans page
  left open while its newest ban was removed and another added no longer removes the new ban, and
  lifts it on every server, when Remove is pressed. An existing install's tables are rebuilt once,
  at the first start after this update, with every row and id kept. A table that cannot be copied
  without losing something is left as it was and logged, and the next start tries again. The next id
  also starts above any id something still points at, such as an audit row or a tag left behind by a
  deleted server. Work that holds a row through a long step also checks it is still the same row
  before writing or acting, for any table not rebuilt yet. An install whose host was deleted mid-run
  now stops at its next step instead of running it on the host that took the id, and no longer marks
  that host's new server failed. Starts, stops and restarts, an update's mods restart, bulk actions,
  the command list cache, a cross-server ban, a GMod content job, and the on-demand, full, scheduled
  and queued backups no longer write their result to, audit it under, or act on the server that took
  the id. The monitor, the player count poll, the metric history, the dashboard's status poll and
  the daily OS-update check no longer apply what they found for a deleted row to its successor, and
  an open terminal on a deleted host is closed rather than kept by the host that took its id. The
  hourly auto-block no longer adds or removes firewall rules on a host that took the id of a deleted
  host that had it on.
- **Unbounded reads and rows are capped.**
  - The fail2ban log read stops at 8 MB, and a tally cut short is shown as unread rather than as
    a smaller count.
  - The console backlog keeps each line under 2048 characters and the whole backlog under 256 KB,
    without cutting a colour sequence in half. The live console is unchanged.
  - Every audit column is capped at its declared size, and the detail at 8 KB. SQLite does not
    enforce column sizes, so a megabyte console command went into `panel.db` whole.
  - The Ubuntu Pro service endpoint refuses an unknown service or action before running or
    auditing anything.
- **Changing the panel's own port audits what really happened.** The row said success even when
  the firewall or fail2ban step failed or the old port's rule stayed open. A failed restart now
  gets its own row, and the failure reply includes the firewall outcome.
- **A game server's account name can no longer carry a command** (GHSA-hh39-76g3-wxcx, reported by
  kta1kri). Twenty-five places built `sudo -u <account> bash -c '…'` from a server's account
  (`short_name`) and LinuxGSM script name with neither quoting nor a check — the dashboard's own
  polls among them, with nobody watching. The model checks those names only when they are
  **assigned**, never when a row is read back, so a database from before that check, a hand edit
  of `panel.db`, or a restored backup could hold `short_name="x; curl …|sh; #"`, and the next poll
  ran it as the panel's account on its own host, or as the SSH login on a remote. Every such
  command is now built in one place, which refuses a name that is not one plain account word
  (`root` and sudo's `#0`-style uids included) before anything is sent, and quotes what it accepts.
  A refused name reads everywhere as "could not run", never as an empty result; the commands sent
  for every real name are byte-for-byte what they were. The script name that the monitor, update,
  restart-when-empty and restart-check cron lines carry is checked too. A panel backup is now
  refused, naming the row, when its database holds such a name or a port stored as text — checked
  before the safety copy or anything else is touched — and a row that is already in the database
  is named in the log once, instead of every action on it failing with no reason given. Unit gates
  fail the build on any `sudo -u` built outside that one place.

  A review of that fix found four more ways in, all closed here:
  - **The console read the script name unchecked.** The live console's log path is built from the
    server's game type, and the console reads checked only the account, so a game type of
    `mc; <cmd>; #` ran `<cmd>` every two seconds while anyone had that console open, and when its
    history was loaded. Those reads now check the script name too, and the unit gate that looks for
    a script name dropped on the way into a command now follows it through the server's own
    attributes and the variables built from them, not only through a variable called `selfname`.
  - **The backup check could be sidestepped by spelling.** SQLite does not care about the case of
    table and column names, and the check looked them up exactly: a backup whose database spelled
    the table `GAME_SERVER` or the column `SHORT_NAME` was not checked at all, and the panel then read
    it as usual. The check now reads the database as SQLite serves it. It also refuses a backup whose
    database could change a value after the check, or hide one from it: a trigger, a view, a column
    computed from other columns, an index that disagrees with its table (SQLite's own integrity check
    must pass), or a server or host table missing one of the checked columns. No version of the
    panel has written any of these, so no genuine backup is refused for them.
  - **A port stored as text reached the hourly restart line.** The restart-when-empty cron line was
    the one place that put a server's port into a command without converting it to a number first;
    it now refuses one that is not a number, as does the daily pass that rewrites old lines. A port
    stored as text is also named in the log when the row is read.
  - **A host's SSH login could become an ssh option.** For a host connected over Tailscale, the
    panel runs the system `ssh` client with `<login>@<host>` — for every command, the web terminal
    and file and backup downloads — and a stored login of `-oProxyCommand=<cmd>` ran `<cmd>` on the
    panel's host.
    The login and address are now checked before either is handed to ssh, and they come after `--`,
    where ssh stops reading options. The add/edit host form no longer accepts an address that begins
    with a dash.
- **pip itself is hash-locked.** The installer upgraded the panel's venv with
  `pip install --upgrade pip`: whatever PyPI served that day, unchecked, the first thing the venv
  ran on every install and on every update that reinstalled dependencies. pip now comes from
  `requirements-bootstrap.txt`, a pip-compile lockfile (compiled for Python 3.10, like
  `requirements.txt`) installed with `--require-hashes --only-binary :all:`, so a pip wheel that is
  not byte-for-byte the locked one is refused. Dependabot keeps it current with the rest of the
  Python dependencies, CI installs it on every Python in the test matrix and pip-audit reads it, and
  a change to it alone now counts as a dependency change on update. Checked on fresh 22.04, 24.04
  and 26.04 venvs (their own pip 22.0.2, 24.0 and 25.1.1): each installs it, and refuses it with
  one hash altered. An update pinned to an older commit, which has no such file, keeps the pip the
  venv already has instead of fetching an unpinned one; 22.04's own pip installs the panel's
  requirements unaided. A test now reads every pip call in the project's shell scripts and fails
  on one that is neither hash-checked nor listed with its reason (the one listed is
  `requirements.txt`'s: an older pinned commit's copy may carry no hashes).
- **The Codacy token is no longer readable by a workflow on any branch.** `CODACY_PROJECT_TOKEN`
  was a repository secret, and the coverage job that used it ran the code under test. The upload
  is now its own workflow, `codacy-coverage.yml`, which runs after CI from main's copy of the file,
  in an environment named `codacy`, and uploads the report CI left as an artifact for the commit
  CI tested, so pull requests keep their Codacy coverage checks. The report is treated as untrusted:
  one declaring a DTD or an entity is refused (the reporter's XML parser resolves entities a file
  declares, which could read its environment, token included). Scoping the token takes three
  repository settings a workflow cannot make, listed in that file's header: the environment's
  deployment rule (branch `main` only), the token as an environment secret, and the repository
  secret deleted. `.github/SECURITY.md` says what the token can do; it is more than an upload key.
  The upload's check lands on main's newest commit even for a pull request's run (GitHub files
  every `workflow_run` job there), so the panel's update check ignores it, as it ignores the
  deploy: one pull request's failed upload no longer stops panels being offered main.
- **The code-scanning gate judges main only for a run that was exactly main's.** Like the deploy
  before it, `codeql-alerts.yml` compared the run's branch with `main` the way GitHub compares
  strings, ignoring case and by short name, so a branch `Main` or a tag `main` pushed with its own
  "CodeQL" workflow was judged, and reported, as main. The name is now compared exactly, in bash,
  and any other run judges nothing. Read-only either way.
- **A compromised panel can no longer send root back to an old commit, or choose the branch root
  installs from.** On a root install, the panel could reset its own checkout to an old commit of
  main and ask for a self-update. Root accepted it (every commit main was ever at is on its
  first-parent line) and installed that commit's installer root-owned. One from before e26a644
  read the helper out of the panel-owned `.git`, so a planted replace ref became the helper on the
  next update. Root now keeps a source floor in `/usr/local/lib/linuxgsm-panel/.source-floor`: the
  newest commit of main it has staged from, never lowered, with e26a644 when there is no file yet.
  It refuses any commit below the floor, and any commit whose installer does not enforce the floor
  itself. The auto-deploy refuses the same commits, so re-running an old CI run cannot ship one.
  Separately, the branch the panel tracks (`PANEL_BRANCH`) decided which branch root verified
  against, so any pushed branch could supply the helper. When the panel starts an update, root now
  takes its pieces from main only. On another branch the code still switches, and the helper,
  `db_maintenance.py`, the installer, the recovery command and gamedig's lockfile and install
  script are left as they were, with a message in the update log. An operator testing a branch as root (`cd / && sudo
  PANEL_BRANCH=<branch> bash /usr/local/lib/linuxgsm-panel/install.sh`, or from a root shell) still
  gets that branch's pieces. The helper marks the
  panel's runs in a way the panel cannot remove, and `.github/SECURITY.md` explains how. Installs
  run as a normal user are unchanged.
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
  honours that rule now; it had been resetting a current checkout back to the older commit. It is
  now "never backwards, and never sideways": a checkout on main moves only to a pin that contains
  it. After a foxtrot push a verified pin can be on main's line and neither contain the checkout nor
  be contained by it (the other branch's commit the merge was made on), and the update moved the
  host to it, dropping the commit it was on; now it holds, and says why. The panel's update card,
  which could offer that commit while the merge was still in CI, no longer offers a commit that
  does not contain the running one, so it never shows an update that would only hold, and does
  not ask GitHub's anonymous API about such a commit either (60 requests an hour). And a
  pinned commit the installer cannot verify is no longer replaced by main's tip, which nothing had
  verified: a checkout on main stays where it is, with a warning, and any other stops the update
  with an error that names the pin, having changed nothing. A hold ends with "Not updated: held at
  …, because …", never "Already up to date".

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
- **gamedig is installed from a hash-locked lockfile, and root no longer fetches it every week.**
  It was `npm install -g --ignore-scripts gamedig@5`, at install and from a weekly root cron on
  every host: whatever gamedig 5.x and whatever versions of its ~50 floating dependencies the
  registry served that Sunday, unreviewed, then run by every game account. `tools/gamedig` now holds
  a `package.json` pinning gamedig 5.3.3 and a `package-lock.json` naming all 61 packages, each with
  a sha512, and `install-gamedig.sh` installs that tree with `npm ci`, which rejects any tarball that
  does not match. It builds into a staging directory, runs the result once, and only then switches
  over, so a failed download leaves the working gamedig in place, and it links both
  `/usr/local/bin/gamedig` and `/usr/bin/gamedig` to it, since existing restart-when-empty cron
  lines look in `/usr/bin`. The first run removes npm's old global gamedig once the new one runs
  and both links point at it, so `gamedig` answers throughout the switch. `npm ci` gets ten
  minutes, and on an update it runs after the health check has passed, so a registry that stalls
  cannot hold the verdict or the rollback. A commit that changes only these files is an update
  to what the host runs, not "docs, tests or tooling", on the update card.
  Everything lives in `/usr/local/lib/linuxgsm-panel/gamedig` on every host. `install.sh` places
  the three files there root-owned from root's own source (never the panel-owned checkout), after
  the helper and after the new code is fetched; it used to install gamedig before fetching. Remote
  hosts get them through a new `gamedig-install` verb, which replaces `npm-install-global`, from
  the add-host bootstrap and the daily pass, which on a remote writes the files before the cron
  that runs them. The helper refuses that verb on the panel host. The weekly cron, still
  `/etc/cron.d/lgsm-node-tools`, now re-runs the script and fetches nothing while the tree is in
  place. Updates arrive as Dependabot pull requests (weekly, a seven-day cooldown, gamedig majors
  ignored), and the Dependency Review check now runs on them. Tests hold every lockfile entry to a
  sha512 and a registry.npmjs.org source, and allow no `npm install` in any shell script. This also
  clears Scorecard's last Pinned-Dependencies finding for npm, which counts only `npm ci` as pinned.
  `uninstall.sh` removes the two links, but only where they point into the panel's directory.
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
- **The weekly root cron no longer upgrades npm**, and no longer installs from the registry at all:
  it re-runs `install-gamedig.sh`, which installs gamedig from its hash-locked lockfile (see the
  gamedig entry above). On the panel host, NodeSource's repository is set up with its signing key
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
