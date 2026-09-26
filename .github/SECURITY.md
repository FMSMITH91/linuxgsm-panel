# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull
requests, or discussions.** A public report tips off attackers before a fix is out.

Instead, report privately through GitHub's built-in private vulnerability reporting
(already enabled on this repo):

1. Open the [**Security** tab](https://github.com/FMSMITH91/linuxgsm-panel/security).
2. Click **"Report a vulnerability"**.
3. Describe the issue.

The report stays private between you and the maintainer until a fix is ready. You can
expect an initial response within a few days.

When you can, please include:

- the version you're running (see the `VERSION` file, or the panel's footer),
- a description of the issue and its impact,
- steps to reproduce (or a proof of concept), and
- any suggested fix.

Coordinated disclosure is appreciated: please give a reasonable window to release a fix
before any public write-up.

## Supported versions

The panel is a rolling release — fixes land on `main` and are picked up by re-running the
installer, which updates in place (with a health check and automatic rollback). Security
fixes are applied to the **latest** version only, so please update before reporting.

| Version | Supported |
| --- | --- |
| Latest `main` / newest release | ✅ |
| Anything older | ❌ — please update first |

## Deploying securely

The panel manages game-server hosts over SSH, so treat it as sensitive infrastructure:

- Keep it behind **Tailscale** (or a reverse proxy with a real certificate) rather than
  exposing the panel port to the public internet. See [docs/https.md](../docs/https.md).
- Keep **two-factor authentication** enabled on admin accounts.
- Keep the install **up to date** — re-running the installer applies the latest fixes.

## Known trust-model limitation: the panel has root on its own host

When the installer is run as **root** it creates a dedicated service user and grants it
passwordless sudo. **What that grant permits now depends on whether the root-owned helper
pieces are installed**, and the installer tells you which one it wrote:

| condition | grant |
|---|---|
| helper + root-owned `db_maintenance.py` + root-owned installer all present | `ALL=(root) NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper` |
| any of them missing | `ALL=(ALL) NOPASSWD:ALL` — unchanged, and the panel falls back to the pre-helper path |

For most of this project's life it was unconditionally the second row, and this document said
so in these words: *there is no privilege boundary between "the web panel is compromised" and
"the host is root-owned."* On an install with the narrow grant that is no longer true. On one
without it, it still is — **re-run `install.sh` as root to get the narrow grant**.

Why it could not simply be edited into place earlier: the panel escalated local work as
`sudo bash -c '<command>'`, and a sudoers rule permitting `/bin/bash` is exactly as powerful as
`NOPASSWD:ALL`. The same is true of `systemd-run` and of the `tailscale` binary — each runs
whatever you hand it. A "scoped" list containing any of them reads as narrower while granting
identical power. Every one of those was a call site; every one is a verb now, and none appears
in the narrow grant.

**The helper.** `tools/panel-helper` is that script. It is
installed root-owned at `/usr/local/lib/linuxgsm-panel/panel-helper`, deliberately outside
the panel's own checkout — the checkout belongs to the panel user and `git pull` rewrites it
on every self-update, so a helper living there would be panel-writable by design. It takes a
verb and already-separated arguments, re-validates every argument against its own table, and
execs a fixed argument vector. There is no shell in it, and the only program it can run is
one it names: `bash` does not resolve.

Converted so far: **`ufw`, `fail2ban-client`, `systemctl`, `apt`/`dpkg`, the log reads
(`journalctl` / `tail`), cron and user management, the sshd port change, the deferred reboot,
Ubuntu Pro, the host controls, the GMod shared-content box, the fail2ban activity report, the
detached OS update, Tailscale's join, the panel's own restore/self-update, the VPS hardening
steps, running a LinuxGSM action as the game user, enrolling a game account in the group the
grant names, installing a game's dependencies, reading the pending-restart flags, freeing
Steam's per-account crash-dump slots, configuring NodeSource's repository on a remote with its
signing key pinned and installing gamedig on a remote from its hash-locked lockfile** — 102 verbs. (`tests/unit_test.py` asserts
this number against `privileged.verbs()`, so it cannot drift from the table again.)

**A correction to the numbers previously reported here.** Earlier revisions of this section
said the panel had "113" privileged call sites and tracked them down to 42. That counted only
`run_command(..., sudo=True)`. There is a second escalation route — a helper named `_sudo_sh`
that builds `sudo bash -c '<pipeline>'` itself and then passes `sudo=False`, so it is invisible
to a search for `sudo=True`. It had 18 call sites the whole time. The real starting figure was
**131 root-escalating sites, not 113**.

Both routes are now counted by a test that ratchets: the ceilings may be lowered as call sites
convert and never raised, so a new escalation written as a shell string fails the build instead
of going unnoticed. Current state:

| route | sites remaining |
|---|---|
| `run_command(..., sudo=True)` | 2 |
| `_sudo_sh(...)` | **0 — the route is gone** |
| **root total** | **2** (from 131) |

`_sudo_sh()` built `sudo bash -c '<pipeline>'` itself and passed `sudo=False`, which is why a
search for `sudo=True` never saw it and why its 18 call sites went uncounted for half this work.
It has no callers left and the function itself has been deleted.

**"…so that route cannot come back by accident" was wrong, and it had already come back.** The
ratchets count three things — calls to a function *named* `_sudo_sh`, the `sudo=True` keyword, and
an argv list beginning with `"sudo"` — and the route is none of those; it is a *shape*, and the
shape is one f-string. `_core._rewrite_crontab` renders `crontab -u <user>` into exactly such a
`sudo bash -c '<pipeline>'` and passes `sudo=False`, reachable from five cron routes. The account
name went in **unquoted**, into a pipeline that runs as root, held only by the model's `@validates`
hook — which fires on assignment and never on a row loaded from the database. It is validated and
quoted at that site now, and a test drives a hostile name through it.

**And it no longer runs as root at all.** `crontab -l` and `crontab <file>` run *as* an account
operate on that account's own crontab — exactly what all five cron routes want — so the `-u` and
the root shell were never needed. It is `sudo -u <user> bash -c '<pipeline>'` now: one fewer root
escalation, and the only reason cron works on a narrow-grant host, where `sudo bash` is refused and
every autostart toggle, scheduled restart and backup schedule failed silently. Verified on a test
host: `sudo -n bash -c 'crontab -u gmodserver -l'` answered "sudo: a password is required", while
the new form read the crontab, added a line and removed it again, leaving the real entries intact.
The pipeline SHAPE remains, because `crontab -l | filter > tmp; crontab tmp` genuinely is a
pipeline. Read the table above as "no `_sudo_sh` **function**", not as "no hand-built escalation".

**And the largest group was not a hand-built escalation at all — it was a DEFAULT.**
`run_command(server, cmd)` takes `sudo=None`, which resolved to `server.sudo_enabled`; the panel's
own host row is created with that True. So every caller that did not pass `sudo=` sent its command
to the panel's own machine as `sudo bash -c '<cmd>'` — about twenty of which need no privilege
whatsoever: the dashboard's port scan, disk and load, uptime, `/etc/os-release`, `id`,
`tailscale status`. Measured on a test host, as the panel user, with the panel's own code:

```
run_command(local, "echo ok")      ->  rc=1  sudo: a password is required
run_command(local, "ss -H -lntu")  ->  rc=1  sudo: a password is required
```

Under the narrow grant that is the dashboard, the host cards and the console failing; under the
wide grant it was `/proc` being read as root for no reason. Locally, an escalation must now be
asked for explicitly — the privileged path is `run_privileged()` and the helper, which is the whole
point of the verb table. `sudo_enabled` still means what it says for a remote host, which is the
only place it was ever a useful default.

Two reads genuinely needed more than the panel user, and were converted FIRST, because flipping
the default without them would have broken the console on every host with the wide grant, where it
works today: the console log reads now run **as the game account** (its home is 0750, so this is
less privilege than before, not more), and the cron restart flags became the `restart-flags` verb.
That one had never worked unprivileged anyway — `ls -1d /home/*/.restart-pending` stats a literal
final component, so every candidate was EACCES, the glob matched nothing, `|| true` discarded the
rc, and the caller received a confident empty set. It returns `None` for "could not look" now.

**A third hand-built escalation, and the one that actually broke the hardened install.**
`run_as_game_user` rendered `sudo -u <user> bash -c '<inner>'` and passed `sudo=False` — the same
shape as `_rewrite_crontab`, invisible to all three ratchets for the same reason. Unlike the cron
one it was not merely unnarrowed, it was **broken**: the narrow grant permits the helper and
nothing else, so on a host where install.sh reported `sudo grant: narrow` the panel could not run
a single LinuxGSM command. Measured on a test host with that grant — `sudo -n -u gmodserver id`
answered "sudo: a password is required"; a restart issued through the API left the pid unchanged
and logged `restart_server success=False`; `/api/server/<id>` reported `"unknown"`. The dashboard
showed those servers **online** throughout, because `/api/servers` port-scans instead of asking
LinuxGSM. Status, start/stop/restart, console, mods and LinuxGSM backups were all dead, silently.

It is the `lgsm-command` verb now: a managed non-uid-0 account, a script name re-resolved inside
that user's home after the credential drop, one action from a fixed list, and prompt answers as
bare tokens fed down a pipe. No shell on the local path at all. Remote hosts keep the old form,
which is correct — their sudoers is the operator's to arrange.

**What that fix does NOT cover, stated plainly.** `run_as_game_user` was one of about 45 sites
that build `sudo -u <game user> bash -c '<shell>'` and pass `sudo=False`: the file browser,
the GMod content mounts, the cron readers, the install flows and the disk-usage probes are all
the same shape, and all of them fail under the narrow grant exactly as server control did. The
count in the table below is of `sudo=True` sites and has never included any of these. Converting
them is not finished; until it is, a host with the narrow grant has working server control and a
file browser that does not work.

**The dependency installer is a verb now, and it was not merely unnarrowed — it was broken.**
`install_game_dependencies` ran one `sudo bash -c '<pipeline>'`, which the narrow grant refuses, and
it is **step 3 of the Install Server flow**, not a bootstrap step. Its call site swallowed the
failure in a bare `except` that logs at debug level, and the pipeline ended in `echo deps-done`, so
the function returned success however badly it had gone: a refused step surfaced as neither an
error nor a log line, and the install went on to fail later looking like a bad download. It is a
sequence of verbs now — `dpkg-add-arch`, `apt-add-repo` (universe **and** multiverse),
`apt-update`, `steamcmd-install`, then `apt-install-minimal` in chunks with a per-package retry —
and it reports the batch's real result, which the caller now surfaces.

**Two `sudo=True` sites remain.** One is the Tailscale installer on a remote host, named below:
it runs Tailscale's downloaded install script as root, and no verb can narrow that. The other is
the remote form of the LinuxGSM discovery scan — a fixed script whose only inputs are file names on
that host; on the panel's own host the same scan is the `lgsm-discover` verb. The bootstrap's
Node.js step was a third until it became the `nodesource-setup` verb (below). Earlier revisions of
this paragraph counted four and misdescribed two of them: the per-server metrics probe no longer
escalates at all, and the dependency installer they named as the fourth is the verb sequence
described above.

(Those counts exclude six calls that ARE the verb layer's own transport — the `run_command` /
`_run_local` / `_run` at the end of `run_privileged`, `write_root_file`, `write_content_cron` and
`_run_verb`, which pass
a command built from the verb table rather than composed at a call site. Earlier revisions counted
them, overstating the remaining work. A test pins the exclusion at exactly those six, so it cannot
quietly widen and make the number flattering.)

Separately there are ~46 `sudo -u <gameuser>` sites. Those run as the game user rather than
root, so they are a smaller problem — but they still depend on the same unrestricted grant,
and they are not yet counted in the conversion.

Two of those verb families are worth describing, because the narrowing is in the argument
types rather than in the command names:

- The systemd verbs take a unit from an **exhaustive list** (`ssh`, `sshd`, `fail2ban`,
  `ssh.socket`, `whoopsie`, `cups`, `modemmanager`, `unattended-upgrades`). Those are the only services the panel
  ever touches, so a unit-name *pattern* would only buy the ability to control units nobody asked it
  to. The panel's OWN unit is deliberately not in that list — it is reachable through exactly one
  verb, `panel-restart`, which takes a bounded delay and nothing else.
- The write verb takes a **destination name** and the content on **stdin**. Locally the helper
  does the write itself in Python — the content is never an argument, and the path is looked up,
  so `write-file /etc/shadow` fails on the *name*, not on a filter.
- **The sshd port change** is the one sequence whose failure mode is "you can no longer reach the
  machine", so every step of it is a verb: snapshot the drop-in, write the new one, run `sshd -t`
  against the whole config, restart, confirm the port is actually listening, and restore the
  snapshot on any failure. A test asserts the drop-in may be written *only* while that entire
  sequence exists, and the rollback is exercised against a sandboxed filesystem rather than by
  inspecting the commands: a host that had no drop-in ends with none, and a host that had one gets
  it back byte for byte.
- **The GMod shared-content box** shares nothing until access is granted: `serverfiles` is created
  private (`0700`) and the group bits are added by the grant verb, where the shell form created it
  group-readable from the moment it existed. It builds every path from a validated user name plus a
  validated game or script identifier. Three of its verbs end in `rm -rf` running as root, so the caller
  passes *names* and the helper assembles the paths — `content_path()` re-checks the assembled
  result, and is tested directly rather than only through the verbs, because the verbs' own
  validators would otherwise reject every probe before it got that far.
- **The detached OS-update job** was `setsid bash -c '<seven statements>' &` — truncate, header,
  `export`, `apt-get update`, `full-upgrade` with four `-o` flags, `autoremove`, and a sentinel
  carrying the exit code. It took no caller input at all, which is what lets it be a zero-argument
  verb rather than a command the panel composes.
- **Tailscale's join** took the auth key, the advertised routes and the tags straight from the
  request and shell-quoted them into a root command. They are validated arguments now: routes are
  *parsed* as networks, each tag must be `tag:name`, and the auth key is charset-checked and never
  echoed back — not even in a rejection, since the value is a secret. Nor is it ever on a command
  line, and neither is the Ubuntu Pro token: `/proc/<pid>/cmdline` is world-readable, so a game
  user could read either while the command ran. Both travel on stdin — through the helper into the
  tool's own stdin on the panel host, and into a root-only temp file the tool is pointed at on a
  remote. The interactive login flow's poll log also moved from `/tmp` to `/run`: in `/tmp` any
  local user could pre-create the file the root poll then reads.
- **The sshd hardening** set four directives with `sed -i 's/^#\?Key.*/Key value/'` in a joined
  root shell. Both halves are closed sets now: the panel may set exactly those four directives, to
  exactly the values it hardens them to. `PermitRootLogin yes` is individually well-formed and
  still refused, which is a property a per-argument check cannot express.
- **The fail2ban top-IPs report** was a five-stage `zcat | awk | grep | awk | sort | head` running
  as root, with the cutoff date and the row limit interpolated into it. The verb does the read half
  only — a fixed log glob, gzip handled in Python — and the tallying is Python. Both halves are
  asserted against real plain and gzipped logs rather than by comparing command strings.
- **The deferred reboot** was `( sleep 2 ; reboot ) &` — a subshell, a background job and a
  redirect. The helper double-forks instead: the grandchild detaches, waits, and execs the reboot
  binary. It returns immediately, which is the whole reason the subshell existed.
- **The file browser's downloads** are the one place a caller-chosen *path* crosses the boundary —
  everywhere else a path is assembled from a validated identifier. It could not be an identifier
  here: these files are named by mod authors, map packers and Windows tooling, so a charset filter
  would refuse real files the browser is already listing. So the argument is checked for SHAPE
  (non-empty, relative, no `..` component, no NUL or newline, bounded length) and the containment
  question is answered where it can be answered honestly. The helper looks the home directory up
  from the **passwd entry**, never from the caller; then it forks, drops supplementary groups, gid
  and uid to the **game user**, and only then resolves the path with `realpath` and opens it. Both
  halves of that order matter: a check before the drop is a check against a path nobody will open,
  and a read as *root* would turn a download button into "hand me any file on the box" — a
  privilege increase out of a change meant to reduce privilege. The panel passes the canonical
  relative path rather than the string it received, and refuses the home directory itself. The
  folder download is Python's `tarfile` writing to the pipe, not the `tar` binary: an archiver that
  takes a path and reads whatever it finds is a general file-reader under another name, and the
  helper resolves only the tools its verbs name. Symlinks are stored as links, never followed.
  Over **SSH** the path is not in the command at all: a download there is parsed twice — once
  assembling the local `ssh` argv, again by the remote shell — and two-level quoting is where this
  class of bug lives, so the remote command is FIXED TEXT and the relative path arrives on stdin as
  data. A hostile filename and a benign one produce byte-identical commands, which is what the test
  asserts; the containment check rides in that fixed text and judges the resolved path on the host.
- The log verbs take a **source name**, never a path or a unit: `log-tail auth`, not
  `tail /var/log/auth.log`. The table turns the name into the path, so reading `/etc/shadow`
  through the helper is not something a filter rejects — it is not expressible.
- `apt-install` is the one verb taking a variable-length list. Every package name is
  charset-checked individually, and the list has a floor and a ceiling — so a name cannot be
  an option (`--reinstall`), and the list cannot be made arbitrarily long. dpkg's conflict
  answers (`--force-confdef`, `--force-confold`) are fixed in the helper rather than passed
  in, so an unattended upgrade can never be talked into clobbering a config file you edited.

The two remote installer steps below are also **unreachable on the panel's own host**: the routes
that run them (VPS bootstrap, Tailscale install, Tailscale join) refuse the local host outright. The
remotes page had always hidden them for it; the routes had not, so a direct POST could aim a full
VPS preparation — including a reboot — at the machine the panel runs on.

**One operation cannot be narrowed, and is named rather than left unremarked.** Installing
Tailscale on a remote host pipes Tailscale's install script into a root shell. That IS the
operation: a verb could pin the URL, but only by giving the helper the ability to execute a
downloaded script — exactly the capability its tool allowlist exists to deny. Wrapping it would
move the risk, not reduce it. If that trade is not one you want, that step is the thing to change,
not the helper.

**The VPS bootstrap's Node.js step was the second such operation, and this section was wrong to
call it impossible to narrow.** It piped NodeSource's setup script (`setup_lts.x`) into a root
shell, so whoever could serve that one URL ran code as root on every remote being prepared.
`install.sh` had already shown the way on the panel host: what the script does is small and
fixed, so it can be done directly, and the one thing it fetches — NodeSource's signing key — can
be checked. The bootstrap now does the same through the `nodesource-setup` verb: it downloads only
the key, trusts it only if the file holds exactly **one** primary key and that key has the pinned
fingerprint (the one `install.sh` pins; a unit test holds the two copies equal), writes the deb822
source and the apt pin itself, and executes nothing it downloaded. apt then verifies every package
against that key. A remote that already has Node.js 18+ keeps it and never touches NodeSource. The
helper refuses this verb: it exists for remote hosts, and `install.sh` configures NodeSource on the
panel's own.

**gamedig, the player-query tool, is installed from a hash-locked lockfile, not from whatever the
registry serves.** It was `npm install -g --ignore-scripts gamedig@5`, run once at install and
again by a weekly root cron on every host: root fetched whatever 5.x release and whatever versions
of its ~50 floating dependencies were current that Sunday, with nobody reviewing them, and every
game account then ran that code, hourly from cron and on every player poll. `--ignore-scripts`
stopped install hooks, not code in the package itself. Now `tools/gamedig/package-lock.json` names
every package with a sha512, and `tools/gamedig/install-gamedig.sh` installs it with `npm ci`, which
refuses a tarball that does not match. The lockfile changes only through Dependabot pull requests,
reviewed like any other change and held back seven days after a release, and CI checks that every
entry has a sha512 and a registry.npmjs.org source. The script builds the new tree beside the old
one, runs it, and only then switches `/usr/local/bin/gamedig` and `/usr/bin/gamedig` to it, so a
failed install leaves the working gamedig in place. The weekly cron now re-runs that script and
fetches nothing while the tree is in place. It is a repair job, not an updater. On the panel host
the lockfile and script are root-owned pieces like the helper: `install.sh` stages them from
root's own source, never from the checkout the panel user can write, and the helper refuses the
`gamedig-install` verb. A remote receives them from the panel through that verb, which is no new
trust, since the panel already runs `sudo bash -c` there.

**Every one of those is converted, and the grant has narrowed.** On an install where the three
root-owned pieces are present, `/etc/sudoers.d/linuxgsm-panel` contains two lines:

```
<panel-user> ALL=(root)              NOPASSWD: /usr/local/lib/linuxgsm-panel/panel-helper
<panel-user> ALL=(%lgsmpanel-games)  NOPASSWD: ALL
```

**Root is reachable only by running the helper.** In particular **not** `/bin/bash`, `/bin/sh`,
`systemd-run`, the `tailscale` binary, or `sudo -u root` — each of those runs whatever argv you
hand it, so permitting any one of them would be `NOPASSWD:ALL` wearing a disguise. Each was a call
site once; each is a verb now.

**The second line is the game accounts, and it is a real grant — stated rather than buried.** The
panel drives those accounts directly at about 45 sites: the file browser reads and writes files as
them, the GMod content mounts, the cron writers, the install flows. For one release the grant was
the first line alone, and every one of those silently failed on exactly the install this document
recommends; `lgsm-command` converted server control, and the rest are the same shape. So the right
to *become a game account* is granted, and bounded by a group instead:

* the Runas target is `%lgsmpanel-games`, never `ALL` and never a named user, so `sudo -u root`
  stays refused — verified on a test host, along with a non-member account also being refused;
* membership is controlled by install.sh and by the `gameuser-group` verb, which takes the account
  as its only argument and holds the group name as a literal — a caller that could name the group
  could name one that root is in;
* install.sh only enrols a home with a LinuxGSM instance (`lgsm/config-lgsm`) or a Steam content
  tree (`serverfiles`). A person's account has neither, and must never be enrolled: the group is
  the right for the panel to act as that account;
* **and no account that can already escalate is ever enrolled, by either route.** This is the
  check the whole split rests on: the grant says the panel may *become* a member, so a member who
  can run `sudo` makes it `NOPASSWD:ALL` with one extra hop — `sudo -u them bash -c 'sudo -i'`.
  It is also not an exotic case. Running LinuxGSM under your own sudo-capable account is an
  ordinary setup, it is what LinuxGSM's own documentation shows, and the panel's discovery scan
  exists to import exactly those installs — so such an account is a *likely* candidate for
  enrolment, not an unlikely one. install.sh refuses one in `sudo`/`admin`/`wheel`/`root` or with
  any `sudo -l -U` privileges and says so; the `gameuser-group` verb refuses the same, reading the
  group database and the sudoers files itself, and treats anything it cannot parse as "can
  escalate". A false refusal costs one account the panel cannot drive, and is reported; a false
  accept costs root.

What this does NOT give the panel is root. A game account cannot write `/etc`, cannot install
packages, cannot read another account's home, and cannot edit the helper or the sudoers file.

Three conditions bound that claim, and all are enforced rather than asserted:

* **The grant only narrows when all three root-owned pieces landed** — the helper, the
  root-owned `db_maintenance.py`, and the root-owned installer. A host running new code that
  has not had `install.sh` re-run as root keeps the wide grant, because it still falls back to
  `sudo bash -c '<verb rendered as text>'` and narrowing under that would break every
  privileged action rather than secure anything. The installer prints which grant it wrote.

* **Root no longer executes anything out of the panel's checkout — and no longer *installs* from
  it either.** `PANEL_DIR` is owned by the service user and rewritten by `git pull` on every
  self-update, so a boundary that let root run files from there would have been decorative. The
  offline DB repair and the self-update run root-owned copies placed only by `install.sh`, never
  by a verb. The CI auto-deploy (`deploy.yml`) follows the same rule on a root install. It used to
  refresh `${PANEL_DIR}/install.sh` with `git checkout` as the service user and run that with
  `sudo bash`. It now ships the verified commit's `install.sh` from the runner over SSH and runs
  that copy from a directory root created.

  *Which* commit is proved on the runner, not assumed from the trigger. The job's `if` checks the
  branch by its short name, and GitHub compares strings ignoring case, so any ref whose short name
  matches main case-insensitively passes it: a pushed tag `main`, a branch `Main`, a tag `MAIN`.
  So before it joins the tailnet, the job requires the run's branch name to be exactly `main`,
  fetches main's history from `refs/heads/main`, confirms `refs/remotes/origin/main` exists under
  exactly that name, and requires the commit to be on its first-parent line. That line holds the
  commits main's tip has been at and each commit of a multi-commit push or rebase merge, but not an
  intermediate commit of a pull request merged with a merge commit, which is an ancestor of main
  and was never its tip. One exception: a push that fast-forwards main onto a branch that had main
  merged into it (a "foxtrot" merge) moves the commits main was at before onto that merge's second
  parent, and a re-run deploy of one of them is then refused. It also refuses a commit older than
  root's source floor (below) — e26a644, the first installer that staged from root's own clone —
  since re-running an old CI run deploys that commit, and its installer runs as root. Only then
  does it read `install.sh` out of that commit, and it refuses a commit with none or an empty one,
  or one whose installer does not enforce that floor. On the host, `install.sh`
  checks the pin again against its own fetch; a pin it cannot verify is never replaced by main's
  unverified tip — the host stays where it is, or the update stops with an error. The job logs in
  to Tailscale with OIDC workload identity, not a stored secret: Tailscale's credential accepts
  only a GitHub-signed token whose subject is this repository's `production` environment, and that
  environment admits only the branch `main`. The OAuth client secret it replaced was a repository
  secret, readable by a workflow run on any branch or tag.

  The second half of that sentence was missing, and it mattered: `install_root_tools` *copied*
  those root-owned pieces **out of the working tree**, and the integrity argument was that
  `fetch_code` ran `git reset --hard` first. That is not a guarantee. `git update-index
  --skip-worktree <path>` exempts a path from `reset --hard`, so attacker content — or a deletion —
  survives it; a smudge filter in `.git/info/attributes` plus a `filter.*.smudge` in `.git/config`
  rewrites the file *during* checkout. Both live in `.git/`, which is untracked and panel-owned,
  and `_gitc` runs git **as the checkout owner**, so git honours them. `check_origin_trusted`
  compares the remote URL and sees neither. The deletion variant was the sharper one: a missing
  `tools/panel-helper` zeroed `HELPER_OK`, and `write_sudoers_grant` then replaced the narrow rule
  with `NOPASSWD:ALL` — the panel user could remove its own sudo restriction by deleting a file it
  owned.

  The first fix staged the pieces with `git cat-file blob HEAD:<path>`, which consults neither the
  working tree nor the index nor any filter. It still read the panel-owned **object store**, and
  git trusts that too. A replace ref (`git replace <committed-blob> <other-blob>`) or a loose object
  written under the committed blob's name makes `cat-file` return other bytes while `HEAD` still
  names the real upstream commit. With no `.git` at all, the tree was copied as-is, and the panel
  user can delete its own `.git`.

  All of these are now closed. Run as root against a checkout the panel user has any hand in,
  `stage_root_source` reads from **root's own clone** of the repository
  (`/usr/local/lib/linuxgsm-panel/.source.git`). Root's git fetches it with no user or system
  git config and no inherited `GIT_*` environment. The panel's `HEAD` is only a request: it is
  honoured once root's clone shows that commit on the tracked upstream branch's first-parent line
  (a commit reachable only through a merge's second parent does not count). A checkout at a
  commit upstream does not have, or with no `.git`, gets no refresh, and the installer says so. A
  checkout that is still entirely root's (the fresh install, before the chown) is read directly.
  So is the operator's own source tree when `sudo bash install.sh` is run from a clone or an
  unpacked tarball other than the checkout — but only while the installer running is that tree's
  own `install.sh` (root is already executing it), and only when the tree, every directory above
  it and every entry down to the file are beyond the panel user's reach, with no symlink followed.
  The recovery command follows the same sources, and as root it is never linked into the checkout:
  when no copy can be staged it keeps a root-owned one already in place, or links nothing.
  The output is staged into `HELPER_DIR`, which is root-owned 0755, so the panel user has no window
  to swap the staged copy. And the grant asks `root_tools_present`, i.e. whether the helper root
  will execute actually exists and is root-owned. A failure to *refresh* can no longer widen a
  grant that is already narrow.

  Two things still let a compromised panel choose that commit, and both are closed.

  *An old commit.* Every commit main was ever at is on its first-parent line, and the panel moves
  its own `HEAD`. It could reset its checkout to an old commit and call `panel-self-update`, and
  root installed that commit's installer root-owned. One from before e26a644 read the helper out
  of the panel-owned `.git`, so a planted replace ref then became the helper root installs. Root
  now keeps a **source floor**, `/usr/local/lib/linuxgsm-panel/.source-floor` (root-owned, 0644,
  in the root-owned directory): the newest commit of main it has staged its pieces from. It
  refuses any commit the floor is not an ancestor of, raises the floor to each commit of main it
  stages from, and never lowers it. A fresh install records the commit its own checkout is at,
  when root's clone shows that commit on main. With no floor file yet, the floor is e26a644. That
  alone would still admit a commit between e26a644 and the floor's arrival, whose installer
  ignores the floor and, once root-owned, would accept anything again. So root also stages only
  from a commit whose `install.sh` carries the floor's own line (`ROOT_SRC_FLOOR_FILE=…`, which
  that file says never to change), and the deploy ships only such an installer. A floor file that
  is not one commit id stops root staging until it is removed. Removing it (as root) resets the
  floor to e26a644 and is the way to put root's pieces back to an older version on purpose.

  *Another branch.* The panel names the branch it tracks (`PANEL_BRANCH`), and root verified the
  panel's `HEAD` against that branch, so a compromised panel plus any branch pushed to the
  repository chose the helper. Root now asks who started the run. When it was the panel, root
  verifies against main only, and on any other branch it withholds its pieces and says so, as it
  does for an untrusted origin. The code still switches branch; the helper, `db_maintenance.py`,
  the installer, the recovery command and gamedig's lockfile and install script stay as they
  were. When an operator runs
  `cd / && sudo PANEL_BRANCH=<branch> bash /usr/local/lib/linuxgsm-panel/install.sh` (the
  refusal prints that line), or runs an installer in a root shell, root follows the
  branch they chose. It stages from that branch's tip (also when the branch forked below the floor),
  and it leaves the floor on main. The panel cannot pass for the operator. Its only way to run the
  installer as root is the helper's `panel-self-update` verb, and the helper sets
  `PANEL_SELF_UPDATE=1` in the environment it builds for the installer, after copying its own,
  so nothing the panel hands sudo removes it. A run whose `SUDO_UID` is the panel's own account
  also counts as the panel's. sudo sets that value and the narrow grant does not let the panel
  change it, and it covers an older helper running a newer installer. One consequence: the host
  terminal's password-gated sudo runs as the panel account, so an installer started there counts
  as the panel's, and takes root's pieces from main only. Run it over SSH to test a branch.
  Installs run as a normal user are unchanged: their updates run as that account, which already
  owns everything they would stage from, so there is no boundary for either rule to hold.

* **The installed helper has to stay in step with the panel's code.** It lives outside the
  checkout, so the panel cannot refresh it — only `install.sh` can, as root. The verb table grows
  most releases, and a helper left behind answers a new verb with `unknown verb` and rc 2, with no
  fallback: the feature behind it simply stops working, silently. `install.sh` therefore refreshes
  the helper (and `db_maintenance.py`, `panel.conf` and its own root-owned copy) on the **update**
  path as well as a fresh install, and re-evaluates the sudoers grant there — which is also the
  only way a host that first installed before the helper existed ever gets narrowed. The panel's
  Diagnostics card compares the two verb tables and says which verbs are missing if they differ.

The remaining `sudo` call sites in the source are the pre-helper fallbacks described above. They
are counted by a ratchet in the test suite (`direct ['sudo', ...] sites`) that can fall but never
rise, so the boundary cannot quietly erode.

What you can do today:

- **If you only manage remote servers from this panel**, delete
  `/etc/sudoers.d/linuxgsm-panel`. The panel keeps working; the grant disappears. Only
  local-host management (panel-host OS updates, its firewall, its game-server users)
  stops working.
- **If you do manage the local host**, treat the panel host as you would any machine
  where a network service can become root: keep it off the public internet, keep 2FA on,
  and keep it updated.

Installs run as a **normal user** (the non-root path) get no sudoers entry at all and are
not affected.

Thank you for helping keep the project and its users safe.
