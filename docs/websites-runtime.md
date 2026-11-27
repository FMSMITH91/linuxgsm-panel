# Websites: how they run

This page is for operators. It says where a website runs, what limits it, how the web proxy is set up,
and where every pinned image and download comes from.

## Where websites run (version 1)

Websites run on the **panel's own host only** in this version. A website needs the panel's root helper
(it creates the site's own Linux account, the web proxy's service and the egress guard), and only the
panel's own host has it. If you pick a managed host, the panel refuses with this sentence:
"Websites run on the panel's own host for now: a managed host cannot run the panel's root helper, which
websites need." Websites on managed hosts will come in a later version.

## One account and one container per site

Each site runs under its own account (`ws` followed by the site's number), in rootless Podman, from an
image the panel builds on the host from a base pinned by digest in the signed catalog (a static site runs its
pinned image as it is; see "Images built on the host" below). The container runs as that account's own user,
with every capability dropped, no new privileges, a read-only system and limits on memory (no swap), processes
and open files. Its server listens only on the host's loopback address, and it refuses any request that
does not carry the web proxy's secret token, so another account on the host cannot reach it directly.

A site has no route to the internet. WordPress reaches only its own update hosts (api.wordpress.org and
downloads.wordpress.org), through a small proxy that refuses any name resolving to a private or local
address. A Node.js app reaches npm's registry only while it is being built. The egress guard (an
nftables table) keeps site accounts away from the host's other addresses (its LAN, tailnet and public
addresses), so a site cannot reach the panel's port or SSH. Its rules apply only to packets that carry a
site account's uid; a packet the kernel sends without a socket of its own (a reset for a closed port, a
ping reply, the last ACK of a closed connection) has no uid and is never dropped, so the host keeps
answering ping and refusing closed ports for every account while a website is online.

A site has no name server either. Its container gets a read-only `/etc/resolv.conf` from the panel
(`~/site/conf/resolv.conf`) that names no server and allows one try of one second, so a name lookup is
refused at once. Before, the container kept its image's own file (WordPress's names 1.1.1.1 and
1.0.0.1), which it cannot reach, and every lookup waited about 20 seconds. The same file is used by an
app's build and by an app's install steps. A site with **full egress** (a superadmin's switch) keeps the
name servers Podman gives it.

### WordPress's scheduled tasks

WordPress normally runs its scheduled tasks (publishing scheduled posts, update checks, plugins' jobs)
during a visitor's request, by sending a request to the site's own address. That visitor waited for it,
and with the page cache on the visit ended in an error. A WordPress site installed by the panel turns
that off (`DISABLE_WP_CRON` in its `wp-config.php`) and runs the tasks from a timer of the site's own
account instead (`lgsm-site-cron.timer`), every 5 minutes, inside the site's running container
(`podman exec lgsm-site php /var/www/html/wp-cron.php`). Each site keeps a fixed offset within the 5
minutes, so a host's sites do not all run at once. A run is skipped while the site is stopped or before
WordPress is installed. The page output is thrown away; PHP's errors go to the site account's journal,
without function arguments. The timer is written and started with the site, and removed with the site
(an install that fails and is undone removes it too).

Running the tasks in the running container costs about 0.13 s of Podman's own time per run, where a
separate wp-cli container took about 0.29 s and a second copy of PHP in memory (measured on Podman with
a Debian image).

The other apps need no timer. phpBB, MyBB and Simple Machines Forum start their tasks from an image in
the page that the visitor's browser fetches (`cron.php` or `task.php`), never from the server itself;
Drupal's automatic cron runs in the same PHP process after the page is sent. A task that looks a name up
now fails at once instead of waiting.

## CPU limits

A site's CPU limit is applied in one of three ways, and the site card says which one:

- **On the container**, when the host lets the site's account control its own CPU (the usual case on
  Ubuntu 24.04 and later).
- **On the whole account**, when the host does not delegate CPU control to user accounts. The panel then
  sets a CPU quota and weight on the account's user slice, which covers the site, its object cache and
  its gate together. The limit is just as strict; it is shared by those containers.
- **None**, only if neither could be set. The card says "this website runs without one" rather than
  hiding it.

## Disk

A site's disk limit (2048 MB unless an administrator changes it) counts the site's own folder: its files, its
backups and its settings. The panel measures it with `du`, as the site's account, before every upload and every
saved file. If `du` cannot read all of it, the panel does not guess: nothing is written, and the page says the use
could not be measured. A write that would pass the limit is refused.

The site's container images do not count toward that limit. They come from the signed catalog, they are the same
for every site of a kind, and old ones are removed after an update. Each site account keeps its own copy: about
1.1 GB for a WordPress site (its image and wp-cli's), about 1.1 GB for a PHP site, and about 0.3 GB for a Node.js
site (its image and the gate's nginx). On a host where `/home` has user quotas on, the panel also sets the site
account's quota, to the site's limit plus 4096 MB for those images.

## The web proxy

One web proxy (Caddy) per host owns ports 80 and 443 while at least one site is enabled. It is
downloaded from Caddy's own release, checked against the sha256 in the signed catalog, and runs as its
own system user with only the right to bind low ports. Its admin interface is off. Any request for a name
it does not serve, including the bare IP address, is closed, so the panel itself is never reachable
through it.

### Page cache

The page cache needs Caddy built with the cache module. The panel builds it on each host that has a web
proxy when a superadmin turns on **Page cache in the web proxy** in the Websites security settings (and again
after the plain proxy is installed while it is on). The build runs in the background and takes a few minutes;
a failure is shown on the security settings card, saying which part failed (the build, the check or the
install), with the reason and the build's last lines in the panel's log. A container
build from the pinned Caddy builder image runs `xcaddy` with the module at the exact version the catalog
names. Go checks every module against its checksum database. Where the pinned Caddy asks for a library version
with a known flaw, the build raises it to the fixed version (today golang.org/x/net, to v0.62.0); that only sets a
minimum, so a later Caddy that needs a newer one still gets it. The build runs with every capability dropped
and on the host's own network, so Podman sets up no network of its own: it never turns on the host's IP
forwarding or adds firewall chains. The binary is then taken out of the image, written beside the installed
proxy with its owner and mode, run as the proxy's own unprivileged user to check that it contains the module,
and moved over the plain proxy. Every image the build made (its builder stage and the images it pulled, about
3 GB) is removed from root's image store afterwards, whether the build worked or not; no other image is
touched. Podman's small blob-info cache (`/var/lib/containers/cache`) is removed too, but only when the build
made it: one that was already there belongs to another tool and stays. Until then, a site's page cache is left out and nothing breaks, and a site's Performance tab says
whether the proxy is still being built or why its build failed.
The page cache is off by default. Logged-in visitors, form posts and admin pages always bypass it.

## Images built on the host

A pinned upstream image keeps every security issue its distribution has fixed since the image was last rebuilt,
and the official images are rebuilt days (Debian) or weeks (Alpine) after a fix is published. So the panel does
not run the pinned images as they are: it builds each site's image on the host, as the site's own account, from
a file in `panel/website_images/`, with the pinned image as the base. The build applies the distribution's
security updates, keeps no package lists or caches, and is built again only when the catalog pins a new base or
the panel ships a changed file. Only the built image stays in the account's store: the build makes no
intermediate images and removes its bases once it is done.

- **WordPress** (`wordpress/`): the official WordPress image for the site's PHP version, with Debian's updates.
- **wp-cli** (`wpcli/`), which WordPress's install steps run: the official wp-cli image (Alpine) with Alpine's
  updates. It runs as `www-data` (82), as upstream's does. It is built when the first step needs it.
- **Node.js** (`node/`): the official Node.js image for the app's version, with Debian's updates and npm at the
  exact version the catalog names (`sites.runtimes.node.npm`), which npm checks against the registry's sha512
  before installing it. A Node.js release keeps the npm it shipped with, and npm's bundled packages get their
  fixes in later npm releases. The app's `npm ci` runs this npm. npm's update notice is turned off for the
  app's build, so the build's last lines on the page are the build's own.
- **The tunnel connector** (`cloudflared/`): Cloudflare's image is a Debian "distroless" image with no package
  manager, so its libraries cannot be updated in place. cloudflared is a single static program that loads none
  of them, so the panel copies it onto an empty image with only the certificate authorities (from Debian's
  `ca-certificates`, upgraded in a pinned `debian:trixie-slim` stage, `sites.tunnel.cloudflare.certs`) and the
  account files. It runs as user 65532, as upstream's does, with no shell.
- **PHP** (`php/`): see the next section.

Each build reaches the distribution's archive (and, for Node.js, npm's registry) through the host's network,
for the build only; the site's container never does. A first install takes a few minutes longer on a small
host. A build that fails says so ("The site's image could not be built") and shows the build's last lines.
CI builds every one of these files from the catalog's pins and scans the built images, which are what the
sites run (see "Pinned images and downloads").

## The PHP sites' image

PHP sites and the one-click apps other than WordPress run on the official PHP image (Apache) pinned in the
catalog, with the extensions the apps need added: mysqli and pdo_mysql (their database drivers), gd, intl and
zip. The official image has none of them. The panel builds this image on the host, as the site's own account,
from `panel/website_images/php/Containerfile` the first time a site needs it (a few minutes on a small host),
and again only when the catalog pins a new PHP image. It is built in Docker's image format, which keeps the
file's `SHELL` line (Podman's default format ignores it), and its commands are plain POSIX shell as well. The
build fetches Debian's packages, each checked by apt against Debian's signing keys, and keeps only the
libraries the extensions load, after applying Debian's security updates. CI builds the same file for every PHP
version the catalog pins and scans the built image.

## An app's variables

A Node.js app's environment variables are stored encrypted in the panel's database. On the host they are in
`~/site/conf/app.env` (0600, in a 0700 folder of the site's account), which its container reads as its
environment: the app's own processes, the site's account (`podman inspect`) and root can read them, and no
other account. They are never on a command line, in a unit file, in the journal or in an audit row.

## Pinned images and downloads

Every image and download a site uses is pinned in the signed catalog (`panel/addon_images/catalog.json`,
section `sites`): images by sha256 digest, downloads by sha256 and an https address on a fixed list of
hosts. A refused catalog changes nothing. CI scans what the sites run with Trivy and fails on a High or
Critical issue that has a fix: each image built on the host, built in CI from the same file and the catalog's
pins, and each image a site runs as pinned (the static sites' nginx, the object cache's Valkey). A pinned image
that is only a build's base is not scanned on its own, as no site runs it: the issues the build's updates fix
would fail the scan although no host has them.

How the one-click app releases were pinned:

- **phpBB**: the release archive and the `.sha256` file phpBB publishes beside it.
- **Drupal**: the release archive and the SHA-256 on its release page.
- **MyBB**: the release archive and the sha256 GitHub records for the release asset.
- **WordPress**: comes inside the official WordPress image, pinned by digest (the base of the site's image).
- **Simple Machines Forum**: simplemachines.org's downloads sit behind a browser check that automated
  clients cannot pass, so neither the panel nor the maintainer's tools can fetch them. The pin is the
  official repository's tag archive (`github.com/SimpleMachines/SMF`, tag v2.1.8). It was downloaded twice
  with the same sha256. Files inside it were checked against the tag's own git objects, and the
  installer's form fields were read from the tagged source. To update it, download the new tag's archive,
  record its sha256 in the catalog, and repeat both checks.

The Cloudflare network list used by the "restricted" exposure mode is also part of the catalog. A daily CI
job compares it with Cloudflare's published lists and opens a pull request when they change.
