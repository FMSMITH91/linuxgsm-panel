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
image pinned by digest in the signed catalog. The container runs as that account's own user, with every
capability dropped, no new privileges, a read-only system and limits on memory (no swap), processes and
open files. Its server listens only on the host's loopback address, and it refuses any request that
does not carry the web proxy's secret token, so another account on the host cannot reach it directly.

A site has no route to the internet. WordPress reaches only its own update hosts (api.wordpress.org and
downloads.wordpress.org), through a small proxy that refuses any name resolving to a private or local
address. A Node.js app reaches npm's registry only while it is being built. The egress guard (an
nftables table) keeps site accounts away from the host's other addresses (its LAN, tailnet and public
addresses), so a site cannot reach the panel's port or SSH.

## CPU limits

A site's CPU limit is applied in one of three ways, and the site card says which one:

- **On the container**, when the host lets the site's account control its own CPU (the usual case on
  Ubuntu 24.04 and later).
- **On the whole account**, when the host does not delegate CPU control to user accounts. The panel then
  sets a CPU quota and weight on the account's user slice, which covers the site, its object cache and
  its gate together. The limit is just as strict; it is shared by those containers.
- **None**, only if neither could be set. The card says "this website runs without one" rather than
  hiding it.

## The web proxy

One web proxy (Caddy) per host owns ports 80 and 443 while at least one site is enabled. It is
downloaded from Caddy's own release, checked against the sha256 in the signed catalog, and runs as its
own system user with only the right to bind low ports. Its admin interface is off. Any request for a name
it does not serve, including the bare IP address, is closed, so the panel itself is never reachable
through it.

### Page cache

The page cache needs Caddy built with the cache module. The panel builds it on the host when you turn the
cache on: a container build from the pinned Caddy builder image runs `xcaddy` with the module at the exact
version the catalog names. Go checks every module against its checksum database. The binary is then taken
out of the image, checked to contain the module, and installed in place of the plain proxy. The page cache
is off by default. Logged-in visitors, form posts and admin pages always bypass it.

## Pinned images and downloads

Every image and download a site uses is pinned in the signed catalog (`panel/addon_images/catalog.json`,
section `sites`): images by sha256 digest, downloads by sha256 and an https address on a fixed list of
hosts. A refused catalog changes nothing. CI scans every pinned image with Trivy and fails on a High or
Critical issue that has a fix.

How the one-click app releases were pinned:

- **phpBB**: the release archive and the `.sha256` file phpBB publishes beside it.
- **Drupal**: the release archive and the SHA-256 on its release page.
- **MyBB**: the release archive and the sha256 GitHub records for the release asset.
- **WordPress**: comes inside the official WordPress image, pinned by digest.
- **Simple Machines Forum**: simplemachines.org's downloads sit behind a browser check that automated
  clients cannot pass, so neither the panel nor the maintainer's tools can fetch them. The pin is the
  official repository's tag archive (`github.com/SimpleMachines/SMF`, tag v2.1.8). It was downloaded twice
  with the same sha256. Files inside it were checked against the tag's own git objects, and the
  installer's form fields were read from the tagged source. To update it, download the new tag's archive,
  record its sha256 in the catalog, and repeat both checks.

The Cloudflare network list used by the "restricted" exposure mode is also part of the catalog. A daily CI
job compares it with Cloudflare's published lists and opens a pull request when they change.
