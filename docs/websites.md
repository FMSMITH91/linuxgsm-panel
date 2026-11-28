# Websites

Back to the [README](README.md). Who may do what: [permissions.md](permissions.md#permissions).

The **Websites** page (in the sidebar, beside Databases) hosts websites from the panel: a plain HTML
site, your own PHP code, a Node.js app, or a ready-made app (WordPress, phpBB, Drupal, Simple Machines
Forum, MyBB) installed in one step. Each site runs in its own locked-down container under its own
account on the host, and one web proxy on the host serves every site and gets their HTTPS certificates.

Not included: mail, DNS hosting, FTP accounts (use the panel's [SFTP service](sftp.md)), and a web
application firewall. Without mail, an app's "forgot password" email cannot be sent: an administrator
resets the password from the app's own admin page instead, and a WordPress administrator's password can be reset
from the site's Overview (see [Forgot the admin password](#forgot-the-admin-password)).

## Adding a website

Press **Add a website** (top right; it is always there for anyone who may add one). Pick a kind, give
it a name and, if you have one, a domain, and press **Create**. Everything else (memory, CPU, disk,
processes, largest upload) takes the defaults from the web proxy card's Security settings.

| Kind | What it is |
|------|------------|
| Plain site | HTML, CSS and images. Nothing on it runs code. |
| PHP site | Your own PHP code, with the PHP version you pick. |
| Node.js app | Your own Node.js app: see [Node.js apps](#nodejs-apps). |
| Install an app | WordPress, phpBB, Drupal, Simple Machines Forum (SMF) or MyBB, set up for you. |

If something the host needs is missing (for example the web proxy is not installed yet), the dialog
says so on its first line, with one button that fixes it for a superadmin; anyone else is told to ask
a superadmin. Websites run on the panel's own host for now, so the dialog offers no other host, and an
administrator below a superadmin (who never manages that host) gets no **Add a website** button: the list says
why instead. A missing web
proxy does not hold **Create** back: a site can be made first and put online once
the proxy is installed. A site that fails to start shows why, its last log lines and a **Retry** button. Retry sets
the site up again (its account, files, image and container) and starts it, so it also recovers a site whose
first install failed. An app whose install stopped part-way cannot be set up again: an administrator
gets **Delete and add again** instead, and anyone else is told to ask one. In a site's log
lines, requests its server refused ("client denied", nearly always scanners trying private pages such as
`/server-status`) are counted in one line instead of being listed.

Websites run in Podman, like add-ons. The first website on a host installs Podman and its two helpers from
Ubuntu's archive; a host where that fails is refused before anything is made. A first install that fails
later removes the site's account and folders again, so nothing half-made is left behind. If the panel
stops while a site is still being set up (a restart in the first seconds of an add or an app install), the
site cannot finish: the next time the Websites page is read it shows as failed, saying to delete it and add
it again. The delete removes whatever part of it reached the host.

## Installing an app

Choose **Install an app**, pick the app, and enter its domain and the app's admin username and email.
Leave the password empty and the panel makes a strong one, shown once when the install starts (a
password you type needs at least 15 characters). The panel then:

1. creates the site's account and container, and the app's database (a scoped user with a generated
   password, stored encrypted, the same way as the [Databases](permissions.md#the-databases-manager)
   page makes one);
2. downloads the app's pinned release from the signed catalog and checks its SHA-256 before unpacking;
3. writes the app's settings (WordPress gets fresh secret keys) and runs its installer inside the
   container, before the site is public. SMF and MyBB have no command-line installer, so the panel walks
   their install pages over the site's own local address, then removes their `install` folder: a
   leftover installer would let anyone take the site over;
   A fresh WordPress also has the bundled plugins (Akismet, Hello Dolly) and the default themes it does not use
   removed, keeping its active theme and WordPress's default one as the fallback, so its Site Health has none
   to recommend removing;
4. checks what the installer left before calling it done: the app's settings file is there and not empty,
   its tables are in its database, and its first page answers. An installer that reports success after
   failing is undone like any other failed step;
5. turns HTTPS on and shows **Open the site** and **Open the admin page** (the app's own admin address).

Every app needs a database server on the host. When it has none, the dialog says so before anything is made,
with **Set up databases** for a superadmin (MariaDB, reached from this machine only, the same setup as the
Databases tab of a game server). The dialog follows the setup and makes **Create** available once the server is
ready, with no reload; it reads the host's state again each time it opens. A database server that is installed
but stopped gets **Start the database server** instead, which starts it and enables it at boot. **Create**
asks the host again before anything is made, so a server that stopped after it was set up is caught there
(with the Start button), not at the install's database step. The site's Database tab offers Set up databases
too, and asks the host again before it creates a database.

The admin password and the database password never appear on a command line or in a log: each reaches the
installer as a file that only the site's account can read, removed when the step ends, and the installers'
output is never written to the system journal.

The dialog shows each step as it runs (a plain, PHP or Node.js site shows its own: the account, the image
built or downloaded, which takes a few minutes for PHP on a small host, and the container). If one fails, every step done before it is undone: no half
installed site, account, database or container is left behind. The dialog then says the install failed, why,
and that nothing was left on the host, with **Try again**, which brings the form back as you filled it in
(the password field empty). If a step cannot be undone (a database
server that does not answer, say), the dialog marks that step **Not undone** and says what is left; the
site stays in the list, and deleting it tries again. New app versions arrive through the
signed catalog, like add-on updates: see [New app versions](#new-app-versions).

### Forgot the admin password

A WordPress site's Overview has **Reset admin password** for whoever runs the site. After your panel password
check it lists the site's WordPress administrators; pick one, and press **Set the new password**. Leave the
password empty and the panel makes a 24-character one, shown once, as dots until you press Show (Copy copies it
without showing it; a shown password hides again after 30 seconds, or when you leave the tab). A password you
type needs 15 to 128 characters and is not shown back. You can set the administrator's email in the same step:
an address that receives mail lets WordPress's own "Lost your password?" work later.

The panel runs WordPress's own command-line tool (wp-cli) in a one-off locked-down container as the site's
account, with plugins and themes not loaded: the administrator's name, the password and the email reach it as
files only the site's account can read, never on a command line or in a log. Only an account with the
administrator role can be changed, and it is signed out of WordPress everywhere. The panel never stores the
password; the audit log records who reset which administrator of which site, and whether the email changed,
never the password or the address. For phpBB, Drupal, MyBB and SMF the card says to use the app's own "Forgot
password" link, which needs the site to send mail.

## New app versions

A new install always uses the app release and the container images named in the signed catalog, which
every panel fetches once a day, so a new release of WordPress, phpBB, Drupal, MyBB or SMF reaches new
installs without a panel update. This is how a new release gets there:

1. Every day a job in the project's CI looks for each app's newest stable release on the version line the
   panel supports (phpBB 3.3, Drupal 11, MyBB 1.8, SMF 2.1; WordPress's newest release), from the app's
   own release source. It downloads the official archive and checks it against the checksum the app's
   publisher publishes: phpBB's `.sha256` file, the SHA-256 on Drupal's release page, the SHA-256 GitHub
   records for MyBB's release. SMF publishes none, so its archive's SHA-256 is recorded as downloaded.
   WordPress comes inside the official WordPress image, so its new version is that image's.
2. When a release is newer, the job opens one pull request that changes the release's version, address and
   SHA-256 in the catalog. The site images (PHP, Node.js, WordPress, the static sites' web server, the
   object cache, the tunnel connector) and npm are kept current the same way, each within its supported
   version line, by the project's dependency bot.
3. A person with write access starts the pull request's checks (GitHub holds them for a pull request a job
   opened), which build and scan the images and check the catalog, then reviews and merges it. The catalog
   is then signed, and panels pick it up within a day.
4. The next install uses the new release.

**An existing site is not changed by any of this.** WordPress keeps itself up to date through WordPress's
own update servers, which its site may reach. The other apps' existing sites are updated from the app's
own admin page.

## How visitors reach your sites

A superadmin chooses this once per host, on the **Web proxy and public access** card at the bottom of
the Websites page:

- **Public**: anyone on the internet reaches your sites on ports 80 and 443.
- **Restricted**: ports 80 and 443 are open only to the networks you list. **Use Cloudflare's networks**
  and **Use Fastly's networks** add that CDN's official published ranges (they come with the signed
  catalog, so the panel fetches nothing extra; each list folds open under the buttons, with its source
  and the catalog's date); you can add any other network, IPv4 or IPv6, such as your own. The visitor's
  real address is read from a CDN's header only for requests from that CDN's networks: Cloudflare's
  `CF-Connecting-IP` while Cloudflare's are the only trusted networks, otherwise `X-Forwarded-For`, read
  from the right to the first address that is not a trusted network. Fastly adds the visitor's address
  only for HTTPS visitors, so turn on Force TLS for the service at Fastly. Your own networks are
  allow-only: they reach the sites, but the proxy reads no visitor's address from their requests unless
  you switch on **Trust my networks as proxies** (then `X-Forwarded-For` from them is believed, so turn
  it on only for proxies you run or trust: anyone on those networks could otherwise make your sites see
  any address). **A list from an address** reads more networks from an https address you give (one
  network a line; lines starting with `#` are skipped): when you save a new address, then once a day. A
  list is used only whole, when every line is a network no wider than /8 (IPv4) or /16 (IPv6) and there
  are at most 200; otherwise the save is refused naming the lines at fault, and a daily read that fails
  keeps the last good list and says why on the card. A changed list is applied at once. The address must
  be https on port 443 and resolve only to public addresses; Settings → Outside services → *Website allow
  lists read from an address* turns the reading off. These networks count as your own networks: allow-only
  unless trusted.
- **Tunnel**: no port is opened at all. The host connects out to Cloudflare with your tunnel's token,
  and Cloudflare brings visitors in. In Cloudflare's dashboard, give each website's domain a **Public
  Hostname** on that tunnel with the service `http://localhost:19080` (the card and each site's Domains tab
  show it). A domain needs no DNS check in this mode (its DNS points at Cloudflare, not the host): the web
  proxy serves every domain of an online site, and its Domains tab says HTTPS comes from the tunnel. Paste the token once: the panel stores it encrypted, never shows it
  again, and keeps it off every command line and log. Leave the box empty to keep the saved one. If the
  connector cannot start (a wrong token, or the host cannot reach the internet), the card says so;
  applying again tries at once, even after several failures in a row. An apply waits a few seconds after
  starting the connector and says it did not start when it stopped in that time (Cloudflare refuses a
  wrong token only once the connector has started). Switching to Tunnel closes ports 80 and 443 first, so
  the sites are never reachable straight at the host while the mode says Tunnel, even when the connector
  fails; a failed apply says the ports were closed. **Check the web proxy** on the card shows the proxy's
  version and state and, in tunnel mode, the connector's; **Apply again** applies the host's settings again.

In Public and Restricted mode, ports 80 and 443 are opened in the host's firewall when the first site
goes online and closed again when the last one goes offline; the web proxy stops too, so nothing
listens. When the host's firewall is off, the page says so: the ports are then reachable regardless. A
cloud provider's own firewall is outside the panel's reach: open or close 80 and 443 there yourself.
The panel's own address and port are never served through the web proxy.

The web proxy listens only on the host's own public and local-network addresses, read again each time its
settings are applied: never on the host's Tailscale address, where Tailscale Serve keeps port 443 for the
panel. If another program already uses port 80 or 443 there, or the host has no address outside its
Tailscale network, the card says which and nothing changes. When the host's address changes, the proxy
follows: it reads its addresses again each time it starts (a reboot included) and every 10 minutes while
it runs. A request for a name the proxy does not serve, over HTTP or HTTPS, gets no answer at all. Every apply leaves the proxy running and started at boot, and says it worked only once the proxy
really runs; otherwise the previous settings are put back and the proxy's own error is shown.

### Security settings

The same card has a folded **Security settings** section (the **Web proxy & security settings** button at the
top of the Websites page leads to the card). Every value can be changed; OWASP's recommended value is printed
beside the field, and a value outside it shows a note but is still saved. **Save settings** applies the proxy's
settings to every host with an online site at once; if a host's proxy refuses them, nothing is saved and the card
says why.

| Setting | Default | OWASP's recommendation |
|---------|---------|------------------------|
| HSTS max-age | 63072000 seconds | 63072000 (two years) |
| HSTS for every subdomain (includeSubDomains) | off | on, once every subdomain is served over HTTPS |
| Ask browsers to preload HTTPS (preload) | off | in OWASP's example header, with a warning that it is hard to undo |
| Lowest TLS version | TLS 1.2 | TLS 1.3 preferred; TLS 1.2 allowed for compatibility |
| Use the web proxy's own local certificates | off | off: a certificate authority visitors' browsers trust |
| Use Let's Encrypt's test service | off | off (browsers do not trust its certificates) |
| Page cache in the web proxy | off | none (not a security setting) |
| Customers must use two-factor sign-in | on | on |
| Access logs on for new sites | off | (privacy) |
| Let's Encrypt contact email | empty | optional |

**Why TLS 1.2 is the lowest version by default.** OWASP's Transport Layer Security Cheat Sheet ("Only
Support Strong Protocols") says web applications must default to TLS 1.3 and may support TLS 1.2 for
compatibility. With TLS 1.2 as the lowest version, every browser that has TLS 1.3 uses it, which is
the default OWASP asks for, and the older phones, computers and crawlers a public website still gets
visits from can connect over TLS 1.2. Choosing TLS 1.3 here leaves those visitors out; the card says so.
includeSubDomains and preload are off by default because the panel cannot know that every subdomain of
a customer's domain is served over HTTPS; the card notes each one while it is off. Preload only goes out
together with includeSubDomains. Turning on the page cache builds the web proxy with it on the host, which
takes a few minutes; until then the sites' page caches are left out and nothing breaks.

### Blocked visitors

A visitor that tries too many sign-ins on the websites, or asks for paths only scanners ask for, is blocked
for a while by the web proxy itself (fail2ban counts, the proxy refuses). It works behind Cloudflare or a
tunnel, where a firewall would only ever see Cloudflare's addresses: the proxy refuses the visitor's own
address, as the trusted-proxy rules above decide it (a CDN's header is believed only from that CDN's
networks). In Public mode the firewall blocks the address on ports 80 and 443 as well. A blocked visitor
gets a 403 from every website on the host, before anything else runs (no cached page, no redirect), and
nothing is reloaded or restarted for a ban.

What is counted, per address:

- **Sign-in attempts**: POSTs to the sign-in pages of the apps the panel installs (WordPress's
  `wp-login.php` and `xmlrpc.php`, Drupal's `/user/login`, phpBB's `ucp.php?mode=login`, MyBB's
  `member.php`, SMF's `index.php?action=login2`). WordPress answers 200 to a wrong password, so attempts
  are counted, not failures: 10 in 10 minutes by default.
- **Scanner requests**: paths nobody but a scanner asks for (`.env`, `.git`, backups of `wp-config.php`,
  `server-status`, phpMyAdmin and the like) and the site's own **Block a path** rules: 3 in 10 minutes by
  default.

Only those requests are written to the web proxy's security log (`/var/log/lgsm-web-proxy/security.log`,
readable by root alone, kept two days), and only the time, the visitor's address, the method, the site's
name and the answer's status: no path, query, header or cookie. Every other request is logged only where a
site's own access log is on, as before (a blocked visitor's refused requests are written to the security log
too, with the same few fields). The log's folder is made, the web proxy's own, before the proxy checks a new
configuration, and each site's names are tied to its security log whether or not its access log is on.

Settings, per host, under **Blocked visitors** on the web proxy's card (superadmin): blocking on or off,
the two limits, the window, the first ban (10 minutes by default, OWASP's example of a fixed lockout), a ban
that grows for an address banned again (on by default, OWASP's exponential backoff), the longest ban (24
hours by default; OWASP asks for temporary blocks) and addresses never to block. OWASP gives no number for
a limit or a window; the card shows OWASP's words beside each field, and a note, never a block, when
blocking or the growing ban is off, or the first ban is shorter than OWASP's 10 minutes (OWASP Authentication Cheat Sheet, "Login Throttling"; Credential
Stuffing Prevention Cheat Sheet, "IP Mitigation and Intelligence"). Never blocked, whatever the settings:
the host's own addresses, the loopback, your tailnet, every CDN preset's networks, the allow list above and
the panel's login whitelist, so a CDN's own address is never blocked.

Each website's **Rules** tab lists the addresses blocked while attacking it (why, since when and until
when), with **Unblock**, and counts the host's other blocked addresses, which are kept off this website too
(they attacked another one, so they are not named). A ban is listed on the site its counted requests asked for
(never the site of a refused request), and a ban fail2ban puts back after a restart keeps that site. Until when
is fail2ban's own end: a growing ban is raised by fail2ban a moment after it starts, and the list follows it.
Unblock asks first, then lifts the address in fail2ban and in the web proxy, and its row leaves the list at once;
an address already lifted on the host (fail2ban's `unbanip`) answers that it was already unblocked. Every ban, every ban's end and every Unblock is in the audit
log, each end in its own words: the ban ran its time, it was lifted on the host (fail2ban's `unbanip`), or
the jail stopped or restarted (a restart blocks the addresses whose ban is still running again). A ban is
recorded within 30 minutes even when nobody opens the list, with the time it happened. Switching the
exposure mode restarts the websites' two jails only, so the firewall ban comes or goes at once; live bans
are kept. Blocking needs fail2ban on the host (the panel's installer puts it there); the card says when it
is missing.

The proxy has no request rate limiting of its own: Caddy's rate-limit module is not one of its official
modules, has no tagged release to pin, would need the web proxy rebuilt on every host (as the page cache's
optional build is), and keys on the address the proxy is connected from, which behind a CDN is the CDN's.
The sign-in limit above is the throttle instead, keyed on the visitor's own address.

## Domains and certificates

On a site's **Domains** tab, add a domain and the page shows the exact DNS records to create at your
domain's provider (an A record and, when the host has IPv6, an AAAA record). Each record's name is shown
the way most providers ask for it, `@` for the domain itself or `www` for its www name, with the full
name beside it. The host's addresses are its interfaces' public IPv4 and IPv6 addresses, read again at
each check (never its Tailscale or temporary ones), plus the host's public address, which **Check again**
looks up again (at most every 10 minutes, with the same lookup as the Servers page: behind NAT it asks the
outside service only while Settings > Outside services allows it). A domain is checked as soon as it is
added, from the add dialog too; press **Check again** once the records are in place. The panel looks the domain up and compares the answer with the host's address; it
never connects to the domain itself. A domain that points at a private address is refused. A domain whose
answers are all inside one CDN's published networks (Cloudflare's or Fastly's today, the signed catalog's
allow-list presets) is shown as **going through** that CDN and is served too: see
[Behind a CDN](#behind-a-cdn). Answers split between two CDNs, or any other answer, are "points elsewhere",
and the web proxy does not serve that domain until a check finds it pointing here.
When a check finds a domain of a site that is already online pointing here for the first time, the web
proxy is updated at once and the site answers on it; nothing has to be taken offline and back.

**Put online** checks every domain's DNS again first. A website goes online only when at least one of its
domains would be served. If none would be (none points here or goes through Cloudflare yet), it refuses
and names each domain with its DNS state, with a link to the Domains tab, so a site is never shown online
while it answers on nothing. It also refuses, in words, while the web proxy is not installed on the
host: a superadmin gets a link to install it, anyone else is told to ask one. A new site starts offline:
when an app install finishes, the dialog's main button is **Put it online** (for an administrator of the
site, who can also tick **Put it online when it is installed** before Create), and the site's Overview
says it is offline with the same button. When some of its domains are served
and others are not yet, the answer says which ones it does not answer on. On a host in Tunnel mode
there is no DNS rule: every domain of the site is served through the tunnel (the web proxy must still
be installed).

Certificates come from Let's Encrypt automatically, for the domains you added and no others.
Let's Encrypt sees your domain names, the host's address and, if you set one, the contact email. A
test service (certificates browsers do not trust) can be chosen in Security settings for trying things
out. A site has at most 5 domains, and at most 3 can be added per hour.

Each domain on the Domains tab shows the certificate the web proxy really serves for it: who issued it
and when it expires (read from the host at most every 5 minutes). A test or local certificate is
marked as one browsers do not trust. A certificate with fewer than 10 days left gets a warning, as does
an expired one. The proxy renews a certificate once a third of its lifetime is left, so a warning means
renewal has been failing for days, usually because ports 80 and 443 do not reach the host. A domain of an
online site that has no certificate shows the web proxy's own reason as soon as the proxy logs one (for
example the certificate authority's "Timeout during connect"), read from the proxy's own journal; still
without one 10 minutes after it was first served, it says so, as failed, with that reason or, when the proxy
said nothing, the usual one (ports 80 and 443 do not reach the host), instead of "pending".

**Make primary** decides which name the web proxy lists first. On a WordPress site it first sets
WordPress's own address (WordPress Address and Site Address, its home and siteurl options) to the new
domain, with WordPress's own code in the site's running container. If that cannot be done (the site is
stopped, say), the primary domain stays as it was and the answer says why.

### Your own certificate

A website has one **Certificate** button, at the top of its Domains tab: **Automatic (Let's Encrypt)**,
the default, or **Your own certificate**. For your own, paste the certificate followed by its intermediate
certificates (a `fullchain.pem`), and its private key without a passphrase, once for the whole site, then
**Save**. The panel checks it against each of the site's domains: every domain it covers uses it (a
certificate for `example.org` and `*.example.org` covers both, pasted once), and every domain it does not
cover stays automatic, listed with the reason. A domain you add later that the certificate covers uses it
at once; its DNS check and when it goes online are unchanged. Each covered domain's line says **Uses the
site's certificate**. A [Cloudflare Origin CA](#cloudflare) certificate is this case. Switch the site
back to Automatic the same way at any time, one action for every domain; the web proxy then gets Let's
Encrypt certificates again, and its copy of your certificate and key is removed from the host the next
time its settings are applied (at once when the site is online). The certificate and key are stored once
for the site, whatever the number of domains on them; a certificate pasted for one domain before this
existed was moved to its site on the update (a domain whose certificate differed from the rest keeps its
own).

What is checked (OWASP Transport Layer Security Cheat Sheet, "Certificates"):

| Refused (nothing is saved) | Noted, and saved anyway (OWASP's value beside it) |
|----------------------------|----------------------------------------------------|
| a certificate or key that cannot be read, or input over 64 KB | an RSA key under 2048 bits, or an ECDSA key not on P-256 or P-384 ("Use Strong Keys and Protect Them": at least 2048 bits) |
| a key protected by a passphrase | a certificate signed with SHA-1 or MD5 ("Use Strong Cryptographic Hashing Algorithms": SHA-256) |
| a key that is not the certificate's | a self-signed certificate ("Use an Appropriate Certification Authority": a well-known CA) |
| a certificate already expired, or not valid yet | only the server certificate, with no intermediates, or a chain out of order |
| a certificate that does not cover the domain (its subjectAltName; a wildcard covers one label) | 30 days or fewer left |

OWASP gives no number of days for the expiry warning and does not cover the chain; the chain's order is
the one TLS itself requires (RFC 8446, section 4.4.2) and 30 days is the panel's own warning, the same as
for the panel's own certificate. The private key is stored encrypted, is never shown again or returned by
any page, and never goes into a log, an audit row or a command line: it reaches the host on the
privileged helper's input and is written there readable by the web proxy alone. The audit log records
the domain, the certificate's issuer, its expiry and its SHA-256 fingerprint.

If the site is online, saving updates the web proxy at once. If the proxy does not take the new
certificate, the domain keeps the one it had, the proxy is put back as it was, and the page says why. The
panel never renews your certificate: the domain's line warns from 30 days before it expires, and so does
the **A TLS certificate is expiring soon** alert (once a week per domain, under Settings > Notifications).
A self-signed certificate is noted when it is saved, and the domain's line keeps saying that visitors'
browsers warn for as long as it is in use (a CDN's origin certificate is named as one instead).
A host in Tunnel mode serves no certificate of its own: the tunnel's provider serves the one visitors see.
Your certificate stays saved and its key is not sent to the host while the tunnel is in use; it is
served again if the host leaves Tunnel mode. In Tunnel mode no domain is marked as failing to get a
certificate, since the web proxy asks for none.

### Behind a CDN

A domain whose DNS goes through a CDN resolves to the CDN's addresses, not the host's. The panel
recognises each CDN whose published networks the signed catalog carries (the Restricted mode's presets:
Cloudflare and Fastly today) and serves the domain when every answer is inside ONE of them. The Domains
tab names the CDN and says what its certificate needs: if the CDN offers an origin certificate, paste it
as **Your own certificate** and use the CDN's strict TLS mode; otherwise the automatic certificate needs
the CDN to pass plain HTTP to the host for `/.well-known/acme-challenge/`. Where the catalog names a
CDN's own origin certificate and strict mode (Cloudflare's), the note names them.

#### Cloudflare

A domain whose DNS record is proxied by Cloudflare (the orange cloud) resolves to Cloudflare's
addresses. Two ways to give it a certificate:

1. **Recommended: a Cloudflare Origin CA certificate.** In Cloudflare, open SSL/TLS > Origin Server and
   create a certificate for the domain and its wildcard. Paste the certificate and its private key once,
   on the site's **Certificate** button as **Your own certificate**. Then set Cloudflare's SSL/TLS mode
   to **Full (strict)**, so Cloudflare checks the host's certificate on every connection. Only Cloudflare
   trusts an Origin CA certificate, so keep the record proxied; the panel notes this when you save.
2. **Automatic (Let's Encrypt) through Cloudflare.** It works only while Cloudflare passes plain HTTP to
   the host: turn off **Always Use HTTPS** in Cloudflare, and the first certificate can need the record
   set to **DNS only** (grey cloud) until it is issued. Set the SSL/TLS mode to Full (strict) once it is.
   The domain's line says this while it is on Automatic.

With either, the host's ports can be limited to Cloudflare in **Restricted** mode with **Use Cloudflare's
networks**. Cloudflare's "Flexible" mode sends visitors' traffic to the host unencrypted: use Full
(strict). (OWASP Transport Layer Security Cheat Sheet: "Use an Appropriate Certification Authority for
the Application's User Base", "Use Correct Domain Names".)

## Files

The **Files** tab is a file manager for the site's folder: browse, edit, upload, rename, delete, and
**Upload archive and extract** (zip or tar.gz). An archive is checked before anything is unpacked:
nothing may land outside the site's folder, links and device files are refused, and the unpacked size
is capped. The same folder appears in the panel's [SFTP service](sftp.md#websites) for users who may
change the site's files: one file sent through the page may be at most 50 MB, so bigger files go through
SFTP (the Account page has its address and your keys). Uploading a file whose name is already there says so
and offers **Replace them**. The site's disk limit counts this folder, its backups and its settings, not the
container images the panel keeps for it ([how websites run](websites-runtime.md#disk)).

## PHP

PHP sites and the PHP apps have a **PHP** tab:

- **PHP version**: only versions that PHP still supports with security fixes. When a version reaches the
  end of its support it leaves the catalog: a site still on it keeps it selected, marked "end of support", with a
  note to choose a newer one. Only an administrator of the site can change the version; others see it read-only.
- The common `php.ini` values: `memory_limit`, `upload_max_filesize`, `post_max_size`,
  `max_execution_time`, `max_input_time`, `max_input_vars`, `date.timezone` and `display_errors`. OWASP's
  figure is shown beside each one it has a figure for; a value above it shows a note and is saved
  anyway (WordPress, for one, usually needs more memory than OWASP's 50M).
- **Advanced php.ini**: extra `key = value` lines for this site only, checked line by line. Loading an
  extension, prepending or appending a file, and the settings the panel manages are refused.
- Always added after your settings, and cannot be removed: `expose_php = Off` and
  `allow_url_include = Off`.
- **Effective values**: what PHP inside the container really uses.

Saving restarts the site's PHP gracefully.

## Performance

- **OPcache** (PHP): keeps compiled PHP in memory. On by default.
- **Object cache** (PHP): a private Redis-compatible store for this site only, with no copy on disk. Off
  by default. Turning it on or off starts or removes the cache beside the running site; the site itself is
  not restarted. Its password is kept in a file the site reads (`/run/panel/object-cache-password`, read-only),
  there only while the cache is on. A WordPress site the panel installs has the address and password set in its
  `wp-config.php` already: install the **Redis Object Cache** plugin in WordPress and press **Enable Object
  Cache**. For other code, **Show connection settings** gives the address and password once, after the password
  check, and is written to the audit log.
- **Page cache**: the web proxy keeps whole pages for visitors who are not signed in, for the time you
  set. Sign-ins, form posts, any answer that sets a cookie, and admin pages (`/wp-admin`, `/adm`,
  `/admin`) always skip it. **Purge cache** empties this site's cached pages only, through the page cache's own
  interface: nothing restarts and other sites keep theirs. It can be pressed once a minute. **Keep pages for**
  and **Purge cache** stay disabled, with the reason, while the page cache is off or the host's web proxy was
  not built with it. Off by default.
- **Static file caching**: browsers keep images, styles and scripts longer, and pages are sent
  compressed. On by default.

## Rules

The **Rules** tab adds redirects, extra response headers and blocked paths through a form. The web
proxy checks the whole new setup before it replaces the running one: a rule that fails is refused, and
every site keeps serving as before. Superadmins can also add raw web proxy lines to a site, checked the
same way.

## Node.js apps

A Node.js app gets an **App** tab: the Node.js version (only versions Node.js still supports), the
install and build command (`npm ci --omit=dev` by default), the start command (`npm start`), the port the
app listens on, and environment variables. Variables are stored encrypted and never shown again; leave a
saved one empty to keep it.

A new app has no files yet, so it is not started: its page says it waits for its files, with **Upload its
files** (the Files tab), and its main button is **Build and start**, which installs its packages and starts it.

The app runs in its own container from an official Node.js image, not on the host's own Node.js (which
the panel installs for its server queries): that copy is shared with the panel and every account, so an
app there would escape its site's limits and network rules. The build step may reach the npm registry;
the running app has no internet access unless an administrator allows it. A crashed app is restarted,
with a growing pause between tries.

A new Node.js site starts with no files, so it is not started yet: it waits for them. Upload the app on the
**Files** tab, then press **Save and rebuild** on the **App** tab. That runs the install and build command
and starts the app. Press it again after you change the app's files. If the build fails, the running app is
left as it was.

## No outbound access, by default

A site's container reaches its own database and nothing else: it cannot call out to the internet or
reach the host's other services. This keeps a compromised site from attacking anything else. WordPress
is the one exception: it may reach WordPress's own update servers, so its security updates work. It goes
through a small proxy that connects only to those servers on port 443, trying each of their checked addresses
in turn; when it refuses or cannot connect, its journal (the site account's `lgsm-site-egress` unit) says
which host and why, and nothing more. An
administrator can give one site full internet access on its Settings tab, with a warning; saving the switch
installs the site again, and WordPress then connects directly instead of through the proxy. Even then it
never reaches the host's other services. Plugins and themes for other apps are uploaded through Files.

WordPress also calls its own address (Site Health's REST API and loopback tests, the editor's checks). Inside
the container that address leads nowhere, so the panel writes a small must-use plugin,
`wp-content/mu-plugins/lgsm-panel-loopback.php`, at every install of a WordPress site: it sends a request for
the site's own name to the site's own server inside its container, with the web proxy's token read from a file
only the site's account can read (never a command line or a log). The request never leaves the container, so no
outbound access is added. The panel writes the file again at the next install if it is changed or removed.

## Backups and databases

**Backups** holds the site's files and its databases, kept on the host as the site's own account (the
newest 7 by default). Restoring stops the site, takes a safety backup first, then puts the files and
databases back, and starts the site again only if it was running. The Overview shows when the newest backup
was taken. The **Database** tab creates the site's databases (named `ws<site>_<name>`) and shows
their connection settings on request, which is written to the audit log. The site's first database restarts a
running site (a stopped one from its next start), so its code reaches the database server at once. Deleting a site (on its Settings
tab) removes its databases and their database user too; if one cannot be removed, nothing else is, and the
site stays offline for another try. A site still being set up cannot be deleted until that finishes or fails.

## Updates and settings

When the signed catalog has a newer image for a site (a security rebuild), or the panel changed the files it
writes for a site (its web server's settings, for example), the site's Overview offers **Update**, which installs
it again from that image and restarts it (a few seconds offline; building a PHP image can take a few minutes
first). Its files, databases, settings and secrets stay. A site installed before the panel recorded these is
offered Update once. The Overview says how many updates are ready and what they are, and when the site updates by
itself: websites update in the nightly window (04:00-05:00 on the host's clock by default), one at a time, unless a
visitor reached the site in the last minutes; a failed update puts the site back on the image it ran before. See
[updates.md](updates.md). Saving a site's Settings restarts it only when one of its limits changed; the note and the
access log alone never do.

## Access logs

Off by default, for visitors' privacy. When an administrator turns them on for a site, visitor
addresses are shortened before they are kept, and they are kept for the days set in Security settings.
The site's own error log is always readable on its Overview tab.

The Overview shows what the site runs (the image of its container) and what it uses: memory, disk and CPU,
read from the host when the page is opened. A figure that cannot be read says so and why (the site is not
running, the host did not answer, or Podman's own words), never an empty bar. On a host that does not let
a site's account limit its own containers, it also says the CPU limit is set on the whole account.

## Customers

A customer is a panel user whose group holds only website permissions and has their sites in it. They
see only those sites and none of the administrator's controls (limits, putting a site online, deleting
it, full internet access), and cannot see other users, hosts, game servers or other customers' sites.
Controls a customer may see but not change (the PHP version, the object cache, an app's runtime, port and
commands) are shown read-only with who can change them. The invite link uses the panel's site domain from
Settings; without one it uses the address the administrator is on, and says so, since a customer must be able
to reach it.
**Add a customer** gives them the sites you tick. Turn on **They may add their own websites** to let them add
more, up to the number beside it (it starts at the **Sites per customer** setting on the Websites security
settings); their list then says how many they have used. Without it they have only the sites given. Two-factor sign-in
is required for customers by default. The permissions are in [permissions.md](permissions.md#permissions).
