# Websites

Back to the [README](README.md). Who may do what: [permissions.md](permissions.md#permissions).

The **Websites** page (in the sidebar, beside Databases) hosts websites from the panel: a plain HTML
site, your own PHP code, a Node.js app, or a ready-made app (WordPress, phpBB, Drupal, Simple Machines
Forum, MyBB) installed in one step. Each site runs in its own locked-down container under its own
account on the host, and one web proxy on the host serves every site and gets their HTTPS certificates.

Not included: mail, DNS hosting, FTP accounts (use the panel's [SFTP service](sftp.md)), and a web
application firewall. Without mail, an app's "forgot password" email cannot be sent: an administrator
resets the password from the app's own admin page instead.

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
a superadmin. A site that fails to start shows why, its last log lines and a **Retry** button.

Websites run in Podman, like add-ons. The first website on a host installs Podman and its two helpers from
Ubuntu's archive; a host where that fails is refused before anything is made. A first install that fails
later removes the site's account and folders again, so nothing half-made is left behind.

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
4. checks what the installer left before calling it done: the app's settings file is there and not empty,
   its tables are in its database, and its first page answers. An installer that reports success after
   failing is undone like any other failed step;
5. turns HTTPS on and shows **Open the site** and **Open the admin page** (the app's own admin address).

The admin password and the database password never appear on a command line or in a log: each reaches the
installer as a file that only the site's account can read, removed when the step ends, and the installers'
output is never written to the system journal.

The dialog shows each step as it runs. If one fails, every step done before it is undone: no half
installed site, account, database or container is left behind. If a step cannot be undone (a database
server that does not answer, say), the dialog marks that step **Not undone** and says what is left; the
site stays in the list, and deleting it tries again. New app versions arrive through the
signed catalog, like add-on updates.

## How visitors reach your sites

A superadmin chooses this once per host, on the **Web proxy and public access** card at the bottom of
the Websites page:

- **Public**: anyone on the internet reaches your sites on ports 80 and 443.
- **Restricted**: ports 80 and 443 are open only to the networks you list. **Use Cloudflare's networks**
  adds Cloudflare's published ranges (they come with the signed catalog, so the panel fetches nothing
  extra); you can add any other network, IPv4 or IPv6, such as another CDN's or your own. The visitor's
  real address is read from the CDN's header only when a request comes from one of those networks.
- **Tunnel**: no port is opened at all. The host connects out to Cloudflare with your tunnel's token,
  and Cloudflare brings visitors in. Paste the token once: the panel stores it encrypted, never shows it
  again, and keeps it off every command line and log. Leave the box empty to keep the saved one. If the
  connector cannot start (a wrong token, or the host cannot reach the internet), the card says so;
  applying again tries at once, even after several failures in a row. An apply waits a few seconds after
  starting the connector and says it did not start when it stopped in that time (Cloudflare refuses a
  wrong token only once the connector has started), and the proxy's status shows the connector's state.

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

The same card has a folded **Security settings** section. Every value can be changed; OWASP's
recommended value is printed beside the field, and a value outside it shows a note but is still saved.

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

## Domains and certificates

On a site's **Domains** tab, add a domain and the page shows the exact DNS records to create at your
domain's provider (an A record and, when the host has IPv6, an AAAA record). Press **Check again** once
they are in place. The panel looks the domain up and compares the answer with the host's address; it
never connects to the domain itself. A domain that points at a private address is refused.

Certificates come from Let's Encrypt automatically, for the domains you added and no others.
Let's Encrypt sees your domain names, the host's address and, if you set one, the contact email. A
test service (certificates browsers do not trust) can be chosen in Security settings for trying things
out. A site has at most 5 domains, and at most 3 can be added per hour.

Each domain on the Domains tab shows the certificate the web proxy really serves for it: who issued it
and when it expires (read from the host at most every 5 minutes). A test or local certificate is
marked as one browsers do not trust. A certificate with fewer than 10 days left gets a warning, as does
an expired one. The proxy renews a certificate once a third of its lifetime is left, so a warning means
renewal has been failing for days, usually because ports 80 and 443 do not reach the host.

## Files

The **Files** tab is a file manager for the site's folder: browse, edit, upload, rename, delete, and
**Upload archive and extract** (zip or tar.gz). An archive is checked before anything is unpacked:
nothing may land outside the site's folder, links and device files are refused, and the unpacked size
is capped. The same folder appears in the panel's [SFTP service](sftp.md#websites) for users who may
change the site's files. The site's disk limit counts this folder, its backups and its settings, not the
container images the panel keeps for it ([how websites run](websites-runtime.md#disk)).

## PHP

PHP sites and the PHP apps have a **PHP** tab:

- **PHP version**: only versions that PHP still supports with security fixes. When a version reaches the
  end of its support it leaves the catalog, and the tab says so.
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
  by default. The tab shows the address to enter in WordPress's object-cache plugin. Turning it on or off
  starts or removes the cache beside the running site; the site itself is not restarted.
- **Page cache**: the web proxy keeps whole pages for visitors who are not signed in, for the time you
  set. Sign-ins, form posts, any answer that sets a cookie, and admin pages (`/wp-admin`, `/adm`,
  `/admin`) always skip it. **Purge cache** empties it. Off by default.
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
is the one exception: it may reach WordPress's own update servers, so its security updates work. An
administrator can give one site full internet access on its Settings tab, with a warning; even then it
never reaches the host's other services. Plugins and themes for other apps are uploaded through Files.

## Backups and databases

**Backups** holds the site's files and its databases, kept on the host as the site's own account (the
newest 7 by default). Restoring stops the site, takes a safety backup first, then puts the files and
databases back. The **Database** tab creates the site's databases (named `ws<site>_<name>`) and shows
their connection settings on request, which is written to the audit log. Deleting a site (on its Settings
tab) removes its databases and their database user too; if one cannot be removed, nothing else is, and the
site stays offline for another try.

## Access logs

Off by default, for visitors' privacy. When an administrator turns them on for a site, visitor
addresses are shortened before they are kept, and they are kept for the days set in Security settings.
The site's own error log is always readable on its Overview tab.

## Customers

A customer is a panel user whose group holds only website permissions and has their sites in it. They
see only those sites and none of the administrator's controls (limits, putting a site online, deleting
it, full internet access), and cannot see other users, hosts, game servers or other customers' sites.
A customer group can be allowed to add its own sites up to a limit (3 by default). Two-factor sign-in
is required for customers by default. The permissions are in [permissions.md](permissions.md#permissions).
