# Serving the panel over HTTPS

**A fresh install already serves HTTPS** with a built-in self-signed cert (option 4 below), so
your login and session cookie are encrypted out of the box; you just see a one-time browser
warning. The options below give a *trusted* cert, best-first. A reverse proxy (`trust_proxy`)
takes over TLS, and so does Tailscale Serve once the panel is bound to `127.0.0.1`.

**Never expose the panel on plain HTTP over the public internet** — your login password and
session cookie would travel in cleartext.

The relevant `data/config.json` settings:

| Setting | Meaning |
|---------|---------|
| `use_https` | Serve HTTPS directly with a built-in self-signed cert |
| `trust_proxy` | You're behind a reverse proxy — trust its `X-Forwarded-*` headers |
| `trusted_proxies` | Which peers count as that proxy — default all of loopback (`127.0.0.0/8` and `::1`); list yours if it is on another machine |
| `trusted_proxy_users` | On loopback, the accounts the proxy may run as — default `www-data`, `nginx`, `http`, `caddy`, `cloudflared` (root and the panel's own account always count) |
| `bind_host` | `127.0.0.1` when behind a proxy, `0.0.0.0` when facing clients directly |
| `site_domain` | The name the panel is reached at: the self-signed cert's name, and an origin the live console accepts. It does not turn on `Secure` cookies |
| `cookie_secure` | Force `Secure` cookies on/off (`true`/`false`). Unset, they are on when the panel is reached over HTTPS: `use_https`, Tailscale Serve, or `trust_proxy` |

---

## 1. Tailscale Serve — easiest & most secure (no domain, no port, no cert)

Built into the panel's setup wizard. Gives a real HTTPS cert on your private
`*.ts.net` MagicDNS name, auto-renewed, reachable only from your devices. **No
open port, nothing to maintain.** If you don't strictly need public access, use
this. (Setup wizard → "Secure access with Tailscale", or **Enable Serve** on the
`/tailscale` page.) Let the panel write the route rather than running `tailscale serve`
yourself: it picks the scheme it is really serving, records the mount, re-points the
route at every start, and removes its own routes at any other mount. A route written by
hand is not managed, so it answers 502 once the panel's scheme changes.

## 2. Cloudflare Tunnel — best for *public* access (no domain of your own, no open port)

A free tunnel that gives a real trusted HTTPS URL, no inbound port, auto-renewed.

First, in `data/config.json`, set `"bind_host": "127.0.0.1"` and `"trust_proxy": true`, and
restart the panel: until then it still serves its own HTTPS, and the tunnel's `http://` cannot
reach it. Then:

```bash
# on the panel host
sudo curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
sudo chmod +x /usr/local/bin/cloudflared
cloudflared tunnel --url http://localhost:5000
```

That is a quick tunnel: no account needed, and it prints a `*.trycloudflare.com` address that
changes every time it starts. For a fixed address, make a named tunnel on your (free) Cloudflare
account (`cloudflared tunnel login`, then Cloudflare's docs). Run `cloudflared` as
root, as the panel's own account, or as an account listed in `"trusted_proxy_users"` — the
panel believes a loopback proxy's `X-Forwarded-For` only from those, since any local account can
connect to 127.0.0.1.

## 3. Reverse proxy with a free domain + Caddy — real cert, auto-renewed

Get a free hostname (e.g. [DuckDNS](https://www.duckdns.org)) pointed at your IP,
open port 443, and let Caddy handle Let's Encrypt automatically:

```
# /etc/caddy/Caddyfile
yourname.duckdns.org {
    reverse_proxy 127.0.0.1:5000
}
```

`config.json`: `"bind_host": "127.0.0.1"`, `"trust_proxy": true`,
`"site_domain": "yourname.duckdns.org"`. Caddy renews the cert forever, untouched.

## 4. Built-in self-signed HTTPS — the default (no domain, no proxy)

This is **on by default** (`"use_https": true`): a **10-year** self-signed cert under
`data/ssl/`, serving `https://<your-ip>:5000` directly, with no renewal and no domain. Set
`"use_https": false` and restart to serve plain HTTP. It stands down behind a reverse proxy
(`trust_proxy`), and behind Tailscale Serve when the panel is bound to `127.0.0.1`; on any other
bind it stays on and Serve reaches it with `https+insecure://`.

**Caveat:** browsers warn that the cert isn't from a trusted CA, and it protects against passive
eavesdropping but not a determined man-in-the-middle. For serious public use prefer options 1–3.

## Bans and blocks behind a proxy or tunnel

**Block IP** and the auto-block deny an address on every port of the panel's host. A panel-login
ban (fail2ban) does too whenever the panel sits behind a proxy, a tunnel or Tailscale; when visitors
connect straight to the panel it covers the panel's port. Whether the firewall sees a visitor
depends on how they reach the panel:

- **Directly, or through Caddy/nginx on this host:** the visitor connects to this host, so the
  firewall drops them, at the proxy's 443 too.
- **Through a Cloudflare Tunnel, Tailscale Funnel or a proxy on another machine:** the visitor
  never connects to this host (`cloudflared` makes an outbound connection to Cloudflare and hands
  each request to `127.0.0.1:5000`), so the firewall never sees their panel requests. The panel
  refuses them itself: a request whose last `X-Forwarded-For` address is banned or blocked gets
  `403 Forbidden`, and that address's open console and terminal connections are closed. This
  covers the panel only: another site served through the same tunnel is not protected by a ban here.
- **Tailscale Serve:** the visitors are your own tailnet devices, which are never banned or blocked.

The login throttle applies in every case: 8 failed attempts in 5 minutes per address (an IPv6
client counts by its /64). Behind Caddy, nginx or a Cloudflare Tunnel it tells visitors apart only
when `trust_proxy` is on and the proxy is one it trusts (`trusted_proxies`, and on loopback root,
the panel's account or a `trusted_proxy_users` account). Otherwise every login counts as the
proxy's own address, so the throttle counts every visitor together and a ban cannot name the one
guessing.
