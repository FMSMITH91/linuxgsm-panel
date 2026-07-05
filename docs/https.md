# Serving the panel over HTTPS

**Never expose the panel on plain HTTP over the public internet** — your login
password and session cookie would travel in cleartext. Pick one of the options
below. They're listed best-first for a public deployment.

The relevant `data/config.json` settings:

| Setting | Meaning |
|---------|---------|
| `use_https` | Serve HTTPS directly with a built-in self-signed cert |
| `trust_proxy` | You're behind a reverse proxy — trust its `X-Forwarded-*` headers |
| `bind_host` | `127.0.0.1` when behind a proxy, `0.0.0.0` when facing clients directly |
| `site_domain` | Your domain (turns on `Secure` cookies) |
| `cookie_secure` | Force `Secure` cookies on/off regardless of the above |

---

## 1. Tailscale Serve — easiest & most secure (no domain, no port, no cert)

Built into the panel's setup wizard. Gives a real HTTPS cert on your private
`*.ts.net` MagicDNS name, auto-renewed, reachable only from your devices. **No
open port, nothing to maintain.** If you don't strictly need public access, use
this. (Setup wizard → "Secure access with Tailscale".)

## 2. Cloudflare Tunnel — best for *public* access (no domain of your own, no open port)

A free tunnel that gives a real trusted HTTPS URL, no inbound port, auto-renewed.

```bash
# on the panel host
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
chmod +x /usr/local/bin/cloudflared
cloudflared tunnel login          # opens a browser to your (free) Cloudflare account
cloudflared tunnel --url http://localhost:5000
```

Then in `data/config.json`: set `"bind_host": "127.0.0.1"` and `"trust_proxy": true`,
and restart the panel. (For a permanent named tunnel, see Cloudflare's docs.)

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

## 4. Built-in self-signed HTTPS — no domain, no proxy (encrypts, but with a caveat)

For a personal/lab box you just want encrypted. In `data/config.json`:

```json
{ "use_https": true }
```

Restart the panel — it generates a **10-year** self-signed cert under `data/ssl/`
and serves `https://<your-ip>:5000` directly. No renewal, no domain.

**Caveat:** browsers show a "Not secure / proceed anyway" warning (the cert isn't
from a trusted CA), and it protects against *passive* eavesdropping but not a
determined man-in-the-middle. It's strictly better than plain HTTP, but for
serious public use prefer options 1–3, which give real, trusted certificates.
