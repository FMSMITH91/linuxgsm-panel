# Configuration and deployment

Back to the [README](README.md). Installing and updating: [install.md](install.md). HTTPS options: [https.md](https.md).

## Configuration

Stored in `data/config.json` after the setup wizard. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `port` | 5000 | Web server port |
| `bind_host` | *(auto)* | Bind address — empty picks `127.0.0.1` when Tailscale Serve can proxy, else `0.0.0.0`. Set `127.0.0.1` explicitly behind a proxy |
| `trust_proxy` | false | Trust `X-Forwarded-*` from a reverse proxy |
| `tailscale_control_url` | *(empty: Tailscale)* | A self-hosted control server (Headscale) that new Tailscale joins use, as `https://host[:port]`. Set it on the `/tailscale` page; see [Headscale](#headscale-a-self-hosted-control-server) |
| `trusted_proxies` | `["127.0.0.0/8", "::1"]` | With `trust_proxy`: the addresses (or CIDRs) whose `X-Forwarded-For` is believed. Listing replaces the default — add your proxy here if it is on another machine or in a Docker bridge network |
| `trusted_proxy_users` | `www-data`, `nginx`, `http`, `caddy`, `cloudflared` | With `trust_proxy`, on loopback: the local accounts a proxy may run as (names or uids). Root and the panel's own account always count |
| `session_idle_minutes` | 30 | A normal sign-in ends after this long without use (older installs: `session_lifetime_hours`); an upload still running counts as use, a page's own background checks do not |
| `session_absolute_hours` | 8 | ...or this long after sign-in, however active |
| `remember_days` | 3 | A "Remember me" sign-in signs back in by itself until this many days after sign-in, then asks for the password |
| `step_up_minutes` | 10 | How long a sign-in or password confirmation covers the high-risk actions listed under [Security](security-features.md) (0 = never ask again) |
| `ssh_timeout` | 10 | SSH connection timeout (seconds) |
| `reboot_wait_max_hours` | 24 | How long "reboot when everyone has left" waits before it gives up (0 = no limit) |
| `reboot_restore_no_autostart` | true | After a panel reboot, start again the servers that were running without Autostart |

Branding, the default language, session settings, the two reboot settings, the HTTPS certificate ([https.md](https.md)), the **Schedules** card and the **Outside services** switches are also editable at **Administration → Settings** (superadmin). Outside services has one switch for each service the panel calls by itself (the update check, Have I Been Pwned, LinuxGSM's game list and release notes, game icons, Steam Workshop titles, Modrinth and the public address lookup), each saying what stops working when it is off; alert channels and alert devices have their own switches ([PRIVACY.md](PRIVACY.md)). The panel's `port` and `bind_host` are changed at **Panel Server → Panel binding**, which also updates the firewall; `trust_proxy` stays in `config.json`.

## Production deployment

Run behind **Tailscale** (recommended — tailnet-only, no open ports) or a **reverse proxy**. With a proxy, set `"trust_proxy": true` and `"bind_host": "127.0.0.1"` so the panel serves HTTP to the proxy that terminates TLS. See [docs/https.md](https.md).

For Tailscale Serve, use the setup wizard's Tailscale step or **Enable Serve** on the panel's `/tailscale` page rather than a `tailscale serve` command of your own: the panel then writes the route on the scheme it is actually serving and keeps it pointed at the panel. A route you add by hand is not managed, and on the panel's host such a command needs `sudo`. The `/tailscale` page lists a hand-made route with a **Remove** button.

```nginx
# Reverse proxy — the WebSocket console needs the upgrade headers
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    # The panel reads the LAST X-Forwarded-For hop, the peer nginx appends here, so the client
    # cannot choose its own address. Set both this and X-Real-IP.
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # The firewall's lock-out check reads the port the browser came in on.
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_read_timeout 86400;
}
```

### Headscale (a self-hosted control server)

The panel works with [Headscale](https://headscale.net/stable/) as well as Tailscale's own coordination server. Enter its address under **Control server** on the `/tailscale` page (or, during setup, under *Self-hosted control server* in the Tailscale step), for example `https://headscale.example.com`. Every join the panel runs then passes it as `tailscale up --login-server`: Connect on the panel host, and the login link or auth key for a remote. A host you joined by hand is detected from its own prefs, and remotes follow it while the field is empty.

- **Joining.** The login link opens on your Headscale server, which shows the `headscale auth register` command that approves the machine. For an auth key, create one there with `headscale preauthkeys create --user <USER_ID>`.
- **What Headscale does not offer, the panel does not offer either.** It reads what the control server grants this machine (the same capabilities the `tailscale` command checks):
  - **Serve** needs an HTTPS certificate from the control server. Headscale releases up to 0.29 issue none, so the panel hides Enable Serve and says why; reach the panel at its tailnet address with the panel's own certificate (Settings > HTTPS certificate). A Headscale that issues certificates (`dns.certificates` in its config) is detected and Serve is offered again.
  - **Funnel** is not implemented by Headscale, so the Funnel switch is hidden.
  - **Tailscale SSH** works, under the `ssh` rules of Headscale's own policy.
  - **MagicDNS names** end in Headscale's `dns.base_domain`, not `ts.net`; the panel reads the suffix from the tailnet and uses it wherever it qualifies or recognises a name.
- Headscale uses Tailscale's own address ranges (100.64.0.0/10 and fd7a:115c:a1e0::/48); its docs say other ranges are not supported, and so the panel's tailnet checks stay as they are.
- Use an `https://` address. An `http://` one is accepted, with a warning, for a test setup.
