# Run your own ntfy server for phone alerts

The panel can send its alerts to [ntfy](https://ntfy.sh). On the public server, ntfy.sh, a topic is
a public address: anyone who guesses its name can read your alerts. A server of your own, reachable
only over your tailnet, keeps them private, and with the ntfy app from F-Droid no Google service is
involved at all.

This guide puts ntfy on the panel's own host, listening on loopback only, and publishes it to your
tailnet with Tailscale Serve. No port is opened to the internet.

Checked against the ntfy docs ([install](https://docs.ntfy.sh/install/),
[config](https://docs.ntfy.sh/config/), [phone](https://docs.ntfy.sh/subscribe/phone/)) and the
[Tailscale Serve docs](https://tailscale.com/kb/1242/tailscale-serve) on 2026-11-17. If a step
does not match what you see, those pages are the reference.

## 1. Install ntfy (Ubuntu, official apt repository)

```bash
sudo mkdir -p /etc/apt/keyrings
sudo curl -L -o /etc/apt/keyrings/ntfy.gpg https://archive.ntfy.sh/apt/keyring.gpg
sudo apt install apt-transport-https
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/ntfy.gpg] https://archive.ntfy.sh/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/ntfy.list
sudo apt update && sudo apt install ntfy
sudo systemctl enable ntfy && sudo systemctl start ntfy
```

On a 64-bit ARM machine, write `arch=arm64` instead of `arch=amd64`; on 32-bit ARM, `arch=armhf`.

## 2. Configure it

Edit `/etc/ntfy/server.yml`. Replace `<panel-host>.<tailnet>` with your machine's Tailscale name
(shown by `tailscale status`):

```yaml
base-url: "https://<panel-host>.<tailnet>.ts.net"
listen-http: "127.0.0.1:2586"      # loopback only: nothing listens on a public address
behind-proxy: true                 # Tailscale Serve is the proxy in front of it
cache-file: "/var/cache/ntfy/cache.db"
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"    # nobody reads or writes without an account
```

Leave `upstream-base-url` unset: setting it to ntfy.sh forwards poll requests through ntfy.sh to
Firebase and Apple, which is only needed for instant delivery to iPhones (see the last section). Do
not set `firebase-key-file` either.

Then restart: `sudo systemctl restart ntfy`.

## 3. Accounts and a token

Pick a topic name (the panel's Notifications page suggests a long random one). Then:

```bash
sudo ntfy user add --role=user panel          # the panel publishes as this account
sudo ntfy access panel <topic> rw
sudo ntfy token add panel                     # prints the token the panel will use
sudo ntfy user add phone                      # your phone reads as this account
sudo ntfy access phone <topic> ro
```

## 4. HTTPS on your tailnet with Tailscale Serve

```bash
sudo tailscale serve --bg --https=443 127.0.0.1:2586
tailscale serve status
```

Serve gives ntfy a trusted `*.ts.net` certificate and keeps it inside your tailnet. Use Serve, never
Funnel: Funnel would publish it to the internet. To stop it, run the same command with `off` at the
end. If the panel itself is already served on port 443 of this machine, choose another HTTPS port
(for example `--https=8443`) and add `:8443` to `base-url` and to the panel's Server field.

## 5. Your phone

1. Install the Tailscale app and sign in to the same tailnet.
2. Install the ntfy app from **F-Droid**. Its F-Droid build does not use Firebase: every
   subscription is delivered instantly through its own background connection.
3. In the app, add a subscription: topic `<topic>`, server `https://<panel-host>.<tailnet>.ts.net`,
   signed in as `phone`.

## 6. The panel

Notifications → ntfy:

- **Topic**: `<topic>`
- **Server**: `https://<panel-host>.<tailnet>.ts.net` (https, no path)
- **Access token**: the token from step 3
- Tick **My ntfy server is on my own network (LAN, VPN or tailnet)**. Without it the panel refuses
  the tailnet address. The page notes that this is outside the default recommendation; that is
  expected for a server you run yourself.
- Turn ntfy on, **Send test**, then **Save settings**.

## iPhone and iPad

There is no instant, Google-free and Apple-free path to iOS. Without `upstream-base-url`, delivery to
the iOS app can take hours (the ntfy docs). With it, a poll request goes through ntfy.sh to Apple's
push service. The panel's own browser alerts (Account → Alerts on this device) are another option on
an iPhone: they travel encrypted through Apple's push service.
