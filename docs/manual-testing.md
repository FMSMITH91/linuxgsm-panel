# Manual test checklist

Everything that CI can prove is proven automatically (unit + smoke + lint + CodeQL + security).
This list is the rest — the things that touch **real sshd / fail2ban / UFW / systemd / a browser**,
which the automated tests can't exercise. Work top to bottom: the safe, read-only checks are first;
the ones that can cut off SSH are last and in a deliberate order.

> **Do these on the test VPS first, not production.** And for anything that restarts sshd, keep a
> **second way in open** the whole time — a second SSH session, Tailscale SSH, or the VPS provider's
> web console — so a mistake is never a lockout.

---

## 0. Before you start
- [ ] You can reach the panel in a browser and log in as a super admin.
- [ ] For the SSH sections: a **second SSH session** to the test host is open and you've confirmed it stays alive.

## 1. Browser UX — the "modern web app" changes (safe, quick)
These should all happen **without a full page reload** (watch that the page doesn't flash/scroll to top).
- [ ] **Groups**: add a group, edit it, delete it. → each updates the list in place; a toast appears; no reload.
- [ ] **Users**: add / edit / delete a user. → same; the modal closes, row updates, no reload.
- [ ] **Custom commands**: add / edit / delete a command. → same.
- [ ] **Remotes**: add / edit / test a remote. → same; the "Test" result shows as a toast.
- [ ] **Install a game server** from the Game Servers page. → the row appears with a live progress bar, no reload.
- [ ] **Uninstall a game server**. → a styled dialog asks you to **type the server's username**; OK stays disabled until it matches; on confirm the row disappears in place. *(Expected: this is the ONLY place that asks you to type the username.)*
- [ ] **Delete a remote server**. → a styled dialog asks for **your account password**; a wrong password re-prompts; a right one deletes the card. *(Expected: this is the ONLY place that asks for your password.)*
- [ ] Any **restart/stop with players online** → the in-app dialog (not the browser's grey `confirm()` box) warns and offers "wait until empty".
- [ ] Confirm **no browser `confirm()`/`alert()` boxes** appear anywhere — everything is the styled in-app dialog or a toast.

## 2. Account security
- [ ] **Change your own password** (Account page): needs your **current password**; if 2FA is on, also an **authenticator code**. → new password works on next login; other sessions are signed out but this one stays in.
- [ ] **Enable 2FA**: the backup codes are shown **once**, with a **Download .txt** button. → after leaving the page you can't see them again; regenerating is gone (disable+re-enable to get a fresh set of **8** codes).
- [ ] **Log in with a backup code**: on the 2FA prompt, type a backup code in the same field as the OTP. → it logs you in; the same code fails the second time (one-time).
- [ ] **2FA nag**: as a super admin **without** 2FA, the amber banner shows. "Not now" hides it for the session; "Don't remind me again" hides it permanently (survives reload/login).
- [ ] **Remotes page auth badge**: each host shows Tailscale SSH (green) / SSH key (grey) / Password (amber) with a tooltip.

## 3. fail2ban for the panel login (reversible)
- [ ] On the **panel host** page, find "Brute-force protection for the panel login (fail2ban)". Click **Protect the panel login**.
  - Expected: it installs fail2ban if missing and the status flips to **Active**.
  - Verify on the host: `sudo fail2ban-client status linuxgsm-panel` shows the jail, filter, and log path.
- [ ] From a throwaway IP (e.g. your phone off wifi), fail the panel login **5 times in 10 min**.
  - Expected: that IP gets **banned for an hour**; the panel's status line shows "banning 1 IP".
  - Check: `sudo fail2ban-client status linuxgsm-panel` lists the banned IP.
- [ ] Undo a test ban: `sudo fail2ban-client set linuxgsm-panel unbanip <IP>`.
- [ ] Sanity: `data/auth.log` contains lines like `... panel login failed from <ip>`.

## 4. SSH **port** change — do this before the bind change
Keep your second SSH session open. Test on a **remote** first, then the panel host if you want.
- [ ] Host page → Connection & SSH → **SSH port**. Enter e.g. `2222`, leave Bind address blank, confirm.
  - Expected message: SSH now listens on 2222; the **old port stays open** as a fallback.
- [ ] Verify BOTH work: `ssh -p 2222 user@host` **and** `ssh -p 22 user@host` both connect.
- [ ] Verify fail2ban followed: `sudo fail2ban-client status sshd` shows the new port in its port list.
- [ ] Only after both work: close the old port from the **Firewall** page (delete the `22/tcp` rule).
- [ ] Confirm the panel still manages the host (it now connects on 2222 — check any host action works).
- [ ] Failure path (optional): try a port already in use → it should **revert** and say the old port still works.

## 5. SSH **bind address** change — riskiest, do last
Only bind to an IP the panel **already connects to**. Second session still open.
- [ ] Find the host's IPs: `ip -o -4 addr show | awk '{print $4}'`.
- [ ] SSH port control → set the port (can be the same) and enter a **Bind address** that IS the address the panel uses, confirm.
  - Expected: success; sshd now listens only on that IP; the panel still reaches it.
  - Verify: `ss -lnt | grep <port>` shows it bound to that IP; your second session and a fresh `ssh` both still work.
- [ ] Rollback path (the safety net): set a Bind address that is **NOT** reachable by the panel (e.g. a wrong IP).
  - Expected: the panel **cannot reach it, reverts automatically**, and tells you so — your existing SSH is untouched. This is the important one to confirm.

## 6. Moderation & custom commands (needs a game server + a non-admin account)
- [ ] Make a group with only `kick_player` (no `send_command`), scoped to one server; add a test user to it.
- [ ] As that user: you can **kick** on that server but **can't** open the console or run other commands.
- [ ] As super admin: define a custom command like `say {}`, allow it for a group, scope it to that game/engine.
  - Expected: the command button appears on matching servers for that group; a bad argument (e.g. with `;` or a space) is rejected; a valid one runs.
- [ ] Confirm a server **outside** the group's scope does **not** show the command / denies it.

---

### If something fails
- Locked out of SSH: use your second session / provider console; the panel never removes your current port/binding, so the previous way in still works.
- Locked out of the panel: `sudo linuxgsm-panel-recover` from a shell on the host (reset password, disable 2FA, create admin).
- fail2ban issues: `sudo fail2ban-client status`, and jail files live in `/etc/fail2ban/jail.d/` and `filter.d/`.
