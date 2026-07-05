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
  exposing the panel port to the public internet. See [docs/https.md](docs/https.md).
- Keep **two-factor authentication** enabled on admin accounts.
- Keep the install **up to date** — re-running the installer applies the latest fixes.

Thank you for helping keep the project and its users safe.
