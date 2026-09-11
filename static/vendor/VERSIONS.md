# Vendored front-end libraries

These ship with the panel instead of being loaded from a CDN: the panel is designed to run on a
tailnet with no outbound internet, and a strict CSP with no third-party origins. The trade is that
nothing updates them automatically — Dependabot covers `pip` and `github-actions` only, and there
is no `package.json` for it to read here.

So this file is the manifest, and `tests/unit_test.py` gates it: every library listed must exist,
and its recorded version must be the one in the file's own banner comment. A bump is therefore a
deliberate two-line change (file + this table) that shows up in review.

| Library | Version | File | Upstream |
|---|---|---|---|
| Bootstrap (JS) | 5.3.0 | `bootstrap/bootstrap.bundle.min.js` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap (CSS) | 5.3.3 | `bootstrap/bootstrap.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap Icons | 1.11.3 | `bootstrap-icons/bootstrap-icons.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/ |
| Chart.js | 4.4.1 | `chartjs/chart.umd.min.js` | https://cdnjs.cloudflare.com/ajax/libs/Chart.js/ |
| Socket.IO (client) | 4.7.5 | `socketio/socket.io.min.js` | https://cdnjs.cloudflare.com/ajax/libs/socket.io/ |

## Known drift

**Bootstrap's JS is 5.3.0 while its CSS is 5.3.3.** They were vendored at different times. The two
are API-compatible, so nothing is broken today — but a split pair is how a component starts
behaving differently from the styles drawn for it, and it is exactly the kind of thing nobody
notices without a manifest. The gate below now *allows* this one pair to differ and says so, so the
day someone bumps one half the mismatch is a deliberate edit rather than an accident.

To fix it, replace `bootstrap/bootstrap.bundle.min.js` with the 5.3.3 bundle from the URL above and
set both Bootstrap rows in the table to the same version; the gate will then require them to match.

## Updating one

1. Download the exact minified file from the upstream URL (pin the version in the path).
2. Replace the file in place — keep the same filename, so no template changes.
3. Update its row in the table above.
4. Run `./tools/run-tests.sh`; the JS parse gate and this manifest gate both run.
