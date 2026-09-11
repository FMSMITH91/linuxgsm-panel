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
| Bootstrap (JS) | 5.3.3 | `bootstrap/bootstrap.bundle.min.js` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap (CSS) | 5.3.3 | `bootstrap/bootstrap.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap Icons | 1.11.3 | `bootstrap-icons/bootstrap-icons.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/ |
| Chart.js | 4.4.1 | `chartjs/chart.umd.min.js` | https://cdnjs.cloudflare.com/ajax/libs/Chart.js/ |
| Socket.IO (client) | 4.7.5 | `socketio/socket.io.min.js` | https://cdnjs.cloudflare.com/ajax/libs/socket.io/ |

## Bootstrap's two halves must match

The JS and CSS ship as one release and are vendored as two files, so they can drift apart — and had:
the JS sat at 5.3.0 against 5.3.3 CSS for months, because each was fetched on a different day and
nothing compared them. They were API-compatible, so nothing was visibly broken; that is precisely
what makes it the kind of drift nobody notices. Both are 5.3.3 now, and the gate requires the two
rows to agree, so the next split fails the build instead of sitting there.

## Updating one

1. Download the exact minified file from the upstream URL (pin the version in the path).
2. Replace the file in place — keep the same filename, so no template changes.
3. Update its row in the table above.
4. Run `./tools/run-tests.sh`; the JS parse gate and this manifest gate both run.
