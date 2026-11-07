# Vendored front-end libraries

These ship with the panel instead of being loaded from a CDN: the panel is designed to run on a
tailnet with no outbound internet, under a strict CSP with no third-party origins. Nothing updates
them automatically.

| Library | Version | File | Upstream |
|---|---|---|---|
| Bootstrap (JS) | 5.3.3 | `bootstrap/bootstrap.bundle.min.js` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap (CSS) | 5.3.3 | `bootstrap/bootstrap.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap Icons | 1.11.3 | `bootstrap-icons/bootstrap-icons.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/ |
| Chart.js | 4.4.1 | `chartjs/chart.umd.min.js` | https://cdn.jsdelivr.net/npm/chart.js/ |
| Socket.IO (client) | 4.8.4 | `socketio/socket.io.min.js` | https://registry.npmjs.org/socket.io-client/-/socket.io-client-4.8.4.tgz |
| xterm.js (JS) | 5.5.0 | `xterm/xterm.min.js` | https://cdn.jsdelivr.net/npm/@xterm/xterm/ |
| xterm.js (CSS) | 5.5.0 | `xterm/xterm.min.css` | https://cdn.jsdelivr.net/npm/@xterm/xterm/ |

This table is the manifest for people. `package.json` and `package-lock.json` beside it are the
manifest for scanners: Dependabot alerts and the dependency audit (osv-scanner in
`security-code.yml`) read the lockfile, since no scanner can read a minified bundle.

- `dependencies` pins each library at the exact version vendored here.
- `overrides` pins a package a bundle carries inside it at the version the bundle was built with:
  `@kurkle/color` 0.3.2 (Chart.js's bundle keeps its banner), `socket.io-parser` 4.2.7 and
  `engine.io-client` 6.6.7 (read from the code), and `@popperjs/core` 2.11.8 (Bootstrap's own
  lockfile at v5.3.3). The Socket.IO bundle's `engine.io-parser` and `@socket.io/component-emitter`
  keep no banner and are recorded at what npm resolves.
- `vendored` maps every file here to its package, the file in that package's npm tarball, and its
  sha256.
- The lockfile also lists engine.io-client's Node-only dependencies (`ws`, `xmlhttprequest-ssl`,
  `debug`), which the browser bundle leaves out: an advisory against one of those is a false alarm
  here.

Unit checks (`tests/unit/part06.py`, `tests/unit/part37.py`) hold all of this together: every file
is listed and matches its sha256, its banner states the version in the table and in `package.json`,
the lockfile resolves it, Bootstrap's JS and CSS are the same release, and the Socket.IO bundle
carries socket.io-parser's fixes for GHSA-677m-j7p3-52f9 and GHSA-2m8v-j782-fhvr. The two JSON
manifests are scanner input, so `.github/update-paths.txt` names them `noise`.

Templates load every file here through `asset_url(...)`, which puts a hash of the bytes in the URL,
because `/static` is served with a week-long `Cache-Control`. The bootstrap-icons font preload is
the one exception: its URL must match the one the stylesheet requests.

xterm.js comes from jsDelivr (the `@xterm/xterm` package) because cdnjs serves it with no banner,
which would leave the version check nothing to read.

## Updating one

1. Take the file from the package's npm tarball (`https://registry.npmjs.org/<name>/-/<name>-<version>.tgz`)
   and check the tarball's sha512 against the `dist.integrity` the registry publishes for that
   version before using anything in it.
2. Replace the file in place — keep the same filename, so no template changes.
3. Update its row in the table above, its version in `package.json`, and its `vendored` sha256.
   If the bundle carries other packages inside it, find the version it actually carries (a banner
   inside the bundle, the code, or the library's own lockfile at its release tag) and set that in
   `overrides`.
4. Regenerate the lockfile in a scratch copy: `npm install --package-lock-only --ignore-scripts`
   beside a copy of `package.json`, then copy `package-lock.json` back.
5. Run `./tools/smoke-local.sh tests/template_actions_test.py` and `./tools/smoke-local.sh tests/unit_test.py`;
   the JS parse gate and these manifest gates run in those two suites.

## Socket.IO client 4.8.4 (2026-10-03)

Taken from `socket.io-client-4.8.4.tgz` on the npm registry, byte-identical to its
`package/dist/socket.io.min.js`. Before use, the tarball's sha512 matched the registry's
`dist.integrity` and the registry's ECDSA signature was verified with the key
`SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U` from `/-/npm/v1/keys`. The bundle speaks
Engine.IO protocol 4 and Socket.IO protocol 5, which the panel's python-socketio 5.x serves.
