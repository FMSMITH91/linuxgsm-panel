# Vendored front-end libraries

These ship with the panel instead of being loaded from a CDN: the panel is designed to run on a
tailnet with no outbound internet, and a strict CSP with no third-party origins. The trade is that
nothing updates them automatically: no Dependabot entry and no Renovate manager touches this
directory, and nothing installs from it.

This file is the manifest for people, and `tests/unit_test.py` gates it: every library listed must
exist, and its recorded version must be the one in the file's own banner comment.

`package.json` and `package-lock.json` beside it are the manifest for scanners. Until they existed
no scanner could see this directory at all: the dependency graph had no entry for it, and neither
osv-scanner nor Dependabot alerts could read a minified bundle. That is how the Socket.IO client
sat at 4.7.5, bundling socket.io-parser 4.2.4 with two HIGH advisories against it
(GHSA-677m-j7p3-52f9, GHSA-2m8v-j782-fhvr), with every scanner green. Now the dependency graph
reads the lockfile, so Dependabot alerts cover these packages, and the dependency audit
(`security-code.yml`, osv-scanner) reads it on every pull request, push and week.

- `dependencies` pins each library at the exact version vendored here.
- `overrides` pins the packages a bundle carries inside it, at the version found IN the bundle,
  not the newest one npm would resolve (see the Socket.IO section below for how that was read).
- `vendored` maps every file in this directory to its package, the file inside that package's npm
  tarball it was taken from, and its sha256.
- The lockfile over-approximates on purpose: it also lists engine.io-client's Node-only
  dependencies (`ws`, `xmlhttprequest-ssl`, `debug`), which the browser bundle leaves out. An
  advisory against one of them is a false alarm for this directory; one against anything else is
  not.

`tests/unit/part37.py` holds the two manifests and the files to each other: every file here has a
`vendored` entry and matches its sha256; its banner states exactly the version its package is pinned
at; the lockfile resolves that version; this table agrees; and the Socket.IO bundle carries the
socket.io-parser fixes. A bump is therefore a deliberate change to the file, this table and both
JSON files, and it shows up in review.

| Library | Version | File | Upstream |
|---|---|---|---|
| Bootstrap (JS) | 5.3.3 | `bootstrap/bootstrap.bundle.min.js` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap (CSS) | 5.3.3 | `bootstrap/bootstrap.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap/ |
| Bootstrap Icons | 1.11.3 | `bootstrap-icons/bootstrap-icons.min.css` | https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/ |
| Chart.js | 4.4.1 | `chartjs/chart.umd.min.js` | https://cdnjs.cloudflare.com/ajax/libs/Chart.js/ |
| Socket.IO (client) | 4.8.4 | `socketio/socket.io.min.js` | https://registry.npmjs.org/socket.io-client/-/socket.io-client-4.8.4.tgz |
| xterm.js (JS) | 5.5.0 | `xterm/xterm.min.js` | https://cdn.jsdelivr.net/npm/@xterm/xterm/ |
| xterm.js (CSS) | 5.5.0 | `xterm/xterm.min.css` | https://cdn.jsdelivr.net/npm/@xterm/xterm/ |

## Bootstrap's two halves must match

The JS and CSS ship as one release and are vendored as two files, so they can drift apart — and had:
the JS sat at 5.3.0 against 5.3.3 CSS for months, because each was fetched on a different day and
nothing compared them. They were API-compatible, so nothing was visibly broken; that is precisely
what makes it the kind of drift nobody notices. Both are 5.3.3 now, and the gate requires the two
rows to agree, so the next split fails the build instead of sitting there.

## Updating one

1. Take the file from the package's npm tarball (`https://registry.npmjs.org/<name>/-/<name>-<version>.tgz`)
   and check the tarball's sha512 against the `dist.integrity` the registry publishes for that
   version before using anything in it.
2. Replace the file in place — keep the same filename, so no template changes.
3. Update its row in the table above, its version in `package.json`, and its `vendored` sha256.
   If the bundle carries other packages inside it, find the version it actually carries and set
   that in `overrides`.
4. Regenerate the lockfile in a scratch copy: `npm install --package-lock-only --ignore-scripts`
   beside a copy of `package.json`, then copy `package-lock.json` back.
5. Run `./tools/run-tests.sh`; the JS parse gate and these manifest gates all run.

## Socket.IO client 4.8.4 (2026-10-03)

Taken from `socket.io-client-4.8.4.tgz` on the npm registry. Before use, the tarball's sha512
matched the registry's `dist.integrity` (`sha512-7wjKAvVX…kAA==`) and its sha1 matched `dist.shasum`.
The registry's ECDSA signature over `socket.io-client@4.8.4:<integrity>` was also verified, with
the key `SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U` from `/-/npm/v1/keys`. The vendored
file is byte-identical to `package/dist/socket.io.min.js` in it.

`package.json` declares `socket.io-parser ~4.2.4`, which says nothing about what the bundle
contains, so the bundle itself was read:

- socket.io-parser 4.2.6 added the `maxAttachments` limit ("too many attachments"), the fix for
  GHSA-677m-j7p3-52f9.
- 4.2.7 refuses a binary packet that declares fewer than one attachment (`n < 1`, was `n < 0`),
  the fix for GHSA-2m8v-j782-fhvr. It also deconstructs a `toJSON()` result when encoding.

All three are in the 4.8.4 bundle and none is in the 4.7.5 one. engine.io-client 6.6.7's new
`transportImplementations` option is in it too, so the bundle carries engine.io-client 6.6.7. Both
versions are what `overrides` records.

Protocols are unchanged. The bundle speaks Engine.IO protocol 4 (`EIO=4`) and Socket.IO protocol 5,
the same as 4.7.5. python-socketio's compatibility table maps JS client 3.x and 4.x to protocol 5,
Engine.IO 4, and python-socketio 5.x. The panel runs python-socketio 5.17.0 and python-engineio
4.14.0.

## xterm.js is two files from one release, like Bootstrap

The host terminal needs a real terminal emulator, not a `<pre>`: anything full-screen — `top`,
`less`, `nano`, a package manager's progress bar — uses cursor addressing and the alternate
screen, which line-oriented rendering cannot show. `panel/core/terminal.py` renders the game
console's one-way log output and is deliberately not used here.

Fetched from jsDelivr rather than cdnjs for a boring reason that matters to the gate above: cdnjs
serves this bundle with no banner at all, so nothing in the file states its own version and the
manifest check has nothing to verify against. jsDelivr prepends `Original file:
/npm/@xterm/xterm@5.5.0/...` to both, which is the same thing that makes the Chart.js row
checkable. The package is `@xterm/xterm` — the project renamed at 5.4, and the old unscoped
`xterm` name on cdnjs stops being the same lineage.
