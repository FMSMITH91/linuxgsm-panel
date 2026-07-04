# Migrating off eventlet (planning notes)

**Status: not urgent. It works today.** This is a plan to reach for when eventlet
finally breaks on a new Python/dependency, or when there's time to do it calmly —
not a change to rush.

## Why

The panel uses [eventlet](https://eventlet.readthedocs.io) for its async model
(green threads) so Flask-SocketIO can stream the live console. Eventlet is now in
**maintenance/bugfix-only mode** and its own docs recommend new projects use
something else. The risk is future-facing: a Python release or a dependency bump
could break eventlet, and it's woven fairly deep (it monkey-patches the whole
standard library at import).

## Where eventlet is used today

| Location | What it does | Migration impact |
|----------|--------------|------------------|
| `app.py` `import eventlet; eventlet.monkey_patch()` (top of file) | Patches stdlib (sockets, threads, subprocess) so blocking calls yield | Replace with the new backend's patcher, or drop it (threading mode) |
| `app.py` `SocketIO(..., async_mode="eventlet")` | The websocket server backend | Change `async_mode` |
| `ssh_manager.py` `from eventlet import tpool` (with a `None` fallback) | Runs **local** subprocess in eventlet's *native* thread pool, because eventlet's green subprocess is unreliable from a request handler | This is the trickiest bit — see below. Already degrades gracefully when eventlet isn't active. |
| `app.py` `_bg_action` / bootstrap "green thread" background jobs | Long LinuxGSM ops run without blocking the request | Any cooperative-threading backend keeps working; threading mode uses real threads |
| `app.py` in-memory login throttle (`_LOGIN_FAILS`) | Brute-force limit | Assumes a **single process**. Any multi-worker deployment (gunicorn -w N) would need a shared store (e.g. Redis) regardless of the async backend |

Note that `ssh_manager` already guards its eventlet import with a `try/except`
and falls back to plain `subprocess` when eventlet isn't active — so `manage.py`
and the tests already run fine without eventlet. That fallback path is the model
for the whole migration.

## Options (in order of preference)

### 1. gevent — the closest drop-in
- `pip install gevent gevent-websocket`, remove eventlet.
- Replace the eventlet monkey-patch with `from gevent import monkey; monkey.patch_all()` at the very top of `app.py` (before any other import).
- `SocketIO(..., async_mode="gevent")`.
- Replace `eventlet.tpool.execute(...)` in `ssh_manager._run_local` with `gevent.threadpool` (`gevent.get_hub().threadpool.apply(fn)`) — same idea, a real OS-thread pool so blocking `subprocess` doesn't stall the hub.
- paramiko works under gevent the same way it does under eventlet.
- **Best balance of effort vs. keeping current concurrency behaviour.**

### 2. threading mode — the simplest
- `SocketIO(..., async_mode="threading")`, **delete** the monkey-patch entirely, delete the eventlet dependency.
- No green threads: each websocket/long-poll and each background job runs on a real OS thread. paramiko/subprocess "just work" (no green-subprocess weirdness — the whole `tpool` dance in `ssh_manager` can be **removed**, simplifying that file).
- Trade-off: fewer simultaneous console viewers before you'd want a real WSGI server. For a self-hosted panel with a handful of admins this is almost certainly fine, and it's the **least code and least magic**.
- If concurrency ever matters, put it behind `gunicorn -k gthread` or gevent workers.

### 3. ASGI rewrite (uvicorn + async Flask/Quart) — not worth it
Large rewrite of every route to `async def`; no real benefit for this workload. Skip.

## Recommendation

When the time comes, try **threading mode (option 2) first** — it removes the most
code and the most fragile part (the green-subprocess workaround), and the panel's
concurrency needs are modest. Keep **gevent (option 1)** as the fallback if you
find you need many concurrent console streams.

## How to test a migration

1. Live console streams from a running game server (websocket connects, lines flow).
2. A long op (`update` / bootstrap) runs in the background without blocking the UI.
3. Concurrent SSH: open two servers' pages at once; both stream.
4. Local (Panel Server) actions still work — this is where the old green-subprocess
   bug lived, so exercise start/stop/console on a *local* game server specifically.
5. `python tests/smoke_test.py` and `python tests/rbac_test.py` still pass.
6. `manage.py list-users` still works (it already runs without eventlet).

## Not part of this migration

The in-memory login throttle and the update-status cache assume a **single
process**. That's independent of the async backend — only revisit it if you ever
run multiple worker processes, in which case move that state to a shared store.
