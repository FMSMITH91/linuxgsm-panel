"""Boot a throwaway panel for Lighthouse CI.

Marks setup complete (so /login renders instead of redirecting to /setup), creates a minimal
admin, and serves plain HTTP on 127.0.0.1:5000 so headless Chrome in CI can reach it.

IT WRITES THE REAL data/ DIRECTORY, and the guard below is only that no database exists yet. On a
CI runner that is a fresh checkout and the distinction does not arise; run it on a developer
machine to debug the Lighthouse config and it used to permanently flip setup_complete in their
config.json and leave a live superadmin — with a password published in this file — sitting in a
panel.db the panel will happily boot from, since the repo root IS the install layout.

Every sibling harness snapshots config.json and restores it (perf_bench, perf_budget_test,
manage_test). This one does the same now, and removes only what it created.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atexit

from panel.core.config import (CONFIG_FILE, CRED_KEY_FILE, DB_PATH, SECRET_FILE,
                               load_config, save_config)

if DB_PATH.exists():
    print("refusing: a real database exists at %s" % DB_PATH)
    sys.exit(1)

# What was already here BEFORE this script touched anything, so cleanup removes only what it
# created and restores what it edited. Byte-for-byte for config.json: leaving setup_complete=True
# behind in a developer's own config is not "a leftover file", it is a changed install.
_PREEXISTING = {p for p in (SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE) if p.exists()}
_CONFIG_SNAPSHOT = CONFIG_FILE.read_bytes() if CONFIG_FILE in _PREEXISTING else None


@atexit.register
def _cleanup():
    if _CONFIG_SNAPSHOT is not None:
        try:
            CONFIG_FILE.write_bytes(_CONFIG_SNAPSHOT)
        except OSError:
            # Best effort, and this runs at interpreter exit: the data dir may already be gone
            # (a `rm -rf` racing the shutdown), or read-only. Raising here would replace the
            # process's real exit status with a traceback from atexit and restore nothing anyway.
            pass
    for _p in (DB_PATH, DB_PATH.with_name("panel.db-wal"), DB_PATH.with_name("panel.db-shm"),
               SECRET_FILE, CRED_KEY_FILE, CONFIG_FILE):
        if _p in _PREEXISTING or not _p.exists():
            continue
        try:
            _p.unlink()
        except OSError:
            # Same reasoning, per file: one that cannot be removed must not stop the others, and
            # every path here was created by THIS process (anything pre-existing is skipped above).
            pass


# is_setup_complete() needs this flag AND a SetupState row (added below), or every
# page — including /login — funnels into the setup wizard.
cfg = load_config()
cfg["setup_complete"] = True
save_config(cfg)

from app import create_app
from panel.db.models import db, User, SetupState, RemoteServer, GameServer
from panel.security import auth

app = create_app()
with app.app_context():
    if not SetupState.query.first():
        db.session.add(SetupState(step="complete", complete=True))
    if not User.query.filter_by(username="lhci").first():
        db.session.add(User(username="lhci",
                            password_hash=auth.hash_password("Str0ng!passw0rd-lhci"),
                            display_name="LHCI", is_superadmin=True, is_active=True))
    # Seed a host + game server so the dashboard renders a full server card (status
    # badge, Start/Restart/Stop + Console controls) — that's the UI Lighthouse audits.
    if not RemoteServer.query.first():
        r = RemoteServer(name="lhci-host", host="127.0.0.1", port=22,
                         username="root", auth_method="key", auth_credential="")
        db.session.add(r)
        db.session.flush()
        db.session.add(GameServer(remote_id=r.id, name="lhci-cs", short_name="csgoserver",
                                  game_type="csgo", port=27015))
    db.session.commit()

# Plain HTTP (no ssl_args) so Lighthouse's headless Chrome can hit it without cert wrangling.
app.socketio.run(app, host="127.0.0.1", port=5000, debug=False, allow_unsafe_werkzeug=True)
