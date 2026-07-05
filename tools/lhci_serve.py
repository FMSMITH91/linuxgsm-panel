"""Boot a throwaway panel for Lighthouse CI.

Marks setup complete (so /login renders instead of redirecting to /setup), creates
a minimal admin, and serves plain HTTP on 127.0.0.1:5000 so headless Chrome in CI
can reach it. Refuses to run if a real database already exists — like the smoke
test, it only ever touches a fresh, throwaway data dir.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DB_PATH, load_config, save_config

if DB_PATH.exists():
    print("refusing: a real database exists at %s" % DB_PATH)
    sys.exit(1)

# is_setup_complete() needs this flag AND a SetupState row (added below), or every
# page — including /login — funnels into the setup wizard.
cfg = load_config()
cfg["setup_complete"] = True
save_config(cfg)

from app import create_app
from models import db, User, SetupState, RemoteServer, GameServer
import auth

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
