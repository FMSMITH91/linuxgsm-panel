"""The LinuxGSM Panel application package.

Layered: a package's MODULE-LEVEL imports only reach packages above it in this list,
which is what keeps the import graph acyclic.

    core      primitives (clock, config, i18n, middleware, panel_state, terminal)
    db        models, prefs
    security  auth, privileged
    ops       ssh_manager, system_ops, tailscale_integration, backup
    services  monitoring, notifications, certs, lgsm_data

Two function-local imports cross that grain deliberately, and only at call time:
security/auth reaches ops.ssh_manager for game_engine, and ops/ssh_manager reaches
services.lgsm_data for the dependency list. Written lazily for exactly that reason —
inside a function body they cost nothing at import and cannot make a load-order cycle.
The rule is enforced by a gate in tests/unit_test.py, which knows about these two.

app.py, manage.py and db_maintenance.py stay at the repo root: the systemd unit
execs app.py, recover.sh locates an install by manage.py, and db_maintenance.py is
installed root-owned beside the helper with its path recorded in panel.conf.
"""
from pathlib import Path

# The panel's checkout directory — the one every on-disk path is relative to: data/ (database,
# secret key, credential key, TLS certs), translations/, templates/, static/, VERSION, and the
# git tree that self-update and integrity-repair operate on.
#
# It is anchored HERE, once, and not recomputed from __file__ in each module. Before the modules
# moved into this package they each sat at the root, so `Path(__file__).parent` WAS the panel dir
# and five of them said so independently. Moving the files silently redefined all five — config's
# DATA_DIR became panel/core/data/, which on a live install means the panel boots, finds no
# database, and creates an empty one beside the code while the real data/ sits untouched: a
# factory reset that raises nothing. (It happened here, to a test run, before this existed.)
#
# This file's depth is fixed by definition — panel/__init__.py is always one level below the
# root — so it stays correct however the modules below it are arranged. Anything needing the
# panel directory imports it from here.
REPO_ROOT = Path(__file__).resolve().parent.parent
