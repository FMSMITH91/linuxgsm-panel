"""Route modules.

register_routes() was a single 6,430-line function holding 212 handlers — 72% of app.py, and
the reason app.py sat at 46% coverage while the security modules were at 89-94%: a handler you
cannot import is a handler you cannot test in isolation.

Each module here owns one of the sections that function was already divided into by comment, and
exposes `register(app)`. The handlers are MOVED VERBATIM — same bodies, same decorators, same
indentation — so the diff reads as a move rather than a rewrite, and the URL-map snapshot in
tests/url_map_test.py can prove it: 208 rules, their endpoints, methods and guard chains, all
unchanged.

WHY NOT BLUEPRINTS. Flask namespaces blueprint endpoints (`servers.view_logs`, not `view_logs`),
so converting would rename every endpoint and break every url_for() across 27 templates. Modules
that take `app` and keep `@app.route` change no endpoint name at all. url_map_test's own docstring
calls this out; it is the trap this avoids.

WHY `from app import ...` IS NOT CIRCULAR. app.py imports these modules lazily, inside
register_routes(), which runs from create_app() — long after app.py's own module body has
finished. By then every name they ask for exists.

WHAT THE CYCLE DOES COST. It is a cycle to a static analyser even though it is not one at
runtime, and CodeQL cannot follow a use across it. So a module-private name (leading underscore)
defined in app.py and read ONLY from here comes back as py/unused-global-variable: the definition
is visible, the use is not. Seven did, and the count was exact — every such name in app.py was
flagged, while the sixteen equivalents in panel/core/panel_state.py were not, because nothing
imports the route modules from there and so there is no cycle to lose the reference in.

The fix is not to suppress it. If app.py is the only definer and one module here is the only
reader, the state belongs in that module — which is also where it belongs on the merits, since
whatever mutates it lives there. Move it; do not annotate it. Only a name genuinely shared by
several modules is worth keeping central, and panel/core/panel_state.py, which is outside the
cycle, is where those already live.
"""
