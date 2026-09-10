"""URL-map snapshot — the safety net for moving route code.

`register_routes()` is a 6,516-line function holding 206 routes. Splitting it up is a large,
mechanical change, and the failure mode of a mechanical change is silent: a route that quietly
loses a method, an endpoint that gets renamed (breaking every `url_for()` naming it), a decorator
dropped from a stack during a copy-paste. None of those raise at import; they surface as a 404, a
405, or an unguarded endpoint in production.

So before any of that moves, this pins the app's ENTIRE routing surface — every rule, its endpoint
name, its methods, and the guard chain wrapping its view — to a committed baseline, and fails on
any drift.

Deliberate route changes are expected. When one is intended, regenerate:

    ./tools/smoke-local.sh tests/url_map_test.py --update

and the DIFF in that file's git history is then the reviewable record of what the change did to the
routing surface. Regenerating without reading the diff defeats the entire point.

A note on endpoint names, because it is the trap in this refactor: Flask namespaces blueprint
endpoints (`servers.view_logs`, not `view_logs`), so converting to blueprints renames every
endpoint and breaks every `url_for()` in the templates. Splitting into modules that each take
`app` and keep using `@app.route` does not. This test does not care which is chosen — it just
refuses to let it happen by accident.
"""
import json
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from app import create_app   # noqa: E402

BASELINE = os.path.join(_ROOT, "tests", "url_map_baseline.json")


def _guard_chain(view):
    """Describe the decorators wrapping a view, outermost first.

    functools.wraps copies __name__/__qualname__/__module__ from the inner function onto the
    wrapper, so those all lie about which decorator a layer is. The wrapper's own code object does
    not: __code__.co_name stays the decorator's inner function name ('decorated_view' for
    flask_login, 'decorated_function' for auth.py's), and co_filename says which module defined it.
    Those two, plus the RBAC markers auth.py attaches, identify a layer honestly.
    """
    layers = []
    seen = set()
    fn = view
    while fn is not None and id(fn) not in seen:
        seen.add(id(fn))
        layers.append(fn)
        fn = getattr(fn, "__wrapped__", None)

    chain = []
    for i, fn in enumerate(layers):
        code = getattr(fn, "__code__", None)
        if code is None:
            continue
        if i == len(layers) - 1:
            # The innermost layer is the view itself. Record its NAME only, never its file: this
            # test exists to make moving views between modules safe, so a move must not read as a
            # change. The decorator layers above it keep their filenames, which is where the value
            # is — they live in auth.py and flask_login and are not moving.
            chain.append("view:%s" % code.co_name)
            continue
        layer = "%s:%s" % (os.path.basename(code.co_filename), code.co_name)
        perms = getattr(fn, "_required_perms", None)
        if perms:
            layer += "(%s)" % ",".join(sorted(str(p) for p in perms))
        if getattr(fn, "_checks_server_access", False):
            layer += "[server_access]"
        chain.append(layer)
    return chain


def snapshot(app):
    out = {}
    for rule in app.url_map.iter_rules():
        methods = sorted((rule.methods or set()) - {"HEAD", "OPTIONS"})
        view = app.view_functions.get(rule.endpoint)
        out[str(rule)] = {
            "endpoint": rule.endpoint,
            "methods": methods,
            "guards": _guard_chain(view) if view is not None else ["<missing view>"],
        }
    return out


def main():
    app = create_app()
    with app.app_context():
        current = snapshot(app)

    if "--update" in sys.argv:
        with open(BASELINE, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("url_map_baseline.json rewritten: %d rules. READ THE DIFF." % len(current))
        return 0

    if not os.path.exists(BASELINE):
        print("FAIL  no baseline — run with --update once to create it")
        return 1

    with open(BASELINE, encoding="utf-8") as fh:
        base = json.load(fh)

    problems = []
    for path in sorted(set(base) | set(current)):
        was, now = base.get(path), current.get(path)
        if was is None:
            problems.append("ADDED    %s  (%s)" % (path, now["endpoint"]))
        elif now is None:
            problems.append("REMOVED  %s  (%s)" % (path, was["endpoint"]))
        else:
            for field in ("endpoint", "methods", "guards"):
                if was[field] != now[field]:
                    problems.append("CHANGED  %s  %s\n             was: %s\n             now: %s"
                                    % (path, field, was[field], now[field]))

    print("url map: %d rules checked against the baseline" % len(current))
    if problems:
        print("\nFAIL  the routing surface drifted from tests/url_map_baseline.json\n")
        for p in problems[:40]:
            print("  " + p)
        if len(problems) > 40:
            print("  ... and %d more" % (len(problems) - 40))
        print("\nIf this change was intended, regenerate with --update and read the diff.")
        return 1
    print("PASS  every rule, endpoint, method set and guard chain matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
