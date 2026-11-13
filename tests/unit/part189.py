"""Part 189 of the unit suite: checks that read what their titles name.

Held here:
* The host traffic part (177) renders a server page with both background resolvers stubbed on the
  names the page looks up, so no lookup thread outlives the part's stubs.
* Every DEFAULT_CONFIG key has a real read somewhere under panel/ (a `.get("key")` or a `["key"]`
  load), not just its name inside another name.

HOW IT RUNS. Each check reads what an earlier part recorded, or drives the panel's own code with every
host call stubbed. Nothing reaches a host or data/.
"""
import ast as _ast189
import glob as _glob189
import os as _os189

from unit.part01 import check
from unit.part05 import _root
from unit.part177 import _g177
from panel.core import config as _cfgmod189

# ── 1. part177's server page: both background lookups answered by the stubs ───────────────────────
_r42t_res177 = list(_g177.get("resolvers") or [])
check("host traffic part: the server page it renders asks the stubbed public-IP and timezone lookups "
      "(neither starts a thread that reaches the fixture host after the part's stubs are gone)",
      sorted(set(_r42t_res177)) == ["public_ip", "timezone"]
      and getattr(_g177.get("spage"), "status_code", 0) == 200, repr((_r42t_res177, _g177.get("spage"))))


# ── 2. every DEFAULT_CONFIG key has a reader: a real read, not a substring ───────────────────────
def _r42t_cfg_reads(sources, keys):
    """{key: ["file:line", …]} of each `.get("key", …)` call and each `x["key"]` load in `sources`.

    `sources` is {name: text}. A key's name inside another name, a comment, a bare string or a
    store (`cfg["key"] = v`) is not a read.
    """
    found = {k: [] for k in keys}
    for name, text in sources.items():
        for n in _ast189.walk(_ast189.parse(text)):
            key = None
            if isinstance(n, _ast189.Subscript) and isinstance(n.ctx, _ast189.Load) \
                    and isinstance(n.slice, _ast189.Constant):
                key = n.slice.value
            elif isinstance(n, _ast189.Call) and getattr(n.func, "attr", "") == "get" and n.args \
                    and isinstance(n.args[0], _ast189.Constant):
                key = n.args[0].value
            if isinstance(key, str) and key in found:
                found[key].append("%s:%d" % (name, n.lineno))
    return found


def _r42t_panel_sources():
    """{relative path: text} of every .py under panel/ but config.py, which defines the defaults."""
    out = {}
    for path in sorted(_glob189.glob(_os189.path.join(_root, "panel", "**", "*.py"), recursive=True)):
        rel = _os189.path.relpath(path, _root)
        if rel != _os189.path.join("panel", "core", "config.py"):
            with open(path, encoding="utf-8") as fh:
                out[rel] = fh.read()
    return out


# Written by the setup wizard (set_config_keys) and listed in the debug report, but nothing decides
# on it: the wizard's lock and is_setup_complete read the SetupState row (route_helpers.py).
_R42T_CFG_WRITTEN_ONLY = {"setup_complete"}
_r42t_cfg_src = _r42t_panel_sources()
_r42t_cfg = _r42t_cfg_reads(_r42t_cfg_src, _cfgmod189.DEFAULT_CONFIG)
_r42t_cfg_none = sorted(k for k, v in _r42t_cfg.items() if not v)
check("config: every DEFAULT_CONFIG key has a reader (a .get(\"key\") or a [\"key\"] read somewhere in "
      "panel/), but the one key the wizard only writes",
      len(_r42t_cfg_src) >= 100 and _r42t_cfg_none == sorted(_R42T_CFG_WRITTEN_ONLY)
      and "set_config_keys(cfg, setup_complete=True)" in _r42t_cfg_src[_os189.path.join("panel", "routes",
                                                                                     "route_helpers.py")],
      repr((len(_r42t_cfg_src), _r42t_cfg_none)))
_r42t_cfg_ctl = _r42t_cfg_reads(
    {"ctl": "def _attach_debug_logging():\n    pass  # debug_log\nx = 'debug_log'\ncfg['debug_log'] = 1\n"
            "y = cfg['port']\nz = cfg.get('ssh_timeout', 10)\n"}, ("debug_log", "port", "ssh_timeout"))
check("config reader gate: a key inside another name, a comment, a bare string or a store is no read, "
      "and a [\"key\"] load and a .get(\"key\") are (control)",
      _r42t_cfg_ctl == {"debug_log": [], "port": ["ctl:5"], "ssh_timeout": ["ctl:6"]}, repr(_r42t_cfg_ctl))
