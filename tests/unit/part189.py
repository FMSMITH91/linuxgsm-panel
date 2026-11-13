"""Part 189 of the unit suite: checks that read what their titles name.

Held here:
* The host traffic part (177) renders a server page with both background resolvers stubbed on the
  names the page looks up, so no lookup thread outlives the part's stubs.

HOW IT RUNS. Each check reads what an earlier part recorded, or drives the panel's own code with every
host call stubbed. Nothing reaches a host or data/.
"""
from unit.part01 import check
from unit.part177 import _g177

# ── 1. part177's server page: both background lookups answered by the stubs ───────────────────────
_r42t_res177 = list(_g177.get("resolvers") or [])
check("host traffic part: the server page it renders asks the stubbed public-IP and timezone lookups "
      "(neither starts a thread that reaches the fixture host after the part's stubs are gone)",
      sorted(set(_r42t_res177)) == ["public_ip", "timezone"]
      and getattr(_g177.get("spage"), "status_code", 0) == 200, repr((_r42t_res177, _g177.get("spage"))))

