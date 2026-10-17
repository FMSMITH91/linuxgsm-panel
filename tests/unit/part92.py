"""Part 92 of the unit suite: the debug report's security posture stays on the panel's page.

The owner's decision of 2026-10-16 (review 1015d's A06A07b): the downloadable debug report is the
file the GitHub issue form asks to have attached to a PUBLIC issue, and the issue's account names
the owner. So what tells a reader which defence is weak -- 2FA counts, invites that grant
superadmin, accounts that must change their password but hold an API token, the setup-token file,
the firewall's ways in and default, fail2ban jails that cannot ban -- is shown on the in-panel
report page only. Held here:

* for a fixture with weak posture, the REAL network and access sections' output (and the host
  tools line), assembled, puts none of those lines in the file, the summary or the issue body --
  nor whether UFW is active and fail2ban runs or is installed -- and every one of them in the
  page's posture block; the file's non-posture lines stay, and its header says posture is left out.
* the gate: a planted section that prints posture with add(), or one whose part is not a file
  part, does not reach the file; and no section module prints posture vocabulary with add()/find().
* the page: genDebugReport shows the posture block, and the download holds the report only.

HOW IT RUNS. Module functions with stand-ins set on the module they are read through and put back
in a finally; the page's script in node on this part's own DOM. Nothing reaches a host, sudo or
the checkout's data/.
"""
import ast as _ast92
import contextlib as _ctx92
import os
import pathlib as _pl92
import pwd as _pwd92
import shutil as _sh92
import tempfile as _tf92
import time as _time92
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _root
from unit.part47 import _SETTLE47, _cut47
from unit.part87 import _DOM87, _node87
from panel.ops import debug_report as _dr92
from panel.core import config as _cfg92
from panel.ops import system_ops as _so92
from panel.ops.debug_report import _base as _b92
from panel.ops.debug_report import assemble as _as92
from panel.ops.debug_report import install as _in92
from panel.ops.debug_report import network as _nw92
from panel.ops.debug_report import privacy as _pv92
from panel.ops.debug_report import root_pieces as _rp92
from panel.security import banlist as _bl92

_TMP92 = _tf92.mkdtemp(prefix="p92-")
_UNSET92 = object()


@_ctx92.contextmanager
def _r24r_patched(owner, **attrs):
    """Set attributes on `owner` for the block, and put every one back after it."""
    saved = {k: owner.__dict__.get(k, _UNSET92) for k in attrs}
    for k, v in attrs.items():
        setattr(owner, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is _UNSET92:
                delattr(owner, k)
            else:
                setattr(owner, k, v)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A weak-posture fixture through the real sections, assembled
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UFW92 = ("Status: active\nLogging: on (low)\nDefault: allow (incoming), allow (outgoing), "
          "deny (routed)\nNew profiles: skip\n\nTo                         Action      From\n"
          "--                         ------      ----\n"
          "22/tcp                     ALLOW IN    Anywhere\n"
          "5000/tcp                   ALLOW IN    Anywhere\n")
_JAIL92 = ("Status for the jail: %s\n|- Filter\n|  |- Currently failed:\t0\n|  |- Total failed:\t4\n"
           "|  `- Journal matches:\t_SYSTEMD_UNIT=x\n`- Actions\n   |- Currently banned:\t0\n"
           "   |- Total banned:\t0\n")
_F2B92 = {"status": (0, "Status\n|- Number of jail:\t2\n`- Jail list:\tlinuxgsm-panel, sshd"),
          "panel": (0, _JAIL92 % "linuxgsm-panel"), "sshd": (0, _JAIL92 % "sshd")}
# Three active accounts, two superadmins and NO ONE with 2FA; one must change its password and
# holds an API token; two open invites, one granting superadmin; setup complete.
_COUNTS92 = {"users": [(3, 2, 0, 0, 0, 1, 1, 1)], "invites": [(2, 1)], "sessions": [(1, 0)],
             "setup": [(1,)], "signins": [("login_failed", 2, 5)], "sources": [("public", 2)]}
# What the posture says, each one: none may reach the file, every one must reach the page.
_POSTURE92 = ("**Ways in**", "SSH ALLOW from Anywhere", "panel port 5000: allowed from Anywhere",
              "UFW default incoming", "**2FA on**: superadmins 0/2", "1 grant superadmin",
              "Must change password", "setup token file present", "jails: linuxgsm-panel, sshd",
              "jail (runtime)", "jail file", "**sshd jail**", "can never ban",
              "auth.log handler attached", "which no jail can ban",
              "no failed login reaches fail2ban", "not every superadmin has 2FA",
              "does not watch this install's auth.log", "- **UFW**: active · 2 rules",
              "- **fail2ban**: running", "- **Defence tools installed**: ufw ",
              "**Ban gate (Funnel / remote proxy)**: fail2ban set 0 networks",
              "the ban gate's fail2ban set was never read since boot")
# ...and what the file must not say in any form, the old verdict's wording included.
_ABSENT92 = ("UFW active", "UFW inactive", "fail2ban running", "fail2ban not installed",
             "**UFW**: active", "**fail2ban**: running", "ufw ✓", "ufw ✗", "fail2ban-client ✓",
             "fail2ban-client ✗")
# What the file keeps from those same sections.
_KEPT92 = ("- **Deny-all-ports rules**: ", "- **Host tools**: git ", "Network & security: Tailscale",
           "- **Accounts**: 3 active (2 superadmin, 1 other)", "- **auth.log**: ",
           "- **Sign-ins, 24 h / 7 d**: ")


def _r24r_sections():
    """(network Result, access Result): the real sections on the weak-posture fixture."""
    jail, filt = os.path.join(_TMP92, "jail.conf"), os.path.join(_TMP92, "filter.conf")
    with _r24r_patched(_so92, _panel_login_proxied=lambda: True):
        with open(jail, "w", encoding="utf-8") as fh:
            # The jail file watches another install's auth.log: it can never ban here.
            fh.write(_so92._panel_f2b_jail_body("/elsewhere/auth.log", 5000, [], True))
        with open(filt, "w", encoding="utf-8") as fh:
            fh.write(_so92._panel_f2b_filter_body())
    authlog = os.path.join(_TMP92, "auth.log")
    with open(authlog, "w", encoding="utf-8") as fh:
        fh.write("%s panel login failed from unknown\n"
                 % _time92.strftime("%Y-%m-%d %H:%M:%S", _time92.localtime(_time92.time() - 60)))
    token = _pl92.Path(_TMP92, "setup-token")
    token.write_text("x", encoding="utf-8")
    u = _nw92.ufw_classify(_UFW92, "", 0)
    ctx = NS(app=NS(config={"BOOT_PORT": 5000}))
    with _r24r_patched(_nw92, bounded=lambda c, jobs, reserve=0.5: dict(
            {n: ("timeout", None) for n, _f in jobs}, ufw=("ok", u), sshd=("ok", [22]),
            f2b=("ok", dict(_F2B92))),
            _load_cfg=lambda: ({"port": 5000}, True), auth_log_path=lambda: authlog,
            _db_counts=lambda c: dict(_COUNTS92), _funnel_on=lambda: True,
            _authlog_handler=lambda: False), \
            _r24r_patched(_so92, _F2B_PANEL_JAIL=jail, _F2B_PANEL_FILTER=filt,
                          _panel_login_proxied=lambda: True), \
            _r24r_patched(_cfg92, SETUP_TOKEN_FILE=token), \
            _r24r_patched(_bl92, _f2b=frozenset(),
                          _taken={"f2b": float("-inf"), "ufw": float("-inf")}):
        net, acc = _nw92.section_network(ctx), _nw92.section_access(ctx)
    tools = _b92.Result()
    _rp92._tools_lines(tools)     # read-only: shutil.which over the real PATHs
    return net, acc, tools


def _r24r_assemble(extra=None, sections=None):
    """assemble() over every section: the fixture's network and access, a plain line for the rest."""
    net, acc, tools = _r24r_sections()
    secs = tuple(_dr92.SECTIONS) + tuple(sections or ())
    results = {k: ("ok", 0.01, _b92.Result(lines=["- **%s**: fixture line" % k]))
               for k, _t, _m, _mode, _p in secs}
    results.update(header=("ok", 0.01, _b92.Result(lines=["- **Generated**: fixture"])),
                   network=("ok", 0.01, net), access=("ok", 0.01, acc),
                   root_pieces=("ok", 0.01, tools))
    results.update(extra or {})
    ctx = _b92.Ctx(app=None, deadline_s=20.0)
    with _r24r_patched(_pv92, _tailscale_names=lambda c, st, wait: None), \
            _r24r_patched(_dr92, SECTIONS=secs):
        _pv92.prepare(ctx)
        return _as92.assemble(ctx, results), net, acc


_r92 = {}
try:
    _r92["rep"], _r92["net"], _r92["acc"] = _r24r_assemble()
except Exception as _e92:  # noqa: BLE001 - a harness failure fails by name below
    _r92["error"] = "%s: %s" % (type(_e92).__name__, _e92)
_rep92 = _r92.get("rep") or {}
_file92 = "\n".join(_rep92.get(k) or "" for k in ("report", "summary", "issue_body"))
_page92 = _rep92.get("posture") or ""
check("debug report posture: for a weak-posture fixture, the downloaded file, the summary and the "
      "issue body carry NONE of the posture lines (2FA, invites, must-change-password with a "
      "token, the setup token, ways in, the firewall default, fail2ban jails that cannot ban)",
      bool(_rep92) and not [p for p in _POSTURE92 if p in _file92],
      repr(_r92.get("error") or [p for p in _POSTURE92 if p in _file92]))
check("debug report posture: ...nor, in any wording, whether UFW is active and fail2ban runs or is "
      "installed (the public verdict and the host-tools line included)",
      bool(_rep92) and not [p for p in _ABSENT92 if p in _file92],
      repr(_r92.get("error") or [p for p in _ABSENT92 if p in _file92]))
check("debug report posture: ...and the in-panel page's posture block shows every one of them",
      bool(_page92) and not [p for p in _POSTURE92 if p not in _page92],
      repr(_r92.get("error") or [p for p in _POSTURE92 if p not in _page92]))
check("debug report posture: ...the same sections' non-posture lines stay in the file",
      not [k for k in _KEPT92 if k not in (_rep92.get("report") or "")],
      repr([k for k in _KEPT92 if k not in (_rep92.get("report") or "")]))
check("debug report posture: ...the file's header (and the summary's) says the posture is shown in "
      "the panel and not included, and the page's block says it is not in the download",
      _as92.POSTURE_NOTE in (_rep92.get("report") or "").split("### At a glance", 1)[0]
      and _as92.POSTURE_NOTE in (_rep92.get("summary") or "") and _page92.startswith(_as92.PAGE_HEAD),
      (_rep92.get("report") or "")[:600])
check("debug report posture: ...the sections themselves kept it apart (the file's backstop held "
      "nothing back), and At a glance counts no posture finding",
      _as92.WITHHELD_LINE not in _file92 and "Held back from the file" not in _page92
      and "can never ban" not in _file92 and bool(_r92.get("net"))
      and _r92["net"].page_findings and _r92["acc"].page_findings
      and not [f for f in _r92["net"].findings + _r92["acc"].findings
               if _b92.POSTURE_RE.search(f["text"])],
      repr((_r92.get("net") and _r92["net"].findings, _r92.get("acc") and _r92["acc"].findings)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The gate: a planted posture section never reaches the file
# ════════════════════════════════════════════════════════════════════════════════════════════════
_PLANT92 = ("- **Ways in**: SSH ALLOW from Anywhere (planted-p92)",
            "- **2FA on**: superadmins 0/4 (planted-p92)",
            "- **UFW**: inactive · 0 rules (planted-p92)",
            "- **fail2ban**: not installed (planted-p92)",
            "- Network & security: Tailscale on · UFW inactive · fail2ban not installed (planted-p92)",
            "- **Ban gate (Funnel / remote proxy)**: fail2ban set 0 networks, never (planted-p92)")
_planted92 = _b92.Result(lines=["- **Planted**: a plain line (planted-p92)"] + list(_PLANT92))
_pagesec92 = _b92.Result(lines=["- **Page only**: canary-p92-page"])
_pagesec92.find("warn", "Planted", "canary-p92-finding")
_r92p = {}
try:
    _r92p["rep"] = _r24r_assemble(
        extra={"planted92": ("ok", 0.01, _planted92), "page92": ("ok", 0.01, _pagesec92)},
        sections=(("planted92", "Planted posture", "header", "request", "full"),
                  ("page92", "Planted page section", "header", "request", "page")))[0]
except Exception as _e92:  # noqa: BLE001 - a harness failure fails by name below
    _r92p["error"] = "%s: %s" % (type(_e92).__name__, _e92)
_prep92 = _r92p.get("rep") or {}
_pfile92 = "\n".join(_prep92.get(k) or "" for k in ("report", "summary", "issue_body"))
check("debug report posture gate: a planted 'full' section printing posture with add() does not "
      "reach the file (each line is withheld there) and is shown on the page; its other line stays",
      bool(_prep92) and not [p for p in _PLANT92 if p in _pfile92]
      and all(p in (_prep92.get("posture") or "") for p in _PLANT92)
      and (_prep92.get("report") or "").count(_as92.WITHHELD_LINE) == len(_PLANT92)
      and "a plain line (planted-p92)" in (_prep92.get("report") or ""),
      repr(_r92p.get("error") or [p for p in _PLANT92 if p in _pfile92]))
check("debug report posture gate: ...a section whose part is not a file part ('page') is on the page "
      "only: its lines and findings are in neither the file nor At a glance",
      bool(_prep92) and "canary-p92" not in _pfile92 and "Planted page section" not in _pfile92
      and "canary-p92-page" in (_prep92.get("posture") or "")
      and "canary-p92-finding" in (_prep92.get("posture") or ""),
      repr(_r92p.get("error") or _pfile92[:400]))


def _r25d_report_writer92(node):
    """Is call `node` one that puts text in the report file: add()/find(), or an append to .lines/.findings?"""
    _f = node.func
    if not isinstance(_f, _ast92.Attribute):
        return False
    return _f.attr in ("add", "find") or (
        _f.attr in ("append", "extend", "insert") and isinstance(_f.value, _ast92.Attribute)
        and _f.value.attr in ("lines", "findings"))


def _r25d_str_consts92(tree):
    """The module-level `NAME = "text"` assignments of `tree`."""
    return {n.targets[0].id: n.value.value for n in tree.body
            if isinstance(n, _ast92.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], _ast92.Name)
            and isinstance(n.value, _ast92.Constant) and isinstance(n.value.value, str)}


def _r25d_call_text92(node, consts):
    """The text call `node` is handed: its string literals, and the module constants it names."""
    _out = []
    for a in node.args:
        for n in _ast92.walk(a):
            if isinstance(n, _ast92.Constant) and isinstance(n.value, str):
                _out.append(n.value)
            elif isinstance(n, _ast92.Name) and n.id in consts:
                _out.append(consts[n.id])
            elif isinstance(n, _ast92.Attribute) and n.attr in consts:
                _out.append(consts[n.attr])     # another module's constant, `_base.NAME`
    return " ".join(_out)


def _r24r_add_offenders(src, name, shared=None):
    """[(file, line)] where a section prints posture vocabulary with add()/find(), not posture().

    Also through a module-level string constant, and by appending to the result's lines or findings
    itself (review 1016b: only string literals inside add()/find() were read). `shared` holds every
    debug_report module's constants, so one imported or reached as `module.NAME` is read too
    (review 1016c: only this module's own were).
    """
    tree = _ast92.parse(src)
    consts = dict(shared or {}, **_r25d_str_consts92(tree))
    return [(name, node.lineno) for node in _ast92.walk(tree)
            if isinstance(node, _ast92.Call) and _r25d_report_writer92(node)
            and _b92.POSTURE_RE.search(_r25d_call_text92(node, consts))]


_DRDIR92 = os.path.join(_root, "panel", "ops", "debug_report")
_srcs92 = {}
for _fn92 in sorted(os.listdir(_DRDIR92)):
    if _fn92.endswith(".py"):
        with open(os.path.join(_DRDIR92, _fn92), encoding="utf-8") as _fh92:
            _srcs92[_fn92] = _fh92.read()
_shared92 = {}
for _src92 in _srcs92.values():
    _shared92.update(_r25d_str_consts92(_ast92.parse(_src92)))
_off92 = [_o for _fn92, _src92 in _srcs92.items() for _o in _r24r_add_offenders(_src92, _fn92, _shared92)]
_plantsrc92 = ("def section(ctx):\n    res = Result()\n"
               "    res.add(\"- **Ways in**: SSH %s from %s\" % (a, b))\n"
               "    res.find(\"fail\", AREA, \"the jail \"\n             \"can never ban\")\n"
               "    res.posture(\"- **2FA on**: 0/1\")\n    return res\n"
               "_WAYS = \"- **Ways in**: SSH open\"\ndef other(res):\n    res.add(_WAYS)\n"
               "    res.lines.append(\"- **2FA on**: 0/1\")\n    res.posture(_WAYS)\n"
               "def third(res):\n    res.add(_base.ELSEWHERE)\n    res.add(IMPORTED)\n")
_plantshared92 = {"ELSEWHERE": "- **Ways in**: SSH open", "IMPORTED": "- **2FA on**: 0/1"}
check("debug report posture gate: no debug-report section prints posture vocabulary with add() or "
      "find() (posture() / posture_find() keep it on the page); a planted one is caught, line by line",
      _off92 == [] and _r24r_add_offenders(_plantsrc92, "planted", _plantshared92)
      == [("planted", 3), ("planted", 4), ("planted", 10), ("planted", 11), ("planted", 14), ("planted", 15)],
      repr((_off92, _r24r_add_offenders(_plantsrc92, "planted", _plantshared92))))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The page shows the posture; the download holds the report only
# ════════════════════════════════════════════════════════════════════════════════════════════════
with open(os.path.join(_root, "static", "js", "remote_manage_host.js"), encoding="utf-8") as _fh92:
    _JS92 = _fh92.read()
with open(os.path.join(_root, "templates", "remote_manage.html"), encoding="utf-8") as _fh92:
    _TPL92 = _fh92.read()
_diag92 = _TPL92.split('<div id="diag-report"', 1)[-1].split("{% endif %}", 1)[0]
check("debug report page: the posture block sits in the report card, under the report's own text "
      "(no tab or gate of its own), labelled as not in the download or the issue",
      _diag92.find('id="diag-report-text"') < _diag92.find('id="diag-report-posture-wrap"')
      and 'id="diag-report-posture"' in _diag92 and "{%" not in _diag92
      and "not in the download or the GitHub issue" in _diag92, _diag92[-900:])
_name92 = "debug report page: genDebugReport shows the posture"
_fnsrc92 = (_cut47(_JS92, "function genDebugReport(){") if "function genDebugReport(){" in _JS92
            else "/* MISSING genDebugReport */")
_out92 = _node87(_name92, _DOM87 + _SETTLE47 + (
    "const blobs = [];\n"
    "global.Blob = function(parts){ blobs.push(parts.join('')); };\n"
    "global.URL = {createObjectURL: () => 'blob:x'};\n"
    + (_cut47(_JS92, "function _r24rShowPosture(") if "function _r24rShowPosture(" in _JS92
       else "/* MISSING _r24rShowPosture */") + "\n"
    + _fnsrc92 + "\n"
    "(async () => {\n"
    "  answer({report: 'REPORT-p92', posture: 'POSTURE-p92', summary: 's', issue_body: 'b',\n"
    "          issues_url: 'https://example.invalid/issues/new', filename: 'f.md'});\n"
    "  genDebugReport(); await settle();\n"
    "  const w = document.getElementById('diag-report-posture-wrap');\n"
    "  console.log(JSON.stringify({posture: document.getElementById('diag-report-posture').value,\n"
    "    shown: w.style.display, text: document.getElementById('diag-report-text').value, blobs}));\n"
    "})();\n"))
if _out92 is not None:
    check("debug report page: genDebugReport puts the posture in its own block and shows it; the "
          "report text and the download are the report alone",
          _out92.get("posture") == "POSTURE-p92" and _out92.get("shown") == ""
          and _out92.get("text") == "REPORT-p92" and _out92.get("blobs") == ["REPORT-p92"],
          repr(_out92))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The Tailscale wording matches the helper model (decisions 1016a, builder T)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The panel's account is never the Tailscale operator now, and a current Tailscale lets any local
# account read Serve's status. So an unreadable Serve must not blame the operator role, and the
# head line must flag the account BEING the operator, not the account not being it.
_ts_unr92 = _nw92._serve_text({"serve_unreadable": True}, 5000, None)[0]
check("debug report Tailscale: an unreadable Serve names tailscaled not answering and an old "
      "Tailscale that answers only root, never the operator role, and is not 'no routes'",
      "tailscaled did not answer" in _ts_unr92 and "answer only root" in _ts_unr92
      and "operator" not in _ts_unr92 and "not the same as no routes" in _ts_unr92, _ts_unr92)
_uid92 = os.getuid() or _pwd92.getpwnam("nobody").pw_uid
_me92 = _pwd92.getpwuid(_uid92).pw_name
with _r24r_patched(_nw92, os=NS(geteuid=lambda: _uid92)):
    _op92 = (_nw92._operator_text(_me92), _nw92._operator_text("p92-someone-else"))
check("debug report Tailscale: the panel account as the operator is the flagged anomaly (YES, "
      "released at the next start), another or no operator reads a plain 'no'",
      _op92[0].startswith("YES") and "releases" in _op92[0] and _op92[1] == "no", repr(_op92))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The owner's extension: Funnel, automatic security updates, trust_proxy beyond loopback and the
#    session cookie's flags are posture too (decisions 1016a, pre-merge review lead 1)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _r24r_more_sections():
    """{section key: Result} from the REAL network, config, process and diagnostics code."""
    from flask import Flask as _Flask92
    from panel.ops.debug_report import config_section as _cs92
    from panel.ops.debug_report import diagnostics as _dg92
    from panel.ops.debug_report import process as _pr92
    out = {"network": _b92.Result(), "config": _b92.Result(), "process": _b92.Result()}
    v = {"backend_state": "Running", "funnel_enabled": True, "operator_user": "p92-someone-else",
         "serve_services": [
        {"url": "https://h92.tail0.ts.net", "funnel": True,
         "routes": [{"mount": "/", "target": "http://127.0.0.1:5000"}]}]}
    app = _Flask92("p92more")
    app.config.update(BOOT_PORT=5000, BOOT_BIND="::", BOOT_TLS=False, _TRUST_PROXY=True,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax")
    cfg = dict(_cfg92.DEFAULT_CONFIG, port=5000, trust_proxy=True, tailscale_use_funnel=False,
               tailscale_setup_done=True)
    diag = {"checks": [{"name": "Automatic security updates", "level": "warn", "detail": "off"},
                       {"name": "Disk space", "level": "ok", "detail": "plenty"}]}
    facts = {}
    with _r24r_patched(_nw92, _load_cfg=lambda: (cfg, True)), \
            _r24r_patched(_cfg92, load_config=lambda: cfg), \
            _r24r_patched(_so92, panel_diagnostics=lambda **kw: diag), \
            _r24r_patched(_dg92, shared_integrity=lambda c: None, shared_unit=lambda c: None):
        _nw92._tailscale_lines(NS(app=app), out["network"], facts, ("ok", ("ok", v)))
        with app.test_request_context("/", headers={"Tailscale-Funnel-Request": "?1"},
                                      environ_base={"REMOTE_ADDR": "2001:db8::92"}):
            _nw92._request_lines(out["network"], app.config)
        out["config"] = _cs92.section_config(NS(app=app))
        out["diagnostics"] = _dg92.section_diagnostics(NS(app=app))
        out["process"].add("- **Scheme agreement**: " + _pr92._scheme_line(app.config, cfg)[0])
    out["network"].verdict = "Network & security: Tailscale %s" % facts.get("ts")
    return out


# Each: posture text that must be on the page and nowhere in the file, summary or issue body.
_MORE92 = ("- **Funnel**: config off · Serve says on", "Funnel is ON in Serve but off",
           "- **This request through Tailscale Funnel**: yes", "- **Session cookie**: Secure yes",
           "trust_proxy is on but the panel listens beyond loopback", "- **tailscale_use_funnel**: false",
           "[warn] **Automatic security updates**",
           "- **Tailscale operator**: panel account is the operator: no")
_MOREABS92 = ("Funnel on", "Funnel off", "Tailscale-Funnel-Request", "Session cookie", "cookie Secure",
              "Automatic security updates", "listens beyond loopback", "Secure cookies", "operator")
_rm92 = {}
try:
    _rm92["secs"] = _r24r_more_sections()
    _rm92["rep"] = _r24r_assemble(extra={k: ("ok", 0.01, r) for k, r in _rm92["secs"].items()})[0]
except Exception as _e92:  # noqa: BLE001 - a harness failure fails by name below
    _rm92["error"] = "%s: %s" % (type(_e92).__name__, _e92)
_mrep92 = _rm92.get("rep") or {}
_mfile92 = "\n".join(_mrep92.get(k) or "" for k in ("report", "summary", "issue_body"))
_mpage92 = _mrep92.get("posture") or ""
check("debug report posture: Funnel's state (the line, its findings, this request through Funnel, "
      "the config key, the verdict), the automatic-security-updates check, trust_proxy beyond "
      "loopback, the session cookie's flags and whether the panel account is the Tailscale "
      "operator are on the page and in none of the file, summary or issue body",
      bool(_mrep92) and not [p for p in _MORE92 + _MOREABS92 if p in _mfile92]
      and not [p for p in _MORE92 if p not in _mpage92],
      repr(_rm92.get("error") or ([p for p in _MORE92 + _MOREABS92 if p in _mfile92],
                                  [p for p in _MORE92 if p not in _mpage92])))
check("debug report posture: ...and the sections kept them apart themselves (the backstop held "
      "nothing back), while the mount, the scheme agreement and the other diagnostics stay",
      bool(_mrep92) and _as92.WITHHELD_LINE not in _mfile92
      and "- **Mount**: Serve /, config /" in _mfile92 and "- **Scheme agreement**: process serves "
      "http" in _mfile92 and "**Disk space**: plenty" in (_mrep92.get("summary") or "")
      and "Network & security: Tailscale Running" in _mfile92,
      repr(_rm92.get("error") or _mfile92[-1500:]))
_plmore92 = _b92.Result(lines=["- **Funnel**: config on · Serve says on (planted-p92)",
                               "- **Session cookie**: Secure no (planted-p92)",
                               "- [warn] **Automatic security updates**: off (planted-p92)",
                               "- Network & security: Tailscale Running, Funnel on (planted-p92)",
                               "- **Tailscale**: v1.80 · Running · panel account is the operator: YES (planted-p92)"])
_rpm92 = {}
try:
    _rpm92["rep"] = _r24r_assemble(extra={"planted92": ("ok", 0.01, _plmore92)},
                                   sections=(("planted92", "Planted", "header", "request", "full"),))[0]
except Exception as _e92:  # noqa: BLE001 - a harness failure fails by name below
    _rpm92["error"] = "%s: %s" % (type(_e92).__name__, _e92)
check("debug report posture gate: the backstop (POSTURE_RE) withholds the Funnel, cookie, "
      "security-updates and Tailscale-operator wordings, the old verdict's and the old Tailscale "
      "head line's included, printed by any section with add()",
      bool(_rpm92.get("rep")) and "planted-p92" not in "\n".join(
          (_rpm92["rep"].get(k) or "") for k in ("report", "summary", "issue_body"))
      and (_rpm92["rep"].get("posture") or "").count("planted-p92") == 5,
      repr(_rpm92.get("error") or _rpm92["rep"].get("report", "")[-800:]))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The privilege verdict is posture (the session lead, applying the owner's 2026-10-16 rule)
# ════════════════════════════════════════════════════════════════════════════════════════════════
# "passwordless sudo works for this account, so the helper boundary does not constrain this panel"
# was a line of the install section AND one of the file's public Verdicts (the summary and the
# GitHub issue body): it tells a reader that whoever takes this panel has root. The real
# section_install, on an install where passwordless sudo works (its other two parts stood in for:
# they read the host), assembled: neither the verdict nor the sudo probe it rests on is in the file,
# the summary or the issue body; both are on the page; the helper line stays in the file.
_PRIV92 = ("helper boundary does not constrain", "**Privilege verdict**",
           "**Passwordless `sudo -n true`**: works", "Privilege: ")
_rpv92 = {}
try:
    with _r24r_patched(_so92, _helper_present=lambda: True, _SUDO_PROBE={"at": _time92.time(), "ok": True}), \
            _r24r_patched(_in92, _identity_lines=lambda res, facts: None,
                          _sudo_line=lambda res, facts: None, os=NS(geteuid=lambda: 1000, path=os.path)):
        _secpv92 = _in92.section_install(None)
    _rpv92["rep"] = _r24r_assemble(extra={"install": ("ok", 0.01, _secpv92)})[0]
except Exception as _e92:  # noqa: BLE001 - a harness failure fails by name below
    _rpv92["error"] = "%s: %s" % (type(_e92).__name__, _e92)
_pvrep92 = _rpv92.get("rep") or {}
_pvfile92 = "\n".join(_pvrep92.get(k) or "" for k in ("report", "summary", "issue_body"))
_pvpage92 = _pvrep92.get("posture") or ""
check("debug report posture: the privilege verdict ('passwordless sudo works … the helper boundary "
      "does not constrain this panel') and the sudo probe it rests on are in neither the file, the "
      "summary, the issue body nor the Verdicts block; both are on the page, and the section kept "
      "them apart itself (nothing held back); the helper line stays in the file",
      bool(_pvrep92) and not [p for p in _PRIV92 if p in _pvfile92]
      and all(p in _pvpage92 for p in _PRIV92[:3]) and _as92.WITHHELD_LINE not in _pvfile92
      and "- **Privileged helper installed**: yes" in (_pvrep92.get("report") or ""),
      repr(_rpv92.get("error") or ([p for p in _PRIV92 if p in _pvfile92], _pvpage92[-600:])))
_plpv92 = _b92.Result(lines=["- **Privilege verdict**: planted-p92",
                             "- **Passwordless `sudo -n true`**: works (planted-p92)",
                             "- Privilege: passwordless sudo works for this account, so the helper "
                             + "boundary does not constrain this panel (planted-p92)",
                             "- Privilege: the panel runs as root, so nothing constrains its privileged "
                             + "actions (planted-p92)"])
_rpp92 = {}
try:
    _rpp92["rep"] = _r24r_assemble(extra={"planted92": ("ok", 0.01, _plpv92)},
                                   sections=(("planted92", "Planted", "header", "request", "full"),))[0]
except Exception as _e92:  # noqa: BLE001 - a harness failure fails by name below
    _rpp92["error"] = "%s: %s" % (type(_e92).__name__, _e92)
check("debug report posture gate: ...and the backstop (POSTURE_RE) withholds both lines, and the "
      "old public verdict's wording, when a section prints them with add()",
      bool(_rpp92.get("rep")) and "planted-p92" not in "\n".join(
          (_rpp92["rep"].get(k) or "") for k in ("report", "summary", "issue_body"))
      and (_rpp92["rep"].get("posture") or "").count("planted-p92") == 4,
      repr(_rpp92.get("error") or _rpp92["rep"].get("report", "")[-800:]))

_sh92.rmtree(_TMP92, ignore_errors=True)
