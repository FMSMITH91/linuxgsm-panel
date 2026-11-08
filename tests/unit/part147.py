"""Part 147 of the unit suite: the server page says which LinuxGSM release a server is on.

Whether each game server's LinuxGSM is up to date was shown nowhere. /api/server/<id>/version, which the page already fetches once after drawing, now carries
{"release", "latest", "behind"}. Held here:

* hosts.lgsm_versions reads the script's and the modules' release in ONE read, and a failed or
  odd read is (None, None), never a version;
* lgsm_data.latest_release never waits on GitHub: a stale answer starts one background read;
* "behind" only when both releases are known and the server's is older;
* the endpoint carries it, and the page has its line from the first paint.
"""
import os
import time

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, _P9_TRIPPED, _p9_arm, _p9_client, _p9_patch,
                         _p9_patch_sm, _p9_restore_all)
from panel.ops.ssh_manager import _core as _smc147, hosts as _hosts147
from panel.routes import api as _api147
from panel.services import lgsm_data as _lgd147

_TRIP147_START = len(_P9_TRIPPED)
_reads147 = []


def _versions147(answer):
    """hosts.lgsm_versions over a stand-in read answering `answer` (or raising it)."""
    def _read(server, account, sh, timeout=30, selfname=None):
        _reads147.append(sh)
        if isinstance(answer, Exception):
            raise answer
        return answer
    saved = _smc147.read_as_game_user
    _smc147.read_as_game_user = _read
    try:
        return _hosts147.lgsm_versions(None, "u147", "csgoserver")
    finally:
        _smc147.read_as_game_user = saved


_reads147.clear()
check("lgsm_versions: the script's and the modules' release, from one read",
      _versions147(('version="v26.4.0"\nmodulesversion="v26.5.0"\n', "", 0)) == ("v26.4.0", "v26.5.0")
      and len(_reads147) == 1 and "/home/u147/csgoserver" in _reads147[0]
      and "/home/u147/lgsm/modules/core_modules.sh" in _reads147[0], repr(_reads147))
check("lgsm_versions: a missing modules file (grep rc 2) still gives the script's release",
      _versions147(('version="v26.4.0"\n', "grep: no such file", 2)) == ("v26.4.0", None))
check("lgsm_versions: a failed read is (None, None) — empty, a timeout, or a raise",
      _versions147(("", "", 0)) == (None, None) and _versions147(("", "timed out", -1)) == (None, None)
      and _versions147(OSError("ssh down")) == (None, None))
check("lgsm_versions: a value that is not a plain release tag is refused",
      _versions147(('version="v26.4.0; rm -rf ~"\nmodulesversion=master\n', "", 0)) == (None, None))
check("lgsm_versions: no account or script name reads nothing",
      _hosts147.lgsm_versions(None, "", "x") == (None, None))

# ── latest_release: never on the caller's clock ─────────────────────────────────────────────────
_fetches147 = []
_saved_latest147 = dict(_lgd147._latest)
_saved_fetch147 = _lgd147._fetch_latest
try:
    _lgd147._fetch_latest = lambda: (_fetches147.append(1), time.sleep(0.3), "v26.5.0")[2]
    _lgd147._latest.update(tag=None, until=0.0, running=False)
    _t0 = time.monotonic()
    _first147 = _lgd147.latest_release()
    _took147 = time.monotonic() - _t0
    _second147 = _lgd147.latest_release()      # while the first read is still running
    for _ in range(50):
        if not _lgd147._latest["running"]:
            break
        time.sleep(0.05)
    _after147 = _lgd147.latest_release()
    _lgd147._fetch_latest = lambda: None
    _lgd147._latest.update(until=0.0)
    _lgd147.latest_release()
    for _ in range(50):
        if not _lgd147._latest["running"]:
            break
        time.sleep(0.05)
    _kept147 = (_lgd147._latest["tag"], _lgd147._latest["until"] - time.time())
finally:
    _lgd147._fetch_latest = _saved_fetch147
    _lgd147._latest.clear()
    _lgd147._latest.update(_saved_latest147)
check("latest_release: the first call returns at once (None) and reads GitHub in the background",
      _first147 is None and _took147 < 0.2, repr((_first147, _took147)))
check("latest_release: a second call while that read runs starts no second one",
      _second147 is None and len(_fetches147) == 1, repr((_second147, _fetches147)))
check("latest_release: once read, the tag is served", _after147 == "v26.5.0", repr(_after147))
check("latest_release: a failed re-read keeps the last good tag and retries within the hour",
      _kept147[0] == "v26.5.0" and 0 < _kept147[1] <= 3600, repr(_kept147))
check("latest_release: master's linuxgsm.sh line is what it parses (a quoted tag, nothing else)",
      _lgd147._LATEST_VERSION_RE.search('#!/bin/bash\nversion="v26.5.0"\nshortname="core"\n').group(1)
      == "v26.5.0" and _lgd147._LATEST_VERSION_RE.search('version="v26.5.0-rc1"\n') is None)

_script147 = '#!/bin/bash\n# LinuxGSM\n' + "#" * 300 + '\nversion="v26.5.0"\nshortname="core"\n'
check("latest_release: the fetch keeps only a real linuxgsm.sh (a portal page or a body with no version "
      "line is refused before a tag is read from it)",
      _lgd147._looks_like(_lgd147.LATEST_SCRIPT, _script147)
      and not _lgd147._looks_like(_lgd147.LATEST_SCRIPT, "<html>" + "x" * 300 + '\nversion="v26.5.0"\n')
      and not _lgd147._looks_like(_lgd147.LATEST_SCRIPT, _script147.replace('version="v26.5.0"', "")))
_dl147 = []
_saved_dl147 = _lgd147._download
try:
    _lgd147._download = lambda url, name: (_dl147.append((url, name)), (_script147, None))[1]
    _via147 = _lgd147._fetch_latest()
    _lgd147._download = lambda url, name: (None, "HTTP 503")
    _via_fail147 = _lgd147._fetch_latest()
finally:
    _lgd147._download = _saved_dl147
check("latest_release: it goes through the one reviewed downloader, at master's linuxgsm.sh",
      _via147 == "v26.5.0" and _via_fail147 is None and _dl147 == [
          ("https://raw.githubusercontent.com/GameServerManagers/LinuxGSM/master/linuxgsm.sh", "linuxgsm.sh")],
      repr((_via147, _via_fail147, _dl147)))

# ── behind, and the endpoint ─────────────────────────────────────────────────────────────────────
_NS147 = type("_Gs147", (), {"remote": None, "short_name": "csgoserver", "lgsm_name": "csgoserver", "id": 1})


def _info147(release, latest):
    _p9_arm(who="part147")
    _p9_patch_sm("lgsm_versions", lambda remote, account, selfname: (release, "v26.5.0"))
    _p9_patch(_lgd147, "latest_release", lambda: latest)
    try:
        return _api147._lgsm_version_info(_NS147())
    finally:
        _p9_restore_all()


check("behind: an older release than LinuxGSM's latest is behind",
      _info147("v26.4.0", "v26.5.0") == {"release": "v26.4.0", "latest": "v26.5.0", "behind": True})
check("behind: the latest, or a newer one, is not",
      _info147("v26.5.0", "v26.5.0")["behind"] is False and _info147("v26.10.0", "v26.5.0")["behind"] is False)
check("behind: an unread release or an unread latest is never reported as out of date",
      _info147(None, "v26.5.0") == {"release": "", "latest": "v26.5.0", "behind": False}
      and _info147("v26.4.0", None)["behind"] is False)

try:
    # Armed: the closing "nothing reached a real transport" check reads only what an armed tripwire
    # records, and this part never armed it (review 1109 T11).
    _p9_arm(who="part147")
    _p9_patch_sm("game_version", lambda *a, **k: {"reported": "", "build": "", "appid": "",
                                                   "updated": None, "label": "1.5"})
    _p9_patch_sm("lgsm_versions", lambda remote, account, selfname: ("v26.4.0", "v26.4.0"))
    _p9_patch(_lgd147, "latest_release", lambda: "v26.5.0")
    _ep147 = _p9_client(P9_ADMIN).get("/api/server/%d/version" % P9_GS).get_json()
    _p9_patch_sm("lgsm_versions", lambda remote, account, selfname: (_ for _ in ()).throw(OSError("down")))
    _ep_down147 = _p9_client(P9_ADMIN).get("/api/server/%d/version" % P9_GS)
finally:
    _p9_restore_all()
check("version endpoint: it carries the LinuxGSM release beside the game's",
      (_ep147 or {}).get("label") == "1.5"
      and (_ep147 or {}).get("lgsm") == {"release": "v26.4.0", "latest": "v26.5.0", "behind": True},
      repr(_ep147))
check("version endpoint: a LinuxGSM read that raises still answers 200, with no release",
      _ep_down147.status_code == 200 and (_ep_down147.get_json() or {}).get("lgsm", {}).get("release") == "",
      repr((_ep_down147.status_code, _ep_down147.get_json())))

with open(os.path.join(_root, "panel", "templates", "server_detail.html"), encoding="utf-8") as _fh147:
    _tpl147 = _fh147.read()
with open(os.path.join(_root, "panel", "static", "js", "server_detail.js"), encoding="utf-8") as _fh147:
    _js147 = _fh147.read()
check("server page: the LinuxGSM line is there from the first paint, with a dash to fill in",
      '<span id="lgsm-version" data-no-i18n>&mdash;</span>' in _tpl147
      and 'id="lgsm-behind" class="text-warning d-none"' in _tpl147)
check("server page: the version fetch fills it in", "_showLgsmVersion(d && d.lgsm);" in _js147
      and "tf('{latest} available', {latest: info.latest})" in _js147)
check("part147: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP147_START, repr(_P9_TRIPPED[_TRIP147_START:]))
