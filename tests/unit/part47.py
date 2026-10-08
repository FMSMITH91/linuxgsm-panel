"""Part 47 of the unit suite: small page behaviours from the 2026-10-08 review, run in node.

Each check runs the page's OWN function, cut out of its script, in node against a few stubs (the
elements it reads, a fetch the check answers), and judges what a user would see:

* the file browser: deleting a folder closes an editor whose file is INSIDE it, as a rename already
  follows one — left open, Save wrote the file back and recreated the deleted folder;
* Garry's Mod content: Apply that fails at the network level draws the card again, not a button left
  disabled under a spinner until a reload;
* Add Remote: the credential field is a password field when the method is Password (it showed the
  host's SSH password in clear), and a text field again for a key path;
* the Install Tailscale button: a double tap sends one install, and a failure lets it be tried again;
* the setup wizard's Tailscale step: an `up` that fails after the install worked offers Check again;
* the Tailscale page: Enter in the Mount Point field enables Serve, and never submits the form (a GET
  reload that lost what was typed);
* the one-time credential dialog: an invite link is shown as an invite link — its own title and
  copy — and the invite route says it is one.
"""
import json as _json47
import os
import re as _re47
import shutil as _shutil47
import subprocess as _sp47  # nosec B404 - runs node on this part's own snippets

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import _p9, _p9_client, _p9_json
from panel.db.models import Invite, User, db
from panel.security import auth as _auth47

_JS47 = os.path.join(_root, "static", "js")
_TPL47 = os.path.join(_root, "templates")


def _read47(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def _cut47(src, head):
    """The statement that starts with `head` — a function declaration or `x = function(){…}` — whole."""
    i = src.index(head)
    depth = 0
    for k in range(src.index("{", i), len(src)):
        depth += {"{": 1, "}": -1}.get(src[k], 0)
        if depth == 0:
            return src[i:k + 1] + (";" if src[i:k + 1].lstrip().startswith("window.") else "")
    return ""


def _node47(prog):
    """Run `prog` in node; its last stdout line as JSON, None without node, {"error": …} on failure."""
    node = _shutil47.which("node")
    if not node:
        return None
    r = _sp47.run([node, "-e", prog], capture_output=True, text=True,  # nosec B603 - node on fixtures
                  timeout=60, check=False)
    try:
        return _json47.loads((r.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-800:]}


_SETTLE47 = "const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };\n"


def _files47():
    src = _read47(_JS47, "server_files.js")
    prog = (_SETTLE47 + "let curFile, curDir = '', closed = 0, answer;\n"
            "function closeEditor(){ closed++; curFile = null; }\n"
            "function browse(){}\nfunction _pathBody(){ return null; }\n"
            "global.MOUNT = ''; global.serverId = 1; global.window = global;\n"
            "global.confirmDialog = o => o.onConfirm();\n"
            "global.fetch = () => Promise.resolve({json: () => Promise.resolve({success: true})});\n"
            + _cut47(src, "function deletePath(") + "\n"
            "(async () => {\n"
            "  const out = {};\n"
            "  for (const [name, open, del, dir] of [['inside', 'serverfiles/cfg/server.cfg', 'serverfiles/cfg', true],\n"
            "      ['same', 'serverfiles/cfg/server.cfg', 'serverfiles/cfg/server.cfg', false],\n"
            "      ['sibling', 'serverfiles/cfgx/server.cfg', 'serverfiles/cfg', true]]) {\n"
            "    curFile = open; closed = 0; deletePath(del, dir); await settle(); out[name] = closed;\n"
            "  }\n"
            "  console.log(JSON.stringify(out));\n"
            "})();\n")
    out = _node47(prog)
    if out is None:
        skip("file browser: deleting a folder closes an editor open inside it", "node is not installed here")
        return
    check("file browser: deleting a folder closes an editor whose file is inside it (Save recreated the "
          "folder), as deleting the file itself does — and not one in a folder that only shares its prefix",
          out.get("inside") == 1 and out.get("same") == 1 and out.get("sibling") == 0, repr(out))


def _gmod47():
    src = _read47(_JS47, "server_detail.js")
    prog = (_SETTLE47 + "let reloads = 0, toasts = [];\n"
            "global.window = global; global.MOUNT = ''; global.serverId = 1;\n"
            "global.toast = (m, k) => toasts.push([m, k]);\n"
            "function loadGmodContent(){ reloads++; }\n"
            + _cut47(src, "function _gmcPost(") + "\n"
            "(async () => {\n"
            "  const out = {};\n"
            "  global.fetch = () => Promise.reject(new Error('network'));\n"
            "  _gmcPost({action: 'mount', games: []}, 'Applying…'); await settle();\n"
            "  out.network = {reloads, toasts: toasts.slice()};\n"
            "  reloads = 0; toasts.length = 0;\n"
            "  global.fetch = () => Promise.resolve({json: () => Promise.reject(new SyntaxError('not json'))});\n"
            "  _gmcPost({action: 'mount', games: []}, 'Applying…'); await settle();\n"
            "  out.notjson = {reloads, toasts: toasts.slice()};\n"
            "  console.log(JSON.stringify(out));\n"
            "})();\n")
    out = _node47(prog)
    if out is None:
        skip("gmod content: a failed Apply redraws the card", "node is not installed here")
        return
    net, bad = out.get("network") or {}, out.get("notjson") or {}
    check("gmod content: an Apply that fails at the network, or answers with a body that is not JSON, says "
          "so and draws the card again (its button was left disabled under a spinner until a reload)",
          net.get("reloads") == 1 and bad.get("reloads") == 1 and net.get("toasts") == [["Request failed", "danger"]],
          repr(out))


def _creds47():
    src = _read47(_JS47, "manage_remotes.js")
    prog = ("const els = {'credential-group': {style: {}}, 'cred-label': {}};\n"
            "global.document = {getElementById: id => els[id] || null};\n"
            "const input = {type: 'text', value: '~/.ssh/id_rsa'};\n"
            "const form = {querySelector: () => input};\n"
            + _cut47(src, "function toggleCreds(") + "\n"
            "const out = {};\n"
            "for (const v of ['password', 'key', 'tailscale', 'password']) {\n"
            "  toggleCreds({value: v, closest: () => form});\n"
            "  out[v + (out[v] ? '2' : '')] = {type: input.type, ac: input.autocomplete, value: input.value};\n"
            "}\n"
            "console.log(JSON.stringify(out));\n")
    out = _node47(prog)
    if out is None:
        skip("Add Remote: a password is typed into a password field", "node is not installed here")
        return
    pw, key, ts = out.get("password") or {}, out.get("key") or {}, out.get("tailscale") or {}
    check("Add Remote: with auth Password the credential is a password field (new-password), so the host's "
          "SSH password is not shown in clear; a key path or Tailscale makes it a text field again",
          pw.get("type") == "password" and pw.get("ac") == "new-password" and pw.get("value") == ""
          and key.get("type") == "text" and key.get("value") == "~/.ssh/id_rsa" and ts.get("type") == "text"
          and (out.get("password2") or {}).get("type") == "password", repr(out))
    tpl = _read47(_TPL47, "manage_remotes.html")
    grp = _re47.search(r'<div class="col-md-2" id="edit-cred-group-\{\{ remote\.id \}\}"[^>]*>', tpl)
    check("Edit remote: the Credential box of a host already on Tailscale SSH is hidden from the start "
          "(only a change of the select hid it, and a preselected option is never changed)",
          grp is not None and "{% if remote.auth_method == 'tailscale' %} style=\"display:none\"{% endif %}"
          in grp.group(0), grp.group(0) if grp else "no edit-cred-group div")


def _ts_install47():
    src = _read47(_JS47, "manage_remotes.js")
    prog = (_SETTLE47 + "let pending = [], posts = 0, removed = 0, inserted = 0, auth = null;\n"
            "global.MOUNT = ''; global.escapeHtml = s => String(s);\n"
            "const logEl = {innerHTML: '', insertAdjacentHTML: () => { inserted++; auth = {remove: () => { removed++; auth = null; }}; }};\n"
            "global.document = {getElementById: id => id === 'install-log' ? logEl : (id === 'ts-install-auth' ? auth : null)};\n"
            "global.fetch = () => { posts++; return new Promise(res => pending.push(res)); };\n"
            "function renderAuthKeyForm(){ return '<form>'; }\n"
            + _cut47(src, "function installTailscale(") + "\n"
            "const answer = async body => { pending.shift()({json: () => Promise.resolve(body)}); await settle(); };\n"
            "(async () => {\n"
            "  const out = {}, btn = {disabled: false};\n"
            "  installTailscale(3, 'vps', btn); installTailscale(3, 'vps', btn);\n"
            "  out.double = {posts, disabled: btn.disabled};\n"
            "  await answer({success: false, message: 'could not get lock'});\n"
            "  out.failed = {disabled: btn.disabled};\n"
            "  installTailscale(3, 'vps', btn); await answer({success: true, message: 'Installed'});\n"
            "  installTailscale(3, 'vps', btn);\n"
            "  out.done = {posts, disabled: btn.disabled, inserted};\n"
            "  const b2 = {disabled: false}; installTailscale(3, 'vps', b2); await answer({success: true, message: 'Installed'});\n"
            "  out.again = {inserted, removed};\n"
            "  console.log(JSON.stringify(out));\n"
            "})();\n")
    out = _node47(prog)
    if out is None:
        skip("Install Tailscale: one install per tap", "node is not installed here")
        return
    check("Install Tailscale: a double tap sends ONE install (two apt runs fought over the dpkg lock); a "
          "failed install can be tried again, a successful one cannot be sent twice, and a second login form "
          "replaces the first rather than duplicating its ids",
          (out.get("double") or {}) == {"posts": 1, "disabled": True}
          and (out.get("failed") or {}).get("disabled") is False
          and (out.get("done") or {}) == {"posts": 2, "disabled": True, "inserted": 1}
          and (out.get("again") or {}) == {"inserted": 2, "removed": 1}, repr(out))


def _ts_setup47():
    src = _read47(_JS47, "setup_tailscale.js")
    prog = (_SETTLE47 + "const out = {}, box = {innerHTML: ''};\n"
            "global.tsEsc = s => String(s); global._da = a => ' data-action=\"' + a + '\"';\n"
            "function tsOut(){ return box; }\n"
            "let reply;\n"
            "function tsApi(){ return reply(); }\n"
            + _cut47(src, "function tsDoUp(") + "\n"
            "(async () => {\n"
            "  reply = () => Promise.resolve({success: false, message: 'timed out'});\n"
            "  tsDoUp(); await settle(); out.refused = box.innerHTML;\n"
            "  reply = () => Promise.reject(new Error('network'));\n"
            "  tsDoUp(); await settle(); out.failed = box.innerHTML;\n"
            "  console.log(JSON.stringify(out));\n"
            "})();\n")
    out = _node47(prog)
    if out is None:
        skip("setup wizard: a failed tailscale up offers Check again", "node is not installed here")
        return
    want = 'data-action="tsRefresh"'
    check("setup wizard, Tailscale step: an `up` that fails or errors after the install worked offers Check "
          "again (the Install button stays disabled once it worked, and nothing else led on)",
          want in (out.get("refused") or "") and "timed out" in (out.get("refused") or "")
          and want in (out.get("failed") or ""), repr(out))


def _ts_serve47():
    src = _read47(_JS47, "tailscale.js")
    prog = ("let enabled = [];\n"
            "function enableServe(b){ enabled.push(b.id); }\n"
            + _cut47(src, "function _tsServeEnter(") + "\n"
            "const btn = {id: 'go', disabled: false};\n"
            "_tsServeEnter({querySelector: () => btn});\n"
            "btn.disabled = true; _tsServeEnter({querySelector: () => btn});\n"
            "_tsServeEnter({querySelector: () => null});\n"
            "console.log(JSON.stringify({enabled}));\n")
    out = _node47(prog)
    if out is None:
        skip("Tailscale page: Enter in Mount Point enables Serve", "node is not installed here")
        return
    tpl = _read47(_TPL47, "tailscale.html")
    form = _re47.search(r'<form id="serve-form"[^>]*>', tpl)
    tag = form.group(0) if form else ""
    check("Tailscale page: Enter in the Mount Point field enables Serve as its button does (once, not while it "
          "runs, and not for a viewer with no button), and the form is never submitted — a GET reload that "
          "dropped the mount and the Funnel choice",
          out.get("enabled") == ["go"] and 'data-action="_tsServeEnter"' in tag and 'data-on="submit"' in tag
          and "data-prevent" in tag, repr((out, tag)))


def _cred_dialog47():
    src = _read47(_JS47, "manage_users.js")
    prog = ("const mk = k => ({kind: k, hidden: k === 'invite', getAttribute: () => k});\n"
            "const parts = [mk('password'), mk('invite'), mk('password'), mk('invite')];\n"
            "const modal = {querySelectorAll: () => parts};\n"
            "const who = {textContent: ''}, pw = {value: '', attrs: {}, setAttribute(k, v){ this.attrs[k] = v; },\n"
            "  getAttribute(k){ return this.attrs[k] || null; }};\n"
            "const els = {'cred-user': who, 'cred-pw': pw, credentialModal: modal};\n"
            "global.window = global; global.document = {getElementById: id => els[id] || null};\n"
            "let shown = 0, copied = [];\n"
            "global.bootstrap = {Modal: function(){ this.show = () => shown++; }};\n"
            "global.copyText = (v, m) => copied.push(m);\n"
            + _cut47(src, "window.showCredential = function") + "\n"
            + _cut47(src, "window.copyCredential = function") + "\n"
            "const out = {};\n"
            "const seen = () => parts.filter(p => !p.hidden).map(p => p.kind);\n"
            "showCredential({username: 'Invite link', password: 'https://x/invite/abc', kind: 'invite'}); copyCredential();\n"
            "out.invite = {seen: seen(), label: pw.attrs['aria-label'], copied: copied.pop()};\n"
            "showCredential({username: 'alice', password: 'pw-123'}); copyCredential();\n"
            "out.password = {seen: seen(), label: pw.attrs['aria-label'], copied: copied.pop(), shown};\n"
            "console.log(JSON.stringify(out));\n")
    out = _node47(prog)
    if out is None:
        skip("credential dialog: an invite link is shown as one", "node is not installed here")
        return
    inv, pwd = out.get("invite") or {}, out.get("password") or {}
    check("credential dialog: an invite link is shown under its own title and copy (not \"One-time password\", "
          "\"reset the password\"), and a password under the password's again after it",
          inv.get("seen") == ["invite", "invite"] and inv.get("label") == "Invite Link"
          and inv.get("copied") == "Link copied" and pwd.get("seen") == ["password", "password"]
          and pwd.get("label") == "One-time password" and pwd.get("copied") == "Password copied"
          and pwd.get("shown") == 2, repr(out))
    tpl = _read47(_TPL47, "manage_users.html")
    modal = tpl[tpl.index('id="credentialModal"'):]
    modal = modal[:modal.index('<div class="modal-footer">')]
    kinds = _re47.findall(r'data-cred-kind="(\w+)"', modal)
    check("credential dialog: the template carries both versions of the copy that differs (title, hint, "
          "warning), the invite's hidden until asked for",
          kinds.count("invite") == 3 and kinds.count("password") >= 3
          and all(" hidden" in t for t in _re47.findall(r'<[^>]*data-cred-kind="invite"[^>]*>', modal)), repr(kinds))


def _invite_route47():
    """POST /users/invite: the credential it hands the page says it is an invite."""
    made = {}
    with _p9.app_context():
        u = User(username="p47_super", password_hash=_auth47.hash_password("Str0ng!passw0rd-p47"),
                 display_name="p47", is_superadmin=True, is_active=True)
        db.session.add(u)
        db.session.commit()
        made["uid"] = u.id
    try:
        c = _p9_client(made["uid"])
        r = c.post("/users/invite", data={"hours": "2", "note": "p47"},
                   headers={"X-Requested-With": "XMLHttpRequest"})
        cred = (_p9_json(r) or {}).get("credential") or {}
        check("invite route: the link it mints comes back marked as an invite (credential.kind), so the page "
              "words it as one", r.status_code == 200 and cred.get("kind") == "invite"
              and "/invite/" in (cred.get("password") or ""), repr((r.status_code, cred)))
    finally:
        with _p9.app_context():
            Invite.query.filter_by(created_by_id=made["uid"]).delete(synchronize_session=False)
            u = db.session.get(User, made["uid"])
            if u is not None:
                db.session.delete(u)
            db.session.commit()


_files47()
_gmod47()
_creds47()
_ts_install47()
_ts_setup47()
_ts_serve47()
_cred_dialog47()
_invite_route47()
