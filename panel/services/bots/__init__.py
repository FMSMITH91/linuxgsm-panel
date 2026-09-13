"""The Telegram and Discord command bots.

Lifted out of app.py, where they were 554 lines — the largest coherent block left in it after
register_routes() was split into panel/routes/. They hold no route handlers: every function here
is either a background watch, a transport call, or a command implementation, so nothing about the
URL map is involved and the move is a plain relocation.

WHY THREE MODULES, AND WHY `commands` IS NOT `telegram`. Discord calls twelve of the functions
that were defined in app.py's Telegram section, and Telegram calls none of Discord's. So those
twelve were never Telegram code — they are the shared command layer (find a server, format its
players/console/connect string, act on it), and each bot is a thin transport wrapper around them.
Splitting on that line is what makes `discord.py` short: it is a Gateway socket plus argument
parsing, not a second implementation of the commands.

THE `_tg_*` PREFIX IS GONE FROM `commands.py`. It was a leftover from when Telegram was the only
bot, and it actively lied once Discord ran on the same functions — `_tg_find_server` called from
the Discord router reads like a bug. The move landed first as a byte-for-byte relocation so that
diff stayed reviewable, and the rename followed as its own commit. Names that really are
transport-specific keep their prefix (`_tg_reply`, `_dc_reply`, `_parse_tg_command`, …); only the
shared layer was renamed.

NO DEPENDENCY ON app.py. Everything these need comes from the real module that owns it
(panel.db.models, panel.ops.ssh_manager, panel.core.config, panel.services.notifications, …).
The one exception was `_log`, which is only a logger; each module makes its own under the same
name app.py used, so log output is unchanged.
"""
