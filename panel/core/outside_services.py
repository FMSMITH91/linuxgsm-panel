"""One switch per outside service the panel calls, read at the place each call is made.

Every service here is ON by default (a missing key is on) and OFF only when config.json holds the
key as exactly `false`, so an older install, a hand-edited file or a key nobody has saved yet keeps
the behaviour it always had. Settings -> Outside services shows one switch per row of SERVICES, the
note beside it saying what stops working when it is off and what the panel uses instead.

The switch is enforced where the request is made (the one function in each service module that
opens the connection), not only in the page, so nothing else in the panel can reach the service
while it is off. docs/PRIVACY.md lists the same services under "What leaves your server".

OWASP User Privacy Protection Cheat Sheet, "Prevent IP Address Leakage" (let the user block
third-party requests) and "Honesty & Transparency"; OWASP Top 10 Privacy Risks P5 (non-transparent
policies) and P10 (collection of data not required for the purpose).
"""
from panel.core.config import config_value

UPDATE_CHECK = "outside_update_check"
LGSM_GITHUB = "outside_lgsm_github"
GAME_ICONS = "outside_game_icons"
STEAM_WORKSHOP = "outside_steam_workshop"
MODRINTH = "outside_modrinth"
PUBLIC_IP = "outside_public_ip"
DBIP = "outside_dbip"
# The breached-password check (Have I Been Pwned's range API) keeps the key it was built with.
BREACH_CHECK = "breach_check_online"

# Marks a post from the Settings form that carries these switches: a save without it (an older
# page still open in a tab) leaves every switch as it is, instead of reading each absent checkbox
# as "off".
FORM_MARKER = "outside_services_form"

# The order is the card's. `confirm`: turning the switch off asks first, because what stops is a
# security control (updates that carry fixes, the breached-password screen). `owasp`: OWASP's
# recommended value, shown beside the switch, with a note (never a refusal) while it is off
# (settings.html).
SERVICES = (
    {"key": UPDATE_CHECK, "label": "Panel update check (GitHub)",
     "note": "Off: no \u201cUpdate available\u201d and no Update button. Update from the shell with install.sh.",
     "confirm": "Turn off the update check? The panel will no longer tell you about new releases, "
                "including security fixes. You can still update from the shell with install.sh.",
     "owasp": "OWASP recommends on."},
    {"key": BREACH_CHECK, "label": "Have I Been Pwned password check (api.pwnedpasswords.com)",
     "note": "Off: new passwords are checked only against the panel's own lists. On: only the first 5 "
             "characters of the password's SHA-1 hash are sent.",
     "confirm": "Turn off the breached-password check? Passwords that appear in public breaches but "
                "not on the panel's own lists will be accepted.",
     "owasp": "OWASP recommends on."},
    {"key": LGSM_GITHUB, "label": "LinuxGSM game list and release notes (GitHub)",
     "note": "Off: the game list comes from the copy already downloaded (a new install has none); no "
             "LinuxGSM release notes."},
    {"key": GAME_ICONS, "label": "Game icons (linuxgsm.com)",
     "note": "Off: icons already downloaded are shown, initials for the rest."},
    {"key": STEAM_WORKSHOP, "label": "Steam Workshop titles (Steam Web API)",
     "note": "Off: Workshop items are listed by id, without titles."},
    {"key": MODRINTH, "label": "Minecraft plugins and datapacks (Modrinth)",
     "note": "Off: no search or install from Modrinth; your own uploads still work."},
    {"key": PUBLIC_IP, "label": "Public address lookup (api.ipify.org, OpenDNS)",
     "note": "Off: a host behind a router shows its own address, not the public one."},
    {"key": DBIP, "label": "Country database for B3 (db-ip.com)",
     "note": "Only for a B3 add-on with offline geolocation: the panel downloads DB-IP's free country database "
             "once a month; no player address is sent. Off: no download, and B3 keeps the copy it has."},
)
KEYS = tuple(s["key"] for s in SERVICES)

OFF_MESSAGE = "This outside service is turned off in Settings → Outside services."


def is_on(value):
    """Whether a stored switch value means on: anything but exactly False (missing is on)."""
    return value is not False


def enabled(key):
    """Whether the outside service `key` may be called now (one stat of config.json, no full load)."""
    return is_on(config_value(key, True))


def form_rows(cfg):
    """The card's rows: each service with `on`, read from `cfg` (load_config's dict)."""
    return [dict(s, on=is_on(cfg.get(s["key"], True))) for s in SERVICES]


def parse_form(form):
    """{key: bool} for every switch in a Settings post, or {} when the post has no switches block."""
    if not form.get(FORM_MARKER):
        return {}
    return {key: bool(form.get(key)) for key in KEYS}


def change_note(cfg, values):
    """The audit detail for the switches `values` changes from `cfg` ("" when none): "<label> off"/"on"."""
    moved = ["%s %s" % (s["label"], "on" if values[s["key"]] else "off") for s in SERVICES
             if s["key"] in values and values[s["key"]] != is_on(cfg.get(s["key"], True))]
    return ("Outside services: " + ", ".join(moved)) if moved else ""
