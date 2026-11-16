"""What the panel-wide chat channels (Telegram, Discord, ntfy) are told about people.

The alerts and the bots' replies leave the panel for a third party: Discord and Telegram bot messages
are not end-to-end encrypted, and a topic on a public ntfy server is readable by anyone who guesses its
name. So, by default, an alert carries what happened and where, never who or from which address: no
sign-in IP, no username of someone else, no banned address (OWASP Top 10 Privacy Risks P2 and P10;
OWASP Logging Cheat Sheet, "Data to exclude"). This is the rule Web Push alerts already follow
(push_alerts). The details stay in the panel's Audit log.

The Notifications page has one switch, "Include details (IP addresses, usernames) in chat alerts",
stored as notifications.include_details. It is off unless an admin turns it on, and a config saved
before the switch existed has no such key, so an upgraded panel sends the shorter text too.
"""
import secrets

from panel.core.validation import replace_text_ips

# The alerts whose text names a person or an address: who signed in and from where, the attacked
# account and the attacker's address, a banned IP, the account a change was made to or by.
PERSONAL_EVENTS = frozenset({"admin_login", "admin_bruteforce", "account_locked", "ip_banned",
                             "account_change", "credential_change", "twofa_enforced"})
BRIEF_BODY = "Details are in the panel's Audit log."
ADDRESS_MASK = "[address]"

# A suggested ntfy topic: 24 random characters from the topic alphabet (about 143 bits), which no
# one guesses. ntfy topics are at most 64 characters of [A-Za-z0-9_-].
_TOPIC_PREFIX = "panel-"
_TOPIC_RANDOM_BYTES = 18


def include_details(cfg):
    """Whether the stored notifications settings `cfg` ask for the full alert text in chat."""
    return isinstance(cfg, dict) and cfg.get("include_details") is True


def chat_body(cfg, event_key, body):
    """The body an alert for `event_key` carries to the chat channels under the settings `cfg`."""
    if event_key in PERSONAL_EVENTS and not include_details(cfg):
        return BRIEF_BODY
    return body


def mask_addresses(text):
    """Return `text` with every IPv4 and IPv6 address in it replaced by ADDRESS_MASK.

    Each candidate is parsed first (validation.replace_text_ips), so a clock time is left alone, and
    so is a version number written after a letter ("v1.2.3.4"); a bare 1.40.2.4 is a valid address
    and is masked.
    """
    return replace_text_ips(str(text or ""), lambda _addr: ADDRESS_MASK)


def suggested_topic():
    """A long random ntfy topic that nobody can guess."""
    return _TOPIC_PREFIX + secrets.token_urlsafe(_TOPIC_RANDOM_BYTES)


def ntfy_public_warning(nt):
    """Whether the stored ntfy settings `nt` have no access token, so the topic name is the only lock.

    True for any server, ntfy.sh or self-hosted: without a token, whoever guesses the topic reads it.
    """
    nt = nt if isinstance(nt, dict) else {}
    return not nt.get("token")
