"""A website's settings forms, checked: PHP values, performance switches, an app's environment variables.

Each check is an allow-list matched whole (OWASP Input Validation Cheat Sheet, "Allowlist vs
Denylist", "Regular Expressions": fullmatch, length bounded first). PHP values are numbers with a
unit in a range, a time zone from the system's list, or On/Off; OWASP's PHP Configuration Cheat Sheet
values ("PHP error handling", "PHP file upload handling", "Some more security paranoid checks") are
returned beside each field for the page to print, with a note (never a refusal) when a value is
outside them. The panel's own hardening lines (expose_php=Off, allow_url_include=Off) follow the
site's lines in the file the runtime layer writes (websites.php_ini), so no field can turn them off.

Environment variables are a secret the app needs in plain text, so they are stored encrypted
(encrypt_secret), written to a 0600 file on the host, never put on a command line, never logged, and
only their names come back to the page (OWASP Secrets Management Cheat Sheet, "Encryption", "8.3
Detection lifecycle": never logged).
"""
import json
import re

from panel.core import i18n

try:
    from zoneinfo import available_timezones
except ImportError:  # pragma: no cover - Python 3.9+ has it
    available_timezones = None

_SIZE_RE = re.compile(r"([1-9][0-9]{0,5})([KMG]?)")
_UNIT = {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
MIB = 1024 ** 2
# field -> (kind, low, high, OWASP's value). Sizes are bytes; "site_mem" / "site_body" are the site's
# own memory and request-body limits.
PHP_FIELDS = {
    "memory_limit": ("size", 16 * MIB, "site_mem", "50M"),
    "upload_max_filesize": ("size", 1 * MIB, "site_body", "2M"),
    "post_max_size": ("size", 1 * MIB, "site_body", "20M"),
    "max_execution_time": ("int", 1, 3600, "60"),
    "max_input_time": ("int", 1, 3600, "60"),
    "max_input_vars": ("int", 100, 100000, "1000"),
    "date.timezone": ("zone", None, None, "UTC"),
    "display_errors": ("onoff", None, None, "Off"),
    # OPcache (on by default for PHP kinds): PHP's own defaults, as OWASP's page names none.
    "opcache.memory_consumption": ("int", 16, 1024, ""),
    "opcache.revalidate_freq": ("int", 0, 3600, ""),
}
INI_MAX_BYTES = 8 * 1024
INI_MAX_LINES = 300
ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
ENV_MAX_VARS = 100
ENV_MAX_VALUE = 4096
ENV_MAX_TOTAL = 32 * 1024
PAGE_TTL = (10, 86400)


def _size(text):
    m = _SIZE_RE.fullmatch(text) if isinstance(text, str) and len(text) <= 8 else None
    return int(m.group(1)) * _UNIT[m.group(2)] if m else None


def _bound(high, site):
    if high == "site_mem":
        return int(site.mem_mb) * MIB
    if high == "site_body":
        return int(site.max_body_mb) * MIB
    return high


def _zone_ok(text):
    if not isinstance(text, str) or len(text) > 64 or not re.fullmatch(r"[A-Za-z0-9_+/-]{1,64}", text):
        return False
    return text == "UTC" or (available_timezones is not None and text in available_timezones())


def _size_problem(key, value, low, high):
    n = _size(value)
    if n is not None and low <= n <= high:
        return None
    return i18n.Sentence("{key} must be a size like 64M, from {low}M to {high}M.", key=key, low=low // MIB, high=high // MIB)


def _int_problem(key, value, low, high):
    ok = isinstance(value, str) and value.isdecimal() and len(value) <= 7 and low <= int(value) <= high
    return None if ok else i18n.Sentence("{key} must be a whole number from {low} to {high}.", key=key, low=low, high=high)


def _field_problem(key, value, site):
    kind, low, high, _owasp = PHP_FIELDS[key]
    if kind == "size":
        return _size_problem(key, value, low, _bound(high, site))
    if kind == "int":
        return _int_problem(key, value, low, high)
    if kind == "zone":
        return None if _zone_ok(value) else i18n.Sentence("{key} must be a time zone name like Europe/Paris.", key=key)
    return None if value in ("On", "Off") else i18n.Sentence("{key} must be On or Off.", key=key)


def php_form(data, site):
    """(the PHP values to store as a dict, [problems]) from the form's fields; only known fields are read."""
    values, problems = {}, []
    for key in PHP_FIELDS:
        if key not in data:
            continue
        value = str(data.get(key) or "").strip()
        problem = _field_problem(key, value, site)
        if problem:
            problems.append(problem)
        else:
            values[key] = value
    return values, problems


def owasp_notes(values):
    """{field: OWASP's value} for each value past OWASP's PHP Configuration Cheat Sheet value (a note, not a refusal)."""
    out = {}
    for key, value in values.items():
        kind, owasp = PHP_FIELDS[key][0], PHP_FIELDS[key][3]
        if not owasp:
            continue
        if kind == "size":
            past = (_size(value) or 0) > (_size(owasp) or 0)
        elif kind == "int":
            past = int(value) > int(owasp)
        else:
            past = kind == "onoff" and value != owasp
        if past:
            out[key] = owasp
    return out


def ini_size_problem(text):
    """A sentence when an Advanced php.ini text is too long to take, else None (the line rules are the runtime's)."""
    if not isinstance(text, str):
        return "The Advanced php.ini must be text."
    if len(text.encode("utf-8", "surrogatepass")) > INI_MAX_BYTES or text.count("\n") >= INI_MAX_LINES:
        return i18n.Sentence("The Advanced php.ini may hold at most {lines} lines and {kb} KB.", lines=INI_MAX_LINES,
                             kb=INI_MAX_BYTES // 1024)
    if "\x00" in text:
        return "The Advanced php.ini must be text."
    return None


def _env_pair_problem(key, value):
    """The sentence refusing one variable, or None."""
    if not isinstance(key, str) or not ENV_KEY_RE.fullmatch(key):
        return "A variable name is a letter or _ then letters, digits and _, at most 64 characters."
    if not isinstance(value, str) or len(value) > ENV_MAX_VALUE or any(c in value for c in "\x00\r\n"):
        return i18n.Sentence("The value of {key} must be one line of at most {n} characters.", key=key, n=ENV_MAX_VALUE)
    return None


def env_problems(env):
    """[problems] with an environment-variable mapping {NAME: value} (empty: it may be stored)."""
    if not isinstance(env, dict):
        return ["Environment variables must be a list of NAME and value pairs."]
    out = [i18n.Sentence("At most {n} environment variables.", n=ENV_MAX_VARS)] if len(env) > ENV_MAX_VARS else []
    bad = next((p for p in (_env_pair_problem(k, v) for k, v in env.items()) if p), None)
    if bad:
        return out + [bad]
    if sum(len(k) + len(v) for k, v in env.items()) > ENV_MAX_TOTAL:
        out.append(i18n.Sentence("The environment variables may hold at most {kb} KB in all.", kb=ENV_MAX_TOTAL // 1024))
    return out


def env_names(enc_text, decrypt):
    """The variable names stored in `enc_text` (encrypted JSON), never their values."""
    try:
        env = json.loads(decrypt(enc_text) or "{}") if enc_text else {}
    except (TypeError, ValueError):
        return []
    return sorted(env) if isinstance(env, dict) else []


def performance_form(data):
    """(changes {column: value}, [problems]) from the Performance card's fields."""
    out, problems = {}, []
    for key in ("opcache", "object_cache", "page_cache", "static_cache"):
        if key in data:
            v = data.get(key)
            out[key] = v is True or str(v).strip().lower() in ("1", "true", "on", "yes")
    if "page_cache_ttl" in data:
        text = str(data.get("page_cache_ttl") or "").strip()
        if text.isdecimal() and len(text) <= 6 and PAGE_TTL[0] <= int(text) <= PAGE_TTL[1]:
            out["page_cache_ttl"] = int(text)
        else:
            problems.append(i18n.Sentence("The page cache time must be {low} to {high} seconds.", low=PAGE_TTL[0],
                                          high=PAGE_TTL[1]))
    return out, problems
