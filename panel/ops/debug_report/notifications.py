"""Debug-report section(s): notifications.

Owner: builder B3. channels as booleans, delivery counters, command-bot polling (R63).

settings_for_form() is read for its booleans and counts only. It also returns the Telegram chat id,
the Discord channel id, the command users' ids, the ntfy server URL and the ntfy TOPIC (a capability
secret: whoever knows it can subscribe) verbatim; none of those is printed or kept. The ntfy server
is 'default' or 'custom'; the Discord gateway problem is a close code or 'other'.

The counters come from runtime_stats group "notify", written by panel/services/notifications.py:
  "<channel>|<outcome>"        count: sent / rejected / unreachable / not-configured / failed / error
  "<provider>|last_http"       (time, int HTTP status) of the provider's last rejection
  "telegram_poll|ok|failed"    counts of command-bot polls; "telegram_poll|last_ok" (time, 1);
  "telegram_poll|last_http"    (time, int HTTP status) of the last failed poll that had one
  "queue|dropped"              alerts dropped because the queue was full
"""
import re
import time

from panel.core import runtime_stats
from panel.ops.debug_report._base import Result, ago

AREA = "Notifications"
CHANNELS = ("telegram", "discord", "ntfy")
OUTCOMES = ("sent", "rejected", "unreachable", "not-configured", "failed", "error")


def _onoff(flag):
    return "on" if flag else "off"


def _set(flag):
    return "set" if flag else "not set"


def _count_ids(text):
    return len([x for x in re.split(r"[\s,]+", str(text or "")) if x])


def _gateway(text):
    """Why the Discord command bot is not connected, as a fixed token."""
    if not text:
        return "none"
    m = re.search(r"close code (\d{4})", str(text))
    return "close code %s" % m.group(1) if m else "other"


def _telegram_line(tg):
    return "telegram: %s · token %s · chat %s · commands %s · command users %d" % (
        _onoff(tg.get("enabled")), _set(tg.get("has_token")), _set(tg.get("chat_id")),
        _onoff(tg.get("accept_commands")), _count_ids(tg.get("command_users")))


def _discord_line(dc):
    return ("discord: %s · webhook %s · bot token %s · channel %s · commands %s · command users %d"
            " · gateway problem: %s" % (
                _onoff(dc.get("enabled")), _set(dc.get("has_webhook")), _set(dc.get("has_bot_token")),
                _set(dc.get("channel_id")), _onoff(dc.get("accept_commands")),
                _count_ids(dc.get("command_users")), _gateway(dc.get("gateway_problem"))))


def _ntfy_line(nt, default_server):
    return "ntfy: %s · server %s · topic %s · token %s" % (
        _onoff(nt.get("enabled")), "default" if nt.get("server") == default_server else "custom",
        _set(nt.get("topic")), _set(nt.get("has_token")))


def _settings_lines(res, form, default_server):
    res.add("- " + _telegram_line(form.get("telegram") or {}))
    res.add("- " + _discord_line(form.get("discord") or {}))
    res.add("- " + _ntfy_line(form.get("ntfy") or {}, default_server))
    events = form.get("events") or {}
    th = form.get("thresholds") or {}
    res.add("- Events on: %d of %d · thresholds disk %s%% · load %s%% · mem %s%% · for %s min" % (
        sum(1 for v in events.values() if v), len(events), *(
            int(th[k]) if isinstance(th.get(k), int) else "?"
            for k in ("disk_pct", "load_pct", "mem_pct", "load_mins"))))


def _last(stats, key, now):
    v = stats.get(key)
    if not isinstance(v, tuple):
        return None
    return v[1], ago(now - v[0])


def _channel_delivery(stats, name, now):
    counts = {o: int(stats.get("%s|%s" % (name, o), 0) or 0) for o in OUTCOMES}
    parts = ["%d sent" % counts["sent"]]
    parts += ["%d %s" % (counts[o], o) for o in OUTCOMES[1:] if counts[o]]
    last = _last(stats, "%s|last_http" % name, now)
    if last is not None:
        parts.append("last rejection HTTP %s, %s ago" % (int(last[0]), last[1]))
    return "%s %s" % (name, " / ".join(parts)), counts


def _poll_text(stats, now):
    ok, bad = int(stats.get("telegram_poll|ok", 0) or 0), int(stats.get("telegram_poll|failed", 0) or 0)
    if not ok and not bad:
        return "no poll since start"
    last_ok = _last(stats, "telegram_poll|last_ok", now)
    text = "%d answered, last %s" % (ok, (last_ok[1] + " ago") if last_ok else "never")
    if bad:
        code = _last(stats, "telegram_poll|last_http", now)
        text += " · %d failed polls since start%s" % (bad, (", last HTTP %s%s" % (
            int(code[0]), " (another poller uses this token)" if code[0] == 409 else ""))
            if code else "")
    return text


def _delivery_lines(res, queue_size):
    now = time.time()
    stats = runtime_stats.snapshot("notify")
    texts, rejected = [], False
    for name in CHANNELS:
        text, counts = _channel_delivery(stats, name, now)
        texts.append(text)
        rejected = rejected or counts["rejected"] > 0
    res.add("- Delivery since start: %s · queue %s waiting, %d dropped" % (
        " · ".join(texts), queue_size, int(stats.get("queue|dropped", 0) or 0)))
    res.add("- Telegram command bot: " + _poll_text(stats, now))
    if rejected:
        res.find("warn", AREA, "a notification provider rejected alerts since the process started")
    if int(stats.get("queue|dropped", 0) or 0):
        res.find("warn", AREA, "alerts were dropped because the notification queue was full")
    code = _last(stats, "telegram_poll|last_http", now)
    if code is not None and code[0] == 409:
        res.find("warn", AREA, "the Telegram command bot conflicts with another poller on its token")


def section_notifications(ctx):
    """R63: settings as booleans and counts, delivery and polling counters since start."""
    from panel.services import notifications as nt
    res = Result()
    try:
        form = nt.settings_for_form()
        _settings_lines(res, form, nt.NTFY_DEFAULT_SERVER)
    except Exception as exc:  # noqa: BLE001 - the counters below are still worth printing
        res.add("- notification settings could not be read (%s)" % type(exc).__name__)
        res.find("unread", AREA, "notification settings could not be read")
    try:
        size = nt._alert_queue.qsize()
    except Exception:  # noqa: BLE001
        size = "?"
    _delivery_lines(res, size)
    return res
