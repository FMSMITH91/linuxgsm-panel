"""Part 237 of the unit suite: docs/CHANGELOG.md is grouped by release day.

Every commit on main is a release named by its UTC date (YYYY.M.D, `.N` for a later one that day).
Above the numbered 0.10.0-alpha section, the changelog has one section per release day,
`## [YYYY.M.D] — YYYY-MM-DD`, newest first, each holding only the Keep a Changelog categories in
their usual order. A catch-all section (the old `## [Since 0.10.0-alpha]`) hid which day a change
shipped; this gate keeps it from coming back, and keeps the days in order.
"""
import datetime as _dt237
import os
import re as _re237

from unit.part01 import check, eq

_root237 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DAY237 = _re237.compile(r"\[(\d{4})\.(\d{1,2})\.(\d{1,2})\] — (\d{4})-(\d{2})-(\d{2})")
_CATS237 = ("Added", "Changed", "Fixed", "Security")


def _heading_problems237(title, today, last):
    """(problems, day) for one section heading; day is None when it is not a release day."""
    m = _DAY237.fullmatch(title.strip())
    if not m:
        return ["not a release-day heading: %r" % title[:60]], None
    y, mo, d, y2, mo2, d2 = (int(g) for g in m.groups())
    try:
        day = _dt237.date(y2, mo2, d2)
    except ValueError:
        return ["not a date: %r" % title[:60]], None
    problems = []
    if (y, mo, d) != (y2, mo2, d2):
        problems.append("name and date differ: %r" % title[:60])
    if day > today:
        problems.append("dated in the future: %r" % title[:60])
    if last is not None and day >= last:
        problems.append("not newest first: %r" % title[:60])
    return problems, day


def _category_problems237(title, body):
    """[] when the section's ### headings are Keep a Changelog's, each once, in order."""
    cats = _re237.findall(r"(?m)^### (.+)$", body)
    ok = (cats and all(c in _CATS237 for c in cats) and len(set(cats)) == len(cats)
          and cats == sorted(cats, key=_CATS237.index))
    return [] if ok else ["categories %r under %r" % (cats, title[:30])]


def _day_problems237(text, today):
    """Every way `text`'s release-day sections break the layout above; [] when none."""
    head, sep, _old = text.partition("\n## [0.10.0-alpha]")
    if not sep:
        return ["no 0.10.0-alpha section"]
    sections = head.split("\n## ")[1:]
    if not sections:
        return ["no release-day section"]
    problems, last = [], None
    for sec in sections:
        title, _nl, body = sec.partition("\n")
        found, day = _heading_problems237(title, today, last)
        problems += found
        if day is None:
            continue
        last = day
        problems += _category_problems237(title, body)
    return problems


def _part237():
    with open(os.path.join(_root237, "docs", "CHANGELOG.md"), encoding="utf-8") as f:
        text = f.read()
    today = _dt237.datetime.now(_dt237.timezone.utc).date() + _dt237.timedelta(days=1)   # a merge just past midnight
    eq("changelog: one section per release day above 0.10.0-alpha, `## [YYYY.M.D] — YYYY-MM-DD`, newest "
       "first, with only Added/Changed/Fixed/Security in that order", _day_problems237(text, today), [])
    good = ("# Changelog\n\n## [2026.11.18] — 2026-11-18\n\n### Added\n\n- **A.** a\n\n### Fixed\n\n- **B.** b\n\n"
            "## [2026.11.17] — 2026-11-17\n\n### Security\n\n- **C.** c\n\n## [0.10.0-alpha] — 2026-09-09\n")
    probes = {
        "good": good,
        "catch-all": good.replace("## [2026.11.18] — 2026-11-18", "## [Since 0.10.0-alpha]"),
        "out of order": good.replace("2026.11.17] — 2026-11-17", "2026.11.19] — 2026-11-19"),
        "name differs": good.replace("[2026.11.17] — 2026-11-17", "[2026.11.16] — 2026-11-17"),
        "future": good.replace("2026.11.18] — 2026-11-18", "2026.12.30] — 2026-12-30"),
        "category order": good.replace("### Added\n\n- **A.** a\n\n### Fixed", "### Fixed\n\n- **A.** a\n\n### Added"),
        "odd category": good.replace("### Security", "### Removed"),
    }
    got = {k: not _day_problems237(v, _dt237.date(2026, 11, 20)) for k, v in probes.items()}
    check("changelog: (control) the release-day gate passes a well-formed changelog and fails a catch-all "
          "section, days out of order, a name that is not its date, a future day, categories out of order "
          "or not Keep a Changelog's",
          got == {"good": True, "catch-all": False, "out of order": False, "name differs": False,
                  "future": False, "category order": False, "odd category": False}, repr(got))


_part237()
