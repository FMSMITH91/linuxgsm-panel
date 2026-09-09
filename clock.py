"""Time, with one definition of "now".

Everything the panel stores is **naive UTC**: fourteen `db.Column(db.DateTime)` defaults in
`models.py` insert it, and every comparison and retention cutoff reads it back. SQLite keeps no
timezone, so a single aware value written into one of those columns would come back naive anyway
and silently compare as if it were UTC — right only by accident.

`datetime.utcnow()` produced exactly that naive-UTC value and was the obvious way to write it. It is
deprecated since Python 3.12 and **scheduled for removal**, so it cannot stay; the panel had 22 calls
to it. The replacement has to keep the naive-UTC contract rather than quietly switch the codebase to
aware datetimes, because mixing the two raises `TypeError: can't compare offset-naive and
offset-aware datetimes` at whichever comparison runs first — which here is inside a request.

So there are two functions, and which one you want depends on where the value is going:

  * `utcnow()`   — naive UTC. For anything that touches the database.
  * `aware_utcnow()` — timezone-aware UTC. For APIs that want an aware datetime, notably
    `cryptography`, whose naive-datetime certificate properties are themselves deprecated.

No imports beyond the standard library, so anything in the codebase can use it.
"""
from datetime import datetime, timezone


def utcnow():
    """The current UTC time as a **naive** datetime — what `datetime.utcnow()` returned.

    Use for every value that is stored in, or compared against, a `db.DateTime` column."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def aware_utcnow():
    """The current UTC time as a **timezone-aware** datetime.

    Use only where a library asks for one. Never store it: it would land in a naive column."""
    return datetime.now(timezone.utc)
