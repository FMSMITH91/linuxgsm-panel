#!/usr/bin/env python3
"""Print the pins of a hashed requirements file whose environment marker is false on this Python.

pip-audit (--disable-pip) evaluates each pin's marker on the Python it runs on and leaves out a pin
whose marker is false, so the dependency audit (security-code.yml) cannot count every `name==`
line as one pip-audit must have read. requirements.txt pins dnspython 2.8.0 behind
`python_version < "3.11"` and 2.9.0 behind `python_version >= "3.11"`: on the audit's Python 3.11
the 2.8.0 pin is not pip-audit's to read, and osv-scanner, which reads every pin whatever its
marker, audits it. The step subtracts what this prints from its count and names each one.

Usage:
    pins_not_here.py FILE

One line per such pin, `name==version ; marker`. Exits 1, printing nothing to stdout, when a marker
cannot be evaluated: the step then fails rather than guess the count.
"""
import re
import sys

try:
    from packaging.markers import InvalidMarker, Marker
except ImportError:  # the CI unit job installs no packaging; pip vendors it
    from pip._vendor.packaging.markers import InvalidMarker, Marker

# A pin line as pip-compile writes it, with the marker hand-merged in: `name==version ; marker \`.
_PIN_MARKER = re.compile(r"^([A-Za-z0-9._-]+==[^\s;\\]+)[ \t]*;([^\\#\n]+)", re.M)


def pins_not_here(text):
    """[(pin, marker)] for each pin in `text` whose marker is false on the running Python."""
    return [(m.group(1), m.group(2).strip()) for m in _PIN_MARKER.finditer(text)
            if not Marker(m.group(2).strip()).evaluate()]


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: pins_not_here.py FILE\n")
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        text = fh.read()
    try:
        found = pins_not_here(text)
    except InvalidMarker as exc:
        sys.stderr.write("%s: %s\n" % (argv[1], exc))
        return 1
    for pin, marker in found:
        print("%s ; %s" % (pin, marker))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
