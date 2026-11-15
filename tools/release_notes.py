"""Write a GitHub Release's notes: the CHANGELOG entries one release added.

Usage: <before> NUL <after> | release_notes.py <full commit id> <tag>

Stdin is the changelog of the previous signed release (empty on the first release), a NUL byte, then
the changelog of the release (sign-release.sh pipes both from git, so this reads no file). Entries
are compared by the same key the panel's "What's new" card uses (panel.core.whats_new: a hash of the
bold title), so an entry that was moved or rewrapped is not listed again, and the notes match what a
panel shows its users after the update. Prints Markdown on stdout.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panel.core import whats_new  # noqa: E402

# Shown in full on the release page; the rest are counted, and the changelog is one link away.
NOTES_MAX = 60


def new_entries(before, after):
    """The entries in `after` whose key is not in `before`, in file order."""
    seen = {e["key"] for e in whats_new.parse(before)}
    return [e for e in whats_new.parse(after) if e["key"] not in seen]


def _md(text):
    """`text` with "<" escaped, so a placeholder such as <user> shows on GitHub instead of vanishing as a tag."""
    return text.replace("&", "&amp;").replace("<", "&lt;")


def render(entries, sha, tag, first=False):
    """The release notes as Markdown: entries grouped by category, then how to check the signature."""
    out = []
    if first:   # the caller passes no entries then
        out.append("The first release published here. Everything before it is in docs/CHANGELOG.md.")
    elif not entries:
        out.append("No user-facing change in the changelog for this release (maintenance, tests or CI).")
    groups = {}
    for e in entries[:NOTES_MAX]:
        groups.setdefault(e["category"] or "Changed", []).append(e)
    for category, items in groups.items():
        out.append("### %s\n" % category)
        out.extend("- **%s** %s" % (_md(e["title"]), _md(e["body"])) if e["body"] else "- **%s**" % _md(e["title"])
                   for e in items)
        out.append("")
    if len(entries) > NOTES_MAX:
        out.append("...and %d more in docs/CHANGELOG.md." % (len(entries) - NOTES_MAX))
    out.append("---\nRelease `%s`, commit `%s`. Panels install it only when its signature verifies "
               "against the release key in `panel/install/release-signers`. To check the attached "
               "`.sig` yourself:\n\n```\nprintf 'linuxgsm-panel release\\nbranch main\\ncommit %s\\n' > msg\n"
               "ssh-keygen -Y verify -f panel/install/release-signers -I release "
               "-n linuxgsm-panel-release -s linuxgsm-panel-%s.sig < msg\n```" % (tag, sha, sha, tag))
    return "\n".join(out).strip() + "\n"


def main(argv, stdin=None):
    """Print the notes for the input in the module docstring; 2 on a usage error."""
    if len(argv) != 3:
        sys.stderr.write("usage: <before> NUL <after> | release_notes.py <commit> <tag>\n")
        return 2
    data = (stdin or sys.stdin.buffer).read().decode("utf-8", "replace")
    if "\0" not in data:
        sys.stderr.write("release_notes.py: stdin must be <before> NUL <after>\n")
        return 2
    before, after = data.split("\0", 1)
    if not before.strip():  # the first release: all of history is "new", so point at the changelog instead
        sys.stdout.write(render([], argv[1], argv[2], first=True))
    else:
        sys.stdout.write(render(new_entries(before, after), argv[1], argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
