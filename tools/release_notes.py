"""Write a GitHub Release's notes: the CHANGELOG entries one release added.

Usage: release_notes.py <changelog before> <changelog after> <full commit id> <tag>

"Before" is the changelog of the previous signed release ("" or a missing file for none). Entries
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


def _read(path):
    """The file's text, or "" when there is none (the first release)."""
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return ""


def new_entries(before, after):
    """The entries in `after` whose key is not in `before`, in file order."""
    seen = {e["key"] for e in whats_new.parse(before)}
    return [e for e in whats_new.parse(after) if e["key"] not in seen]


def render(entries, sha, tag, first=False):
    """The release notes as Markdown: entries grouped by category, then how to check the signature."""
    out = []
    if first:
        out.append("The first release published here. Everything before it is in docs/CHANGELOG.md.")
    elif not entries:
        out.append("No user-facing change in the changelog for this release (maintenance, tests or CI).")
    groups = {}
    for e in entries[:NOTES_MAX]:
        groups.setdefault(e["category"] or "Changed", []).append(e)
    for category, items in groups.items():
        out.append("### %s\n" % category)
        out.extend("- **%s** %s" % (e["title"], e["body"]) if e["body"] else "- **%s**" % e["title"]
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


def main(argv):
    """Print the notes for the arguments in the module docstring; 2 on a usage error."""
    if len(argv) != 5:
        sys.stderr.write("usage: release_notes.py <changelog before> <changelog after> <commit> <tag>\n")
        return 2
    before, after = _read(argv[1]), _read(argv[2])
    sys.stdout.write(render(new_entries(before, after), argv[3], argv[4], first=not before))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
