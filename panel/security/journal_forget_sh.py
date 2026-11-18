"""The remote form of addon-account-release's clean-up of an uninstalled account (privileged._addon_release_remote).

Its user journals (orphan_journals_sh) and its tmux and JVM folders in /tmp (account_tmp_sh).

Kept out of privileged.py, which is at its size limit; the helper's own form is tools/panel-helper's
_orphan_user_journals.
"""

# After a rotation, the active user journals journald re-created for accounts that are gone (the helper's
# _orphan_user_journals, as shell): a file named user-<uid>.journal, never an archived one, for a uid of at
# least ADDON_FORGET_MIN_UID with no passwd entry and no process (real, effective, saved or fs uid), whose
# header holds journald's signature and counts no entries (n_entries, the 8 bytes at offset 152, all zero:
# systemd.io JOURNAL_FILE_FORMAT). journald keeps every user journal it opened until it restarts and re-creates
# it, empty, at each rotation (journald-manager.c manager_rotate), so a later uninstall's rotation brought
# back an empty file for an account forgotten before.
def orphan_journals_sh(min_uid):
    """The shell itself, for uids of at least `min_uid`."""
    return (
        "if [ -n \"$j\" ]; then for f in /var/log/journal/*/user-*.journal /run/log/journal/*/user-*.journal; do "
        "{ [ -f \"$f\" ] && [ ! -L \"$f\" ]; } || continue; o=${f##*/user-}; o=${o%.journal}; "
        "case \"$o\" in ''|*[!0-9]*) continue ;; esac; [ \"$o\" -ge " + str(int(min_uid)) + " ] || continue; "
        "getent passwd \"$o\" >/dev/null && continue; [ \"$(head -c 8 -- \"$f\")\" = LPKSHHRH ] || continue; "
        "[ \"$(head -c 160 -- \"$f\" | wc -c)\" -eq 160 ] || continue; "
        "[ \"$(head -c 160 -- \"$f\" | tail -c 8 | tr -d '\\000' | wc -c)\" -eq 0 ] || continue; "
        "awk -v u=\"$o\" '$1 == \"Uid:\" { for (i = 2; i <= 5; i++) if ($i == u) f = 1 } END { exit !f }' "
        "/proc/[0-9]*/status 2>/dev/null && continue; rm -f -- \"$f\" && n=$((n + 1)); done; fi; ")


# The account's tmux socket folder (by uid) and JVM perf-data folder (by name) in /tmp, as the helper's
# _forget_account_tmp: each only when it is a real folder (not a link) owned by the uid. Run inside the
# caller's uid >= ADDON_FORGET_MIN_UID test, with $u (the account) and $uid set and $n counting.
def account_tmp_sh():
    """The shell itself."""
    return ("for d in /tmp/tmux-\"$uid\" /tmp/hsperfdata_\"$u\"; do "
            "if [ -d \"$d\" ] && [ ! -L \"$d\" ] && [ \"$(stat -c %u -- \"$d\")\" = \"$uid\" ]; then "
            "rm -rf --one-file-system -- \"$d\" && n=$((n + 1)); fi; done; ")
