"""The upload scan of a database dump: one awk program, run on the game host by the finish of an upload.

routes/databases_files.py runs it (finish_script) as `LC_ALL=C awk -v me=<database> -v max=<bytes>` with the
SQL on its stdin; it prints exactly one verdict: SCANNED, SWITCH, OTHER or BIG. Its own module, with no
imports, so a fuzz harness can load it without the app. Not one of the package's _MODULES: import it by
name, `from panel.ops.ssh_manager import db_upload_scan`.
"""

# The scan of the whole SQL (mawk/gawk alike): its size unpacked, and any statement that switches database
# or names another one as schema. (quoted `gs1_x`.t or not, gs1_x.t). Prints one verdict (`exit` still runs
# END, hence `done`) and stops at the first. Comment lines (-- and #) are not statements; /*! ... */ ones are
# read. A dump's INSERT lines are most of its bytes and hold the data, so on those it reads only the INSERT's
# own head (up to " VALUES") and, on a line that holds a system or panel database's name at all, each part
# after a ";" that starts with an SQL word: split once, so a line is read in one pass (data that merely says
# "; use /help" or "see mysql.user" in a value is not refused); a plain line's chained parts are read the
# same way. Each line is compared in lower case, so an upper-case spelling is refused too (the safe side: on
# Linux database names are case-sensitive).
# Built from parts (dynamic regexes) so no line of this program is too long to read: LEAD is an optional
# executable comment, NM a system or panel database's name, QN that name used as a schema (quoted or not,
# an unquoted one not inside a longer name), SW a statement that switches to one.
SCAN_AWK = r'''function regexes(   w, k, i) {
  LEAD = "(/\\*![0-9]*[ \t]*)?"
  NM = "(mysql|sys|information_schema|performance_schema|gs[0-9]+_[a-z0-9]+)"
  QN = "`" NM "`[ \t]*\\.|(^|[^a-z0-9_$.`])" NM "[ \t]*\\.[ \t]*[`a-z_]"
  SW = "^[ \t]*" LEAD "(use[ \t]+|(create|drop|alter)[ \t]+(database|schema)[ \t]+(if[ \t]+(not[ \t]+)?exists[ \t]+)?)"
  SW = SW "`?(mysql|sys|information_schema|performance_schema|gs[0-9]+_)"
  w = "use update delete insert replace select create drop alter rename truncate call with lock grant set do handler load"
  k = split(w, i, " "); while (k) { KW[i[k]] = 1; k-- } }
function other(l,   s, n) {
  while (match(l, QN)) {
    s = substr(l, RSTART, RLENGTH); sub(/^[^a-z0-9_]*/, "", s); n = s; sub(/[^a-z0-9_].*$/, "", n)
    if (n != me) return 1
    l = substr(l, RSTART + RLENGTH) }
  return 0 }
function named(l) {
  return l ~ /gs[0-9]/ || index(l, "mysql") || index(l, "_schema") || index(l, "sys") }
# chained() takes a line already in lower case: a statement's words and a database's name are compared so.
function chained(l,   n, part, i, w) {
  n = split(l, part, ";")
  for (i = 2; i <= n; i++) {
    if (!named(part[i]) || !match(part[i], /^[ \t]*(\/\*![0-9]*[ \t]*)?[a-z]+/)) continue
    w = substr(part[i], RSTART, RLENGTH); sub(/^[^a-z]*/, "", w); sub(/^[0-9]*[ \t]*/, "", w)
    if (!(w in KW)) continue
    if ((w == "use" || w == "create" || w == "drop" || w == "alter") && part[i] ~ SW) return "SWITCH"
    if (index(part[i], ".") && other(part[i])) return "OTHER" }
  return "" }
function verdict(v) { print v; done = 1; exit }
BEGIN { regexes() }
{ t += length($0) + 1; if (t > max) verdict("BIG")
  if ($0 ~ /^INSERT INTO /) {
    v = index($0, " VALUES"); h = v ? substr($0, 1, v) : $0
    if (other(tolower(h))) verdict("OTHER")
    l = tolower($0)
    if (named(l) && index(l, ";")) { c = chained(l); if (c != "") verdict(c) }
    next }
  if ($0 ~ /^[ \t]*(--|#)/) next
  l = tolower($0)
  if (l ~ /^[ \t]*(\/\*![0-9]*[ \t]*)?(use[ \t`]|use$|connect[ \t]|(create|drop|alter)[ \t]+(database|schema)([ \t`]|$))/) verdict("SWITCH")
  if (other(l)) verdict("OTHER")
  if (named(l) && index(l, ";")) { c = chained(l); if (c != "") verdict(c) } }
END { if (!done) print "SCANNED" }'''
