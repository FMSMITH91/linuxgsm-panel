"""The upload scan of a database dump: one awk program, run on the game host by the finish of an upload.

routes/databases_files.py runs it (finish_script) as `LC_ALL=C awk -v me=<database> -v max=<bytes>` with the
SQL on its stdin; it prints exactly one verdict: SCANNED, SWITCH, OTHER, OPAQUE or BIG. Its own module, with
no imports, so a fuzz harness can load it without the app. Not one of the package's _MODULES: import it by
name, `from panel.ops.ssh_manager import db_upload_scan`.
"""

# A small SQL lexer in awk (mawk and gawk alike; the game host has no Python packages to lean on). It reads
# the dump as the client and the server do, in the C locale and in lower case, and checks the code only:
# string literals, comments and quoted names are never read as statements, however a keyword is spread
# over lines, comments or whitespace (\v and \f included).
#
# * Lexing. Each `\\`, `\'` and `\"` becomes two E first, so a string is just '...' or "..." (in a string
#   that is what the escape means; in the code a backslash is refused anyway). Strings, quoted names
#   (`...`) and block comments may span lines: `st` holds what the next line starts inside. The fast way
#   reads the strings alone, which is exact up to the first comment opener or quoted name holding a quote;
#   a line with one is read again with every kind of special (SP). /*! and /*M! (executable comments) are
#   code, X; their closing */ is K, a blank. The code view `c` keeps quoted names (for `mysql`.t); `k`
#   masks them as N (for the statement words).
# * Across lines. The last word of a line (or its last mark) is put before the next line's code, so
#   `USE` + newline + `mysql` or `mysql` + newline + `.user` reads as one.
# * SWITCH: USE (not an index hint, USE INDEX/KEY), CREATE/DROP/ALTER [OR REPLACE] DATABASE/SCHEMA, or the
#   client's CONNECT at the start of a line. OTHER: a system or other panel database's name, quoted or not,
#   then a dot (the database's own name `me` is fine).
# * OPAQUE: what the lexer cannot vouch for, because the client or the server would then read the text
#   differently from it: an sql_mode with NO_BACKSLASH_ESCAPES or ANSI_QUOTES (or one set from anything but
#   a plain value), a client character set where a backslash can end a character (big5, cp932, gbk,
#   gb18030, sjis), a backslash in the code (a client command such as \C; \N and \- are fine), a DELIMITER
#   that holds a quote, comment opener or word character, `--` not followed by a blank (the client and the
#   server disagree there) with a quote or comment after it, a quote in an optimizer hint (/*+), and an
#   executable comment holding a block comment or a */ inside a string or comment (a server older than its
#   version reads it as a comment, which ends at the first */). Also PREPARE/EXECUTE and LOAD DATA/XML:
#   SQL built or read while it runs is not in the text to read.
#
# The database account's grant (one database) refuses what the scan does not read; the scan is the early,
# readable refusal. Speed: mysqldump's data lines take the fast way (strings only, no comments).
SCAN_AWK = r'''function regexes() {
  N = "\030"; M = "\034"; X = "\035"; C = "\036"; K = "\037"; L = "\031"; Q = "\032"; E = "\033"
  B = "[^a-z0-9_@.]"; SEP = "[^a-z0-9_]+"; WS = "[\001-\040\200-\377]*"; BLANK = " \t\013\014\r" C L K
  PCB = "[^*]*\\*+([^/*][^*]*\\*+)*"
  SP = "'[^']*('|$)|\"[^\"]*(\"|$)|`[^`]*(`|$)|#.*|--([ \t\013\014\r].*|$)"
  SP = SP "|/\\*(" PCB "/|[^*]*(\\*+[^/*][^*]*)*\\**$)"
  END_["'"] = "^[^']*'"; END_["\""] = "^[^\"]*\""; END_["`"] = "^[^`]*`"; END_["/"] = "^" PCB "/"
  END_["h"] = END_["/"]
  NM = "(mysql|sys|information_schema|performance_schema|gs[0-9]+_[a-z0-9_]*)"
  OTHER_RE = B NM WS "\\.|`" NM "`" WS "\\."
  if (me ~ /^[a-z0-9_]+$/) OWN_RE = B me WS "\\.|`" me "`" WS "\\."
  HINT_RE = B "use" SEP "(index|key)[^a-z0-9_]"
  USE_RE = B "use[^a-z0-9_]*[^a-z0-9_" BLANK "]|" B "use" SEP "[a-z0-9_]"
  DB_RE = B "(create|drop|alter|replace)" SEP "(database|schema)[^a-z0-9_]"
  RUN_RE = B "(prepare|execute)[^a-z0-9_]|" B "load" SEP "(data|xml)[^a-z0-9_]"
  SET_RE = "@|[^a-z0-9_](sql_mode|character_set_client|names|charset|character)[^a-z0-9_]"
  BADMODE = "^(no_backslash_escapes|ansi_quotes|ansi|db2|maxdb|mssql|oracle|postgresql)$"
  BADCS = "^(big5|cp932|gbk|gb18030|sjis)$" }
function verdict(v) { print v; done = 1; exit }
# The rest of a line that starts inside a string, quoted name or comment the line before left open.
function resume(l,   s) {
  s = match(l, END_[st]) ? substr(l, 1, RLENGTH) : l
  if ((st == "h" && s ~ /['"`]/) || (ex && index(s, "*/"))) verdict("OPAQUE")
  if (!RSTART) return ""
  l = substr(l, RLENGTH + 1); s = (st == "'" || st == "\"") ? Q : (st == "`") ? "`x`" : L; st = ""
  return s " " l }
# What a special left open at the end of its line: "", or the state the next line starts in.
function opened(s) {
  if (s ~ /^'/) return s ~ /^'[^']*'$/ ? "" : "'"
  if (s ~ /^"/) return s ~ /^"[^"]*"$/ ? "" : "\""
  if (s ~ /^`/) return s ~ /^`[^`]*`$/ ? "" : "`"
  if (s ~ /^\/\*/) return s ~ ("^/\\*" PCB "/$") ? "" : (s ~ /^\/\*\+/) ? "h" : "/"
  return "" }
# The line with each string as Q. Without a double quote (most of a dump: mysqldump writes \" in its data)
# mawk takes one gsub of '...', gawk a split at the quotes (faster there). An odd count leaves one open.
function strings(l,   n, k, i) {
  if (index(l, "\"")) { gsub(/'[^']*'|"[^"]*"/, " " Q " ", l); return l }
  if (!G) { gsub(/'[^']*'/, " " Q " ", l); return l }
  k = split(l, P, "'"); n = P[1]; for (i = 3; i <= k; i += 2) n = n " " Q " " P[i]
  return k % 2 ? n : n " '" }
# The code of a line: strings Q, comments C (to the end of the line) or L, KC the same with quoted names N,
# MK the line with each special between two M ("" when only strings were read).
function lex(l,   n, b, i, j) {
  n = strings(l); MK = ""
  i = index(n, "'"); j = index(n, "\""); if (j && (!i || j < i)) i = j
  if (i) { st = substr(n, i, 1); n = substr(n, 1, i - 1) " " Q " " }
  KC = n
  if (n " " !~ /#|--[ \t\013\014\r]|\/\*/) {
    if (!index(n, "`")) return n
    b = n; gsub("`[^`'\"" Q "]*`", " " N " ", b); if (!index(b, "`")) { KC = b; return n } }
  st = ""; gsub(SP, M "&" M, l); MK = l
  if (substr(l, length(l)) == M) {
    b = length(l) > 8192 ? substr(l, length(l) - 8191) : l
    if (!match(b, M "[^" M "]*" M "$") || RSTART == 1 && b != l) match(l, M "[^" M "]*" M "$")
    st = opened(substr(l, length(l) - RLENGTH + 2, RLENGTH - 2)) }
  gsub(M "['\"][^" M "]*" M, " " Q " ", l); gsub(M "/\\*[^" M "]*" M, " " L " ", l)
  gsub(M "(#|--)[^" M "]*" M, " " C " ", l); gsub(M, " ", l)
  KC = l; gsub(/`[^`]*`/, " " N " ", KC); return l }
function modeok(x,   n, a, i) {
  n = split(x, a, ","); for (i = 1; i <= n; i++) { gsub(/[ \t]/, "", a[i]); if (a[i] ~ BADMODE) return 0 }
  return 1 }
function valok(kind, x) {
  if (x ~ /[^a-z0-9_, \t]/) return 0
  if (kind == "sql_mode") return modeok(x)
  gsub(/[ \t]/, "", x); return x !~ BADCS }
function stop(w) { return w == "" || w == "," || w == ";" || w == ")" || w == "collate" || w == "for" }
# The value at T[i]: "v:<text>", "s:<system variable>", "@<user variable>" or "" (anything else).
function value(i, k,   v, j) {
  v = T[i]; j = i + 1
  if (v ~ /^@@/) { v = substr(v, 3); if (T[j] == ".") { v = T[j + 1]; j += 2 }; v = "s:" v }
  else if (v ~ /^[SB]/) v = "v:" substr(v, 2)
  else if (v ~ /^[a-z_][a-z0-9_]*$/) v = "v:" v
  else if (v !~ /^@[^@]/) v = ""
  return (i <= k && stop(T[j])) ? v : "" }
function allowed(kind, v,   s) {
  if (v ~ /^@/) { if (ANYU) return 0; s = VS[v]; if (s == "") return 1; v = s }
  if (v ~ /^s:/) return substr(v, 3) == kind
  return v ~ /^v:/ && valok(kind, substr(v, 3)) }
# The tokens of a marked line: words and marks, S<text> a string, B<name> a quoted name, U one left open.
function tokens(m,   n, p, i, k, x, a, j, q) {
  n = split(m, p, M); k = 0; delete T
  for (i = 1; i <= n; i++) {
    x = p[i]
    if (i % 2) {
      gsub(X "|\\*/", " ", x); gsub(/:=/, "=", x); gsub(/[\001-\040\200-\377]+/, " ", x)
      gsub(/[^a-z0-9_@ ]/, " & ", x); q = split(x, a, " "); for (j = 1; j <= q; j++) T[++k] = a[j]
    } else if (x ~ /^['"`]/) T[++k] = opened(x) != "" ? "U" : (x ~ /^`/ ? "B" : "S") substr(x, 2, length(x) - 2) }
  return k }
# The settings that change how the client and the server read the text after them: sql_mode and the
# client character set, set directly or through a user variable (VS: what each one was last set to).
function settings(m,   i, k, w, j, v) {
  gsub(SP, M "&" M, m); k = tokens(m)
  for (i = 1; i <= k; i++) {
    w = T[i]; sub(/^@@/, "", w)
    if (w == "sql_mode" || w == "character_set_client") {
      if (T[i + 1] == "=" && !allowed(w, value(i + 2, k))) return 1 }
    else if (w == "names" || w == "charset" || w == "character" && T[i + 1] == "set" && T[i - 1] ~ /^(set|,)$/) {
      j = w == "character" ? i + 2 : i + 1
      if ((w == "character" || T[j] ~ /^([a-z_]|[SBU])/) && !allowed("character_set_client", value(j, k))) return 1 }
    else if (T[i] ~ /^@[^@]/) {
      if (T[i + 1] == "=") { v = value(i + 2, k); VS[T[i]] = (v ~ /^(v|s):/) ? v : "u" }
      else if (T[i - 1] != "=") VS[T[i]] = "u" }
    else if (T[i] == "@" && T[i - 1] !~ /^([SB]|[a-z0-9_])/) ANYU = 1 }
  return 0 }
# The checks on the statement words (k: quoted names masked) and on the names before a dot (c).
function words(c, k,   u, o, a) {
  if (index(k, "use")) { u = k; gsub(HINT_RE, " _ ", u); gsub(HINT_RE, " _ ", u); if (u ~ USE_RE) verdict("SWITCH") }
  if ((index(k, "database") || index(k, "schema")) && k ~ DB_RE) verdict("SWITCH")
  if ((index(k, "mysql") || index(k, "sys") || index(k, "_schema") || k ~ /gs[0-9]/ || c ~ ("`" NM "`")) && c ~ /\./) {
    o = c; if (OWN_RE != "") gsub(OWN_RE, " _ ", o); if (o ~ OTHER_RE) verdict("OTHER") }
  if ((index(k, "prepare") || index(k, "execute") || index(k, "load")) && k ~ RUN_RE) verdict("OPAQUE")
  if (k ~ SET_RE) { a = carry; gsub(/[^a-z0-9_,=@.;() ]/, " ? ", a); if (settings(a " " r)) verdict("OPAQUE") } }
# What the next line's code is read after: its last three tokens (a word with the mark before it, a quoted
# name, or a mark), so a statement's words may each be on a line of their own.
function settail(c,   i, n, t) {
  i = length(c); t = ""
  for (n = 0; n < 3; n++) {
    while (i && index(BLANK, substr(c, i, 1))) i--
    if (!i) return n ? t : carry
    t = token(c, i) " " t; i -= length(TOK) }
  return t }
# The token that ends at c[i], also in TOK (the mark right before a word comes with it).
function token(c, i,   j, ch) {
  ch = substr(c, i, 1)
  if (ch == "`") {
    j = i > 4096 ? i - 4095 : 1
    TOK = match(substr(c, j, i - j + 1), /`[^`]*`$/) ? substr(c, j + RSTART - 1, RLENGTH) : ch; return TOK }
  if (ch !~ /[a-z0-9_]/) { TOK = ch; return TOK }
  for (j = i; j > 1 && substr(c, j - 1, 1) ~ /[a-z0-9_]/; j--) ;
  if (j > 1 && substr(c, j - 1, 1) == "@") { j--; if (j > 1 && substr(c, j - 1, 1) == "@") j-- }
  else if (j > 1 && !index(BLANK, substr(c, j - 1, 1))) j--
  TOK = substr(c, j, i - j + 1); return TOK }
BEGIN { regexes(); G = PROCINFO["version"] != "" }
{ t += length($0) + 1; if (t > max) verdict("BIG")
  l = tolower($0); if (l ~ /[\030-\037]/) gsub(/[\030-\037]/, "\001", l)
  if (index(l, "/*")) gsub(/\/\*m?![0-9]*/, X, l)
  if (index(l, "\\")) gsub(/\\[\\'"]/, E E, l)
  head = (st == "")
  if (!head) { l = resume(l); if (st != "") next }
  w = index(l, X) && index(l, "*/") || ex ? l : ""
  if (head && l ~ /^[ \t\013\014\r]*delimiter/) {
    a = l; sub(/^[ \t\013\014\r]*delimiter/, "", a)
    if (a ~ ("['\"`#\\\\a-z0-9_" E "]|--|/\\*|\\*/")) verdict("OPAQUE") }
  r = l; KC = l
  if (l ~ /['"`#\/-]/) {
    l = lex(l)
    if (index(MK, "/*+") && MK ~ (M "/\\*\\+[^" M "]*['\"`]")) verdict("OPAQUE") }
  if (index(l, "*/")) { n = gsub(/\*\//, K, l); gsub(/\*\//, K, KC) } else n = 0
  if (w != "" && (ex || index(l, X)) && gsub(/\*\//, "", w) != n) verdict("OPAQUE")
  if (head && l " " ~ /^[^a-z0-9_]*connect[^a-z0-9_]/) verdict("SWITCH")
  c = " " carry " " l " "
  if (ex) c = X c
  if (index(c, X) || index(c, K)) {
    if (c ~ (X "[^" K "]*" L)) verdict("OPAQUE")
    if (match(c, "[" X K "][^" X K "]*$")) ex = substr(c, RSTART, 1) == X }
  k = " " carry " " KC " "; if (index(carry, "`")) gsub(/`[^`]*`/, " " N " ", k)
  if (index(k, "use") || index(k, "database") || index(k, "schema") || index(k, "prepare") || index(k, "execute") ||
      index(k, "load") || index(k, "@") || index(k, "sql_mode") || index(k, "names") || index(k, "charset") ||
      index(k, "character") || index(k, "mysql") || index(k, "sys") || index(k, "_schema") || index(k, "gs") ||
      index(c, "`") && c ~ ("`" NM "`")) words(c, k)
  if (index(c, E) || index(c, "\\") && c ~ /\\[^n-]/) verdict("OPAQUE")
  if (index(c, "--") && c ~ ("--.*[`\\\\" Q L K X "]")) verdict("OPAQUE")
  carry = settail(c) }
END { if (!done) print "SCANNED" }'''
