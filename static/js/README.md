# static/js

`panel.js` is base.html's shared behaviour, served as a cacheable file instead of inlined into every
page. It was inline until then, which is why the JS linters had never seen it: Codacy's ESLint and
Semgrep analysers do not parse `<script>` inside a Jinja template. Extracting it surfaced ~66
findings in code that had not changed a line.

`.eslintrc.json`, in this directory, declares the panel's globals so `no-undef` reflects reality — the panel
assigns them with `window.X = ...`, which ESLint cannot infer. The list is generated from the actual
assignments across `panel.js` and `templates/*.html`; regenerate it if you add a new global.
It carries `"root": true`, so it governs exactly this directory and stops ESLint's upward
search here — which is why it lives beside the code it describes rather than at the repo root.
`tools/` has its own, because `tools/lhci-login.js` is a Node script (`module.exports`) and the
browser env here was never right for it.

The remaining findings are the XSS heuristics (`no-unsanitized`, `xss_no-mixed-html`,
`insecure-innerhtml`). They are pre-existing and were spot-checked when the file was created: the
sites either escape with `escapeHtml()`, restore an element's own prior markup, or assign a static
literal. They are NOT suppressed — leaving them visible is the point of having the file analysed at
all. Triage them on their own merits rather than as part of an unrelated change.
