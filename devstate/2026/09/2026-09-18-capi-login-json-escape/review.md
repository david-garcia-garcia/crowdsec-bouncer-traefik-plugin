## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: Task subagent unavailable; prepare wrote the bus in-process. Research write skipped (CAPI login fields already named in-tree).

## explore (2026-09-18)
phase: explore
findings: dest sprintf login body fails JSON decode on quote/backslash/newline; official CAPI/LAPI login is only machine_id, password, scenarios
fixed: none (think-only)
skipped: Task subagent unavailable; research write ran in-process. Four assumed rows left for propose.

## propose (2026-09-18)
phase: propose
findings: none
fixed: none
skipped: Task subagent unused. Three assumed rows remain (Marshal vs Encoder, empty/nil scenarios, Content-Type). Fold Q resolved.

## implement (2026-09-18)
phase: implement
findings: Main Process lint failed on tagliatelle (machine_id) and gocognit (TestGetToken_LoginBodyIsValidJSON)
fixed: json.Marshal loginRequest in getToken; TestGetToken_LoginBodyIsValidJSON; tagliatelle nolint + test helpers; cdc4ae1
skipped: Content-Type and SetEscapeHTML(false) stay out of scope. Three assumed rows remain.
