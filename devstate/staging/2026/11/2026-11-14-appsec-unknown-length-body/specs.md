# Specs
change: appsec-inspect-unknown-length-body
- new core_plugin_appsec_body-read-timeout
- fold core_plugin_appsec_client
- fold core_plugin_appsec_failure-action
- fold core_plugin_middleware_bouncer
- fold core_plugin_lapi_usage-metrics

FindSpecHost verdicts (propose, 2026-11-14):

- `core_plugin_appsec_body-read-timeout` — new, confidence high. New public key, new outcome, new header reason and metrics origin: a capability past the fold threshold. Family `core_plugin_appsec` (in `map.md`); leaf names the key it owns. Candidates: `core_plugin_appsec_client`, `core_plugin_appsec_failure-action`, `core_plugin_middleware_config-validation`.
- `core_plugin_appsec_client` — fold, confidence medium. REMOVED "Zero body limit forwards the full body", ADDED "Non-positive body limit is the default cap", MODIFIED reclaim identity (new knob) and client-disconnect precedence, RENAMED+MODIFIED "Readable body …" → "Client body forwards only on body-bearing methods" (drop set gone).
- `core_plugin_appsec_failure-action` — fold, confidence high. REMOVED "One action covers 500, unreachable, and unreadable body" + ADDED "One action covers AppSec 500, unexpected status, and unreachable" (OpenSpec 2.0 refuses dropping scenarios in MODIFIED); MODIFIED "Structured AppSec verdicts are not failure actions" (reference) and "Three AppSec block booleans are removed" (`crowdsecAppsecUnreadableBodyBlock` has no replacement). Archive also edits its Purpose (tasks.md Workflow follow-up).
- `core_plugin_middleware_bouncer` — fold, confidence high. MODIFIED "Structured remediation header values": closed vocabulary row `ban:appsec-body-timeout`.
- `core_plugin_lapi_usage-metrics` — fold, confidence high. MODIFIED "Dropped items use official labels": plugin origin `plugin:appsec_body_timeout`.
- `core_plugin_middleware_config-validation` — not written. Explore listed it as a candidate; the key's validation lives in the new leaf and the negative-limit acceptance in `core_plugin_appsec_client`, so no requirement of that spec changes.
