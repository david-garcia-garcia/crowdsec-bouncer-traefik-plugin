# Devdocs impact
change: lapi-scope-failclosed-query-hardening

## Units
- LAPI query round trip — pattern — `pkg/lapi/client_http.go` `sendQuery` / `drainResponse`; spec `core_plugin_lapi_query-round-trip`
- Stream lease — pattern — `knowledge/devdocs/core_plugin_lapi_stream-lease.md`; the winner now releases on a failed poll
- LAPI connection — subsystem — `knowledge/devdocs/core_plugin_lapi_connection.md`; owns `client_live.go` and the `LiveLookup` contract that changed meaning
- LAPI scope union — pattern — `knowledge/devdocs/core_plugin_lapi_scope-union.md`; read, unchanged by the apply (the union and `scopes=` are untouched; only the per-scope failure verdict changed)
- CrowdsecLapiFailureAction — product config — `README.md`; operator-facing, documented there, no runtime packet

## Findings
- [x] missing-packet  LAPI query round trip — one exchange had no packet; the drain, the one-shot `401` replay, and the "name your own cause" message rule were only in `client_http.go`
- [x] stale-usage  Stream lease — How-to and snippet stopped at `Acquire` and the loser branch, so nothing said the winner must release the key when its own poll fails
- [x] stale-usage  LAPI connection — How-to said to pass `defaultDecisionSeconds` into `LiveLookup` but never stated how to read the result; after this change "non-nil error" alone no longer tells a caller whether to remediate or to apply `CrowdsecLapiFailureAction`

Produced:
- New packet `knowledge/devdocs/core_plugin_lapi_query-round-trip.md` with the `Query round trip` Language term, How-to, snippet, key files, and gotchas. Row added to `knowledge/devdocs/index_core_plugin.md`. No `domains.md` edit: `core/plugin` already exists.
- `core_plugin_lapi_stream-lease.md`: two How-to bullets (release on a failed poll through the single fetch+apply function; success keeps the key), the release in the snippet, and three gotchas (never release on the loser branch, one store-agnostic `Delete`, the startup flag still clears only on a finished poll).
- `core_plugin_lapi_connection.md`: the `LiveLookup` remediation-kind rule, and a pointer to the new round-trip packet instead of restating drain and replay.

Not produced, on purpose:
- No packet for the failure action itself. `CrowdsecLapiFailureAction` is operator-facing product configuration documented in `README.md`; the implementer-side rule it needs is the `LiveLookup` contract, which now lives on `core_plugin_lapi_connection.md`. Creating `core_plugin_lapi_failure-action.md` would duplicate the README and split the live-lookup contract across two packets.
- No Language term for the fail-closed verdict. "Scope failure" and "active remediation" are already the spec's words and `core_plugin_decisionscope.md` owns remediation vocabulary; adding a synonym here would be inventing a term.