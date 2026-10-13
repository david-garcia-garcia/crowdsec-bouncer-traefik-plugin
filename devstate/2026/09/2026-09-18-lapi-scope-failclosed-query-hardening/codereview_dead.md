# Dead

none.

Grepped every non-test `.go` file under `pkg/` for the three symbols the diff introduces and for the one it demoted:

- `sendQuery(` — production callers at `pkg/lapi/client_http.go:172` (`getToken`), `:208` (`crowdsecQuery`), `:241` (the 401 replay).
- `drainResponse(` — production caller at `pkg/lapi/client_http.go:233`.
- `fetchAndApplyStreamDecisions(` — production caller at `pkg/lapi/client_stream.go:90`.
- `crowdsecQuery(` — still called from production at `pkg/lapi/client_decisions.go:85` and `pkg/lapi/client_stream.go:111`, so the delegator is not test-only.

No symbol was left behind by the extraction: `handleStreamCache` keeps the lease and the startup flag, and the moved body has exactly one caller.