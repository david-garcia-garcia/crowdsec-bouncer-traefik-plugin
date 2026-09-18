# The alone-mode 401 keeps its connection while the token renewal and replay run

IssueKey: 2026-09-18-lapi-scope-failclosed-query-hardening
Size: small
Action: note

## Why this follow-up
`sendQuery` releases every answered response with `defer c.drainResponse(res)` (`pkg/lapi/client_http.go:233`), which is what makes `502/503/504` and plain non-2xx reuse one connection. A `defer` runs when the function returns, so on the alone-mode `401` arm (`pkg/lapi/client_http.go:237-242`) the `401` response is still held while `getToken` dials CAPI and the replay dials LAPI. One renewal can therefore occupy three sockets instead of one.

Bounded: it happens only on a `401`, only in `alone` mode, at most three sockets, and the idle pool reclaims all three as soon as the replay returns. Nothing accumulates, which is why the code review recorded it as judgement rather than applying it (`devstate/2026/09/2026-09-18-lapi-scope-failclosed-query-hardening/codereview_performance.md` item 1).

## Proposed shape
Drain the `401` response explicitly before calling `getToken`, and take that arm out of the `defer` so the body is not closed twice — a second `Close` is logged at `ERROR` by `drainResponse` (`pkg/lapi/client_http.go:201`), so the release has to move, not duplicate. Roughly five lines, and it needs a test that counts connections across a renewal, which the current `TestCrowdsecQuery_ReusesConnection` does not do because it never sends a `401`.

## Why it was not taken
The ticket fenced deliverable 3 to the replay semantics (same method, same body, one renewal) and deliverable 4 to draining every answered response. Both are met. Restructuring the release for one arm changes the shape the ticket specified and risks a double `Close` regression, so it is named for the owner instead of applied unasked.

## Risks
An `alone`-mode LAPI that answers `401` steadily — an expired or rejected CAPI credential — triples the connection churn of the poll path for as long as it lasts.
