# Standards

1. [judgement] Mysterious Name — `pkg/lapi/client_http.go:214` — `sendQuery` is the body that now formats every failure, but the strings it writes still start with the old owner: `crowdsecQuery:unreachable`, `crowdsecQuery:renewToken`, and `crowdsecQuery: missing transport`. A reader who greps `sendQuery` finds no log or error text.
   → Either rename the prefixes to `sendQuery:` or say in the job comment that the prefix is the operator-facing name of the exchange, not the Go identifier
   Status: skipped
   Argument: judgement. `crowdsecQuery:` is an operator-facing string that already appears in this repo's issue history and in README troubleshooting; renaming it would change what operators grep for and buys no behavior. The delegator keeps the name, so the prefix still names a real function.

2. [judgement] Middle Man — `pkg/lapi/client_http.go:206-209` — `crowdsecQuery` now only forwards: `return c.sendQuery(stringURL, data, true)`.
   → Inline it and pass `true` at the two production call sites
   Status: skipped
   Argument: judgement. The wrapper is the meaning: "this is a caller-facing query, renewal allowed once". Inlining puts a bare boolean literal at `client_decisions.go:85` and `client_stream.go:111` and loses that sentence. Keeping it also holds the operator-facing prefix (finding 1) attached to a real identifier.

3. [judgement] Data Clumps — `pkg/lapi/client_decisions.go:133` — `mergeLiveScope` now carries six parameters and returns three values; `(chosen, parsedDuration)` travel in and out together as one verdict.
   → Bundle the pair into a `liveVerdict` value if a third caller appears
   Status: skipped
   Argument: judgement, and `skill:sbs-dev-commandments:Bound the ask`. The clump predates this change; the diff adds one return, not a new caravan. One caller, one callee. Introducing a type here is the abstraction the ticket did not ask for.