# `LookupRemediation` origin id is always 0

IssueKey: 2026-11-21-lapi-ban-retry-after
Size: large
Action: note

## Why this follow-up
`memory.LookupRemediation` and `redis.LookupRemediation` (`pkg/decisionstore/memory.go`, `redis.go`) declare a named `originID` return and never assign it, so `Store.LookupRemediation` always returns origin id `0`. The catalog (`core_plugin_decisionstore_store`, "DecisionStore owns the origin intern table") says it returns the origin id. Callers work only because the origin name is returned too (`resolveDroppedOrigin`, `appliedLAPIRemediation`).

## Why it was not taken
It is not part of the Retry-After ask. Dropping the return or filling it changes the lookup contract and its 43 test callers, and the catalog line. This change already touches that signature for the time left and keeps the origin id as it is.

## Risks
A future caller that trusts the origin id gets `0` and resolves an empty origin name.
