# Requirement
IssueKey: 2026-09-24-remediation-match-trace

## Problem
TRACE ServeHTTP lines show the client IP, `isTrusted`, a leftover `cache=hit`, and remediation letter `t`. That does not explain which CrowdSec scope made the remediation fire. IP is useful; mapped scope values (headers, AS, and the rest of `bouncerDecisionScopeHeaders`) are missing.

## Current (code)
- After IP parse, TRACE `ServeHTTP` logs `ip` and `isTrusted` only: `pkg/bouncer/bouncer.go`
- On live/stream/alone, `LookupRemediation` then an active kind TRACE `ServeHTTP` logs `ip`, `cache`=`hit`, `remediation` (letter `t`/`c`): `pkg/bouncer/bouncer.go`
- `HandleRemediationServeHTTP` TRACE logs `ip` and `remediation` only: `pkg/bouncer/bouncer.go`
- Live/none miss path TRACE `ServeHTTP:LiveLookup` logs `ip` and `isBanned` (the kind), not scopes: `pkg/bouncer/bouncer.go`
- Mapped header scopes for the request are already collected as `RequestScopeValues` immediately before lookup, then passed in; they are not logged: `pkg/bouncer/bouncer.go`, `pkg/decisionscope/lookup.go`
- Store lookup merges Ip key, present header-scope keys, and Range membership; ban wins. Return is kind, origin, originID — no winning scope or identifier: `pkg/decisionstore/lookup.go`, `pkg/decisionstore/store.go`
- Header-mapped scopes include Country, AS, and operator-named extras; missing headers are omitted: `pkg/decisionscope/scope.go`, `pkg/decisionscope/lookup.go`
- TRACE ServeHTTP tests assert `ip` and `isTrusted` attributes, not match identity: `pkg/bouncer/zzz_debug_attrs_test.go`
- Live spec requires those two fields and stem `ServeHTTP` to stay: `openspec/specs/std_go_logger_debug-attrs/spec.md`

## Desired
- Keep logging the client IP on TRACE ServeHTTP.
- Stop presenting the hit as a cache hit; cache is not the operator-facing model.
- When a remediation fires, TRACE must show what triggered it: not only IP, but the values of scoped remediations in play (headers, AS, and the other mapped scopes).

## Affected
- `pkg/bouncer/bouncer.go` — TRACE ServeHTTP on the remediating path
- `pkg/bouncer/zzz_debug_attrs_test.go` — TRACE attribute assertions
- `openspec/specs/std_go_logger_debug-attrs/spec.md` — existing TRACE ServeHTTP contract (ip, isTrusted, stem)

## Out of scope
- Changing default `logLevel` or logger format/destination.
- Changing lookup, PreferRemediation, or which scope wins.
- Changing DEBUG failure lines except as needed if explore folds the leftover `cache` attr on `ServeHTTP:Get` lookup errors (not quoted in the ask).
- Metrics origin, AppSec remediations, forced-decision TRACE, trusted-IP skip (already has IP).
- New public config keys.

## Unknowns
- Attribute names and whether to dump every present `RequestScopeValues` entry versus only the winning scope/value.
- Whether a Range membership hit should name the CIDR (ticket named headers and AS, not Range).
- Whether `LookupRemediation` / `lookupHits` must start returning the winning key, or ServeHTTP can log the request's scope map without a winner.
- Whether `ServeHTTP:LiveLookup` and `handleRemediationServeHTTP` TRACE must carry the same match fields (ticket pasted the `cache=hit` ServeHTTP line only).
- Blast radius on `std_go_logger_debug-attrs` if new required fields land there.

## Tensions
- Ticket: `cache` is not a thing. Dest still labels the store hit `cache=hit` on TRACE and uses `cache` on DEBUG `ServeHTTP:Get` errors (`pkg/bouncer/bouncer.go`). Decision store / live memo still exist; the ask is the breadcrumb wording, not deleting the store.
- Ticket: show what triggered the remediation. Dest merge returns a single kind and does not remember which of Ip / header / Range won (`pkg/decisionstore/lookup.go`).
- Live spec `std_go_logger_debug-attrs` requires `ip` and `isTrusted` to remain on TRACE ServeHTTP; the ticket keeps IP and asks for more fields. Compatible if `isTrusted` stays on the first breadcrumb.
- Ticket sample is live/stream/alone `cache=hit`. Live/none miss uses a different stem (`ServeHTTP:LiveLookup`) with no scope values; same operator need, not named in the paste.
