## Context

See proposal.md — Why. Today `LookupCachedRemediation` takes `mode string` and compares it to `configuration.StreamMode` / `AloneMode` before calling `membership.Remediation`. That is the only `configuration` import in `pkg/decisionscope`. ServeHTTP already knows the mode via `b.conn.Mode()`. `*RangeMembership` is already an argument.

## Goals / Non-Goals

**Goals:**
- Matching consults membership only when the caller says so.
- `pkg/decisionscope` compiles with no `configuration` import.

**Non-Goals:**
- Moving remediation constants off `pkg/cache`.
- Splitting `connection.go` or `configuration.go`.
- Changing identity / `GetRemoteIP`.
- A `CrowdsecConnection` helper for the bool.
- Changing live/none `?ip=` expansion or stream hydrate.

## Decisions

1. **Bool name is `useRangeMembership`.** Ticket allowed equivalent of `useRangeIndex`. The request path uses membership, not the range-index blob. Alternative: keep `useRangeIndex` — rejected; that name is the old blob flag.

2. **ServeHTTP computes the bool at the call site.** `Mode() == StreamMode || Mode() == AloneMode`. Alternative: connection method — extra API; bouncer already imports configuration.

3. **Keep `*RangeMembership`.** Ticket Desired omitted it; that argument is already the Range owner.

4. **Identity:** reuse `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr`.

## Risks / Trade-offs

- [Call site passes the wrong bool] → tests keep stream=true (membership used) and none=false (membership ignored even when populated).
- [Import sneaks back] → `go test` plus grep: `pkg/decisionscope` has no `configuration` import.

## Migration Plan

Plugin version bump. No YAML. Rollback is the previous tag (lookup takes a mode string again).

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
