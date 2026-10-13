## Context

See `proposal.md` Why. Dest remediating TRACE is `pkg/bouncer/bouncer.go` store-hit `ServeHTTP` (`ip`, leftover `cache=hit`, `remediation`) and live/none miss `ServeHTTP:LiveLookup` (`ip`, `isBanned`). `RequestScopeValues` is already collected immediately before lookup (`bouncer.go` ~443) and is not logged. First breadcrumb `ServeHTTP` (`ip`, `isTrusted`) is a live SHALL on `std_go_logger_debug-attrs`. Explore Decisions are accepted.

FindSpecHost:

```
verdicts:
  - { deltaId: remediating-trace-scopes, fold: fold, spec-id: std_go_logger_debug-attrs, confidence: high, candidates: [std_go_logger_debug-attrs, std_go_logger_slog-output, core_plugin_decisions_scopes, core_plugin_middleware_bouncer, core_plugin_decisionstore_store] }
```

Search: `std_go_logger_debug-attrs` already owns TRACE ServeHTTP `ip` + `isTrusted` + stem. This is a small adjustment (one remediating scenario, drop leftover `cache`). `std_go_logger_slog-output` owns construct destination/format (out of scope). `core_plugin_decisions_scopes` owns match behavior, not the TRACE trail. `core_plugin_middleware_bouncer` is Yaegi New / reclaim / config snapshot. `core_plugin_decisionstore_store` owns lookup return (kind, origin, originID) — this run does not change it. Existing leaf name still says Debug; fold stays; rename is already `note large` on `issues.md`.

Identity: `pkg/ip.GetRemoteIP` owns the client address (`clientRequest.remoteIP` after `ipAddr.String()`). `decisionscope.RequestScopeValues` owns header identity. Reuse both outputs. Do not re-parse `RemoteAddr` or re-read headers at log time. Range CIDR has no owner on this path (`RangeMembership.Remediation` returns `KindOriginString` only).

## Goals / Non-Goals

**Goals:**

- Remediating TRACE names present mapped scopes without a second identity walk.
- Leftover `cache=hit` is gone on that TRACE line.
- First breadcrumb SHALL unchanged.
- Tests in `pkg/bouncer/zzz_debug_attrs_test.go` (plus a live fixture if LiveLookup needs HTTP).

**Non-Goals:**

- Changing `LookupRemediation` / `lookupHits` to return a winner.
- Logging a Range CIDR.
- Match fields on `handleRemediationServeHTTP` (apply path; forced-decision TRACE is out of scope).
- Folding DEBUG `ServeHTTP:Get` `cache`.
- New public config keys, default `logLevel`, or logger file/format.
- Writing `knowledge/devdocs` this phase (How-to still documents DestBranch cache-hit; implement / `opd-devdocsimpact` updates that line).

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Seam | Remediating `ServeHTTP` TRACE and `ServeHTTP:LiveLookup` TRACE in `pkg/bouncer/bouncer.go` | Ticket paste is the store-hit line; Desired "when a remediation fires" also covers LiveLookup. Apply TRACE stays. |
| Identity | Reuse `req.remoteIP` and the `scopes` map already in hand | One job, one owner. Do not call `GetRemoteIP` or `RequestScopeValues` again. |
| Attribute shape | slog group `scopes` with each present map key (CrowdSec scope name) and header value | Desired is values in play, not a winner. Omit missing headers. Omit the group when the map is empty (do not pass an empty Attr). |
| Group key order | Sort scope names when building the group | Map iteration is random; stable TRACE helps operators and tests. Not a spec SHALL. |
| Winner / Range | Do not change lookup return. Do not log CIDR | Explore rejected both. Membership does not expose CIDR text. |
| `cache` | Drop from remediating TRACE only | Desired. DEBUG `ServeHTTP:Get` `cache` is the lookup error value. |
| Catalog | Fold `std_go_logger_debug-attrs` only | Small adjustment to the existing TRACE leaf. ADDED remediating requirement; do not MODIFY the first-breadcrumb SHALL. |

**Alternatives rejected:** return a winning key from `lookupHits`; log only the winner; name the Range CIDR; attach scopes on `handleRemediationServeHTTP`; flatten `scope.Country` attrs instead of a group; require `scopes` on the allow/trust breadcrumb; a new spec family.

## Risks / Trade-offs

- **Ip vs Range stay indistinguishable on TRACE** → Accepted. Ticket named headers and AS. Membership has no CIDR text without a lookup reshape.
- **`scopes` is "in play", not "what won"** → Accepted. Desired wording. Winner needs a 4-tuple change this run will not take.
- **LiveLookup test needs an HTTP LAPI** → Stream store-hit test is the cheap ticket paste. LiveLookup coverage uses live mode + empty store + a test LAPI ban (plugin-root `liveLAPI` pattern or a `pkg/bouncer` httptest).
- **JSON sink prints group as nested `scopes` object** → Tests assert keys inside that object. Raw slog without `ReplaceAttr` still names the level `DEBUG-4`; assert `msg` and attributes, not the product `TRACE` token.

## Migration Plan

- Deploy. No config rewrite. Operators grepping `cache=hit` on remediating TRACE switch to `remediation` plus `scopes`. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore wrote them.
