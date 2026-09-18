## Context

See proposal.md for motivation. DestBranch already canonicalizes store-side Ip keys via `IPCacheKey` and request-side keys via `IPLookupCacheKey(remoteIP, ipAddr)`. `ServeHTTP` still copies the raw `GetRemoteIP` string onto `clientRequest.remoteIP`. Live memo still calls `IPCacheKey(remoteIP)`. Captcha bind compares that raw string.

Explore identity owner: `GetRemoteIP` owns which address; after a successful parse, `clientRequest` owns the canonical spelling.

## Goals / Non-Goals

**Goals:**

- One request-side spelling, owned by `clientRequest.remoteIP` after parse.
- Delete the second lookup helper.
- Real-stack e2e for Ip spelling against live CrowdSec.

**Non-Goals:**

- Changing `GetRemoteIP`'s `(raw, parsed)` return.
- A fourth address field.
- Cache migration or new config.
- Observing live memo hits from Pester (unit guard stays).
- Range-index CIDR text matching.

## Decisions

- **Canonicalize on `clientRequest` after the nil-`ipAddr` ban, not in `GetRemoteIP`.** Extract-fail / `tech_trustipfail` logs need the garbage header. Alternative considered: canonicalize inside `GetRemoteIP` — rejected; that hides the raw text the ticket wants on those paths.
- **Delete `IPLookupCacheKey`. Lookup keys on `remoteIP`.** `ipAddr` stays only for Range `Contains`. Alternative considered: keep the helper as a thin alias — rejected; it is the confused second owner.
- **Live memo `Set(remoteIP)` with no `IPCacheKey` on the request path.** After canonicalize, the string is already `net.IP.String()`. Store/delete still use `IPCacheKey` because LAPI decision values are still text.
- **E2e in `decision_scopes.Tests.ps1` (none + stream) with `Add-TestDecision` and XFF `Test-HttpRequest`.** If cscli rejects IPv4-mapped, fall back to `Add-TestScopeDecision -Scope Ip -Value`. Memo-hit stays `TestLiveLookup_MemoHitsOnRepeatedRequests`.

## Risks / Trade-offs

- [cscli rewrites IPv4-mapped] → Mitigation: fall back to `--scope Ip --value`; assert the stored value via LAPI list if the first inject fails.
- [Existing live memo under raw spelling] → Mitigation: no cache migration; TTL expires old keys. Same class as #77.
- [Pester cannot count LAPI GETs] → Mitigation: keep the unit memo-hit tests; e2e asserts ban only.

## Migration Plan

No deploy knob. Roll forward. Old raw-spelling live keys expire by `defaultDecisionSeconds`. Rollback is revert; no data rewrite.
