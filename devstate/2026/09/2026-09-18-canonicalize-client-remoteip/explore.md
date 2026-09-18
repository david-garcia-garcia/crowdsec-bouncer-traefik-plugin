# Explore
IssueKey: 2026-09-18-canonicalize-client-remoteip

## Concepts

```
GetRemoteIP                clientRequest                 consumers
(raw, parsed)     →   after parse: remoteIP =        lookup key = remoteIP
                       ipAddr.String()               Range = ipAddr.Contains
                  →   before parse: remoteIP raw     live memo Set(remoteIP)
                       (trustipfail / extract logs)  captcha bind = remoteIP
                                                     LAPI ?ip= remoteIP
```

- `GetRemoteIP` still owns **which** address (trusted hop / forwarded header) and returns `(raw, parsed)`. It does not rewrite the string.
- `clientRequest` still has three fields. After a successful parse, it owns the **canonical spelling**: `remoteIP = ipAddr.String()`. No fourth field.
- Store path still owns decision-value text: `IPCacheKey` on stream store/delete. Request path must not re-parse.
- `IPLookupCacheKey` is the confused second helper. After canonicalize-at-origin it is redundant.
- Captcha `gateBindIP` is string equality. Same owner as lookup once ServeHTTP canonicalizes before Check/ServeHTTP.
- Real-stack e2e already injects via `Add-TestDecision` (`cscli decisions add --ip`) and hits Traefik with `X-Forwarded-For` (`Test-HttpRequest`). `decision_scopes.Tests.ps1` splits none (`/scope-none`) vs stream (`/scope-stream`). There is no Ip-spelling case today.

## Decisions

- Canonicalize in `ServeHTTP` after the nil-`ipAddr` ban (`tech_trustipfail`), not inside `GetRemoteIP`. Extract-fail / trustipfail logs keep the garbage header.
- Delete `IPLookupCacheKey`. `LookupCachedRemediation` / `LookupCacheKeys` key on `remoteIP` (already canonical). Keep `ipAddr` only for Range membership.
- Live memo writes `Set(remoteIP, …)`. Do not call `IPCacheKey(remoteIP)` on the request path. LAPI `?ip=` keeps using `remoteIP` (now canonical).
- Fold `openspec/specs/core_plugin_decisions_scopes` so the request-side key is the canonical string on `clientRequest`, not a second lookup helper.
- Real e2e stays in `tests/e2e/real/` with `TestUtils.ps1`. Insert Ip bans under expanded IPv6, upper-case IPv6, and IPv4-mapped; request a different spelling via XFF; assert ban. Cover none and stream the way `decision_scopes.Tests.ps1` already does.
- Usage Language `Ip cache key` in `knowledge/devdocs/core_plugin_decisionscope.md` still describes dest (`IPLookupCacheKey`). Fold it when the apply lands (implement / devdocsimpact). Do not invent a new packet.

## Open questions

- Q: Who already owns the client address for a request?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns which address (trust hop / forwarded header) and the `(raw, parsed)` pair. After a successful parse, `clientRequest` owns the canonical spelling (`remoteIP = ipAddr.String()`). Lookup, live memo, captcha bind, and LAPI `?ip=` reuse that string. They must not re-parse the header. Traefik ipstrategy is not the owner.
  By: explore

- Q: Can the real Pester harness observe that a repeated live request does not trigger a fresh LAPI decision fetch?
  Decision: resolved — no. `TestUtils.ps1` can call LAPI, run cscli, and read Traefik access logs. Access logs are the Traefik request, not plugin→LAPI GETs. There is no LAPI query counter on the fixture. Keep `TestLiveLookup_MemoHitsOnRepeatedRequests` (and the existing across-spellings unit) as the memo-hit proof. E2e asserts ban only.
  By: explore

- Q: How does `cscli decisions add --ip` store expanded IPv6, upper-case IPv6, and IPv4-mapped (`::ffff:x.x.x.x`) on the fixture image?
  Decision: assumed — CrowdSec stores decision values verbatim (`knowledge/research/ext_crowdsec_decisions_scopes`). Inject those spellings with `Add-TestDecision` (the helper the ticket called `Add-TestIPDecision`; that name is not in the tree). If cscli rejects or rewrites IPv4-mapped, fall back to `Add-TestScopeDecision -Scope Ip -Value`. Do not invent a second injection path.
  By: explore

- Q: Where do the Ip-spelling e2e cases live, and which modes?
  Decision: assumed — new Contexts in `tests/e2e/real/decision_scopes.Tests.ps1` (none + stream, `/scope-none` and `/scope-stream`). That is the file the ticket named for the mode split. Live-mode HTTP ban can reuse `/live` only if a case needs it; memo-hit observability stays unit-only. Do not add a mock-LAPI suite or a second compose stack.
  By: explore
