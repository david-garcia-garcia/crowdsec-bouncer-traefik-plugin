## 1. Failing tests first

- [x] 1.1 Extend keep-alive reuse coverage in `pkg/appsec/zzz_query_test.go` so 502, 503, and 504 fail today (same shape as 200/403/500)
- [x] 1.2 Add a test that `crowdsecAppsecBodyLimit == 0` forwards a readable POST body and restores it for origin (fails while dest sends GET)
- [x] 1.3 Add a test that an AppSec response-body io error uses `FailureAction` (`passthrough` allow, `ban` error with `appsecQuery:readBody`, `captcha` `ErrFailureCaptcha`)
- [x] 1.4 Add a test that outbound `ContentLength` and `Content-Length` match the forwarded bytes when the client header disagrees
- [x] 1.5 Add a test that an unreadable HTTP/2–3 DELETE with `FailureAction` `ban` is not dropped (headers-only GET)
- [x] 1.6 Keep `NewTestClient` storing into `transport`; do not restore an `httpClient` field

## 2. Drain reverse-proxy responses

- [x] 2.1 Drain and close every non-nil AppSec `Do` response before return, including 502/503/504
- [x] 2.2 Leave transport errors (`err != nil`, typically no body) without a drain

## 3. Unlimited body limit zero

- [x] 3.1 When `appsecBodyLimit == 0` and the client body is readable, skip `io.LimitReader`, `io.ReadAll` the body, POST it, and restore it for origin
- [x] 3.2 Keep a positive limit on `LimitReader`; do not invent a max cap or a new knob
- [x] 3.3 Document README `CrowdsecAppsecBodyLimit` `0` = unlimited; default stays 10485760 when omitted

## 4. Response-body io through FailureAction

- [x] 4.1 Route `readCappedAppsecBody` io errors through `resultForFailureAction(pol.FailureAction, err.Error())` so the string keeps `appsecQuery:readBody`
- [x] 4.2 Log `appsecQuery:failure` on that path like 500
- [x] 4.3 Leave oversized 200 allow and oversized non-200 error as dest today (not FailureAction)

## 5. Rebuild outbound Content-Length

- [x] 5.1 After the forwarded bytes exist, omit client `Content-Length` and `Transfer-Encoding` from the header copy
- [x] 5.2 Set `Request.ContentLength` and the `Content-Length` header from those bytes
- [x] 5.3 Reuse the `ip` argument on `X-Crowdsec-Appsec-Ip`; do not reconstruct from `RemoteAddr` or Host
- [x] 5.4 ~~Do not add a hop-by-hop filter (Connection, Upgrade, …)~~ — superseded by 8.1 (folded from #35 at owner direction)

## 6. DELETE out of the unreadable-body set

- [x] 6.1 Remove DELETE from `isMethodWithBody`; keep POST, PUT, PATCH
- [x] 6.2 ~~Do not gate the readable-body copy on that set~~ — superseded by 8.2: the readable copy is gated on a **separate** predicate; `isMethodWithBody` (the drop set) is unchanged

## 7. Verify

- [x] 7.1 `go test ./pkg/appsec/ -count=1`
- [x] 7.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `crowdsecAppsecUnreadableBodyBlock` and `atomic.Pointer` in `pkg/appsec/`
- [ ] 7.3 Cite #35 and #43 on the PR body when pullrequest lands

## 8. Folded from #35 (amendment; #35 closed as superseded)

- [x] 8.1 Add `isHopByHopHeader` (RFC 7230 section 6.1, errata 4522) and skip those names plus the client `Content-Length` in the header copy; `Transfer-Encoding` is covered by the hop-by-hop set, so the 5.1 skip is not duplicated
- [x] 8.2 Add `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE) and gate the readable-body copy on it; also skip `http.NoBody`. Leave `isMethodWithBody` (POST, PUT, PATCH) and the unreadable-body drop policy untouched
- [x] 8.3 Keep the outbound `Content-Length` header on the POST branch only (do not switch to `req.ContentLength >= 0` as #35 did); after 8.2 the outbound POST is exactly the body-carrying case, so a bodyless GET sends no length header
- [x] 8.4 Do not honour names listed in the client `Connection` header: a client could otherwise hide `Cookie` or any header from AppSec
- [x] 8.5 Tests: a GET carrying a body is not forwarded as POST (table over GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE) and hop-by-hop headers do not reach the listener
- [x] 8.6 Do not touch the unreadable-body security posture or add `crowdsecAppsecUnreadableBodyBlock` (#51 stays the owner's separate decision)
