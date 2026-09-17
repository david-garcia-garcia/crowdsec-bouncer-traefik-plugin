## 1. Failing tests first

- [ ] 1.1 Extend keep-alive reuse coverage in `pkg/appsec/zzz_query_test.go` so 502, 503, and 504 fail today (same shape as 200/403/500)
- [ ] 1.2 Add a test that `crowdsecAppsecBodyLimit == 0` forwards a readable POST body and restores it for origin (fails while dest sends GET)
- [ ] 1.3 Add a test that an AppSec response-body io error uses `FailureAction` (`passthrough` allow, `ban` error with `appsecQuery:readBody`, `captcha` `ErrFailureCaptcha`)
- [ ] 1.4 Add a test that outbound `ContentLength` and `Content-Length` match the forwarded bytes when the client header disagrees
- [ ] 1.5 Add a test that an unreadable HTTP/2–3 DELETE with `FailureAction` `ban` is not dropped (headers-only GET)
- [ ] 1.6 Keep `NewTestClient` storing into `transport`; do not restore an `httpClient` field

## 2. Drain reverse-proxy responses

- [ ] 2.1 Drain and close every non-nil AppSec `Do` response before return, including 502/503/504
- [ ] 2.2 Leave transport errors (`err != nil`, typically no body) without a drain

## 3. Unlimited body limit zero

- [ ] 3.1 When `appsecBodyLimit == 0` and the client body is readable, skip `io.LimitReader`, `io.ReadAll` the body, POST it, and restore it for origin
- [ ] 3.2 Keep a positive limit on `LimitReader`; do not invent a max cap or a new knob
- [ ] 3.3 Document README `CrowdsecAppsecBodyLimit` `0` = unlimited; default stays 10485760 when omitted

## 4. Response-body io through FailureAction

- [ ] 4.1 Route `readCappedAppsecBody` io errors through `resultForFailureAction(pol.FailureAction, err.Error())` so the string keeps `appsecQuery:readBody`
- [ ] 4.2 Log `appsecQuery:failure` on that path like 500
- [ ] 4.3 Leave oversized 200 allow and oversized non-200 error as dest today (not FailureAction)

## 5. Rebuild outbound Content-Length

- [ ] 5.1 After the forwarded bytes exist, omit client `Content-Length` and `Transfer-Encoding` from the header copy
- [ ] 5.2 Set `Request.ContentLength` and the `Content-Length` header from those bytes
- [ ] 5.3 Reuse the `ip` argument on `X-Crowdsec-Appsec-Ip`; do not reconstruct from `RemoteAddr` or Host
- [ ] 5.4 Do not add a hop-by-hop filter (Connection, Upgrade, …)

## 6. DELETE out of the unreadable-body set

- [ ] 6.1 Remove DELETE from `isMethodWithBody`; keep POST, PUT, PATCH
- [ ] 6.2 Do not gate the readable-body copy on that set

## 7. Verify

- [ ] 7.1 `go test ./pkg/appsec/ -count=1`
- [ ] 7.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `crowdsecAppsecUnreadableBodyBlock` and `atomic.Pointer` in `pkg/appsec/`
- [ ] 7.3 Cite #35 and #43 on the PR body when pullrequest lands
