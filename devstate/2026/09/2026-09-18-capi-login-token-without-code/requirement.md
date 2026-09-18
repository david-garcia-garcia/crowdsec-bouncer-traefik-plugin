# Requirement
IssueKey: 2026-09-18-capi-login-token-without-code

## Problem
Alone-mode `getToken` stores a CAPI token only when the login JSON has `code == 200` and a non-empty `token`. Official CrowdSec `WatcherAuthResponse` marks `code` omitempty; official `apiclient` stores `Token` after HTTP 2xx and does not read `Code`. A 2xx body `{"token":"fresh","expire":"later"}` therefore fails with `getToken statusCode:0`, so alone mode treats a successful CAPI login as failure.

## Current (code)
- `sendQuery` already returns the body only after HTTP 2xx; non-2xx never reaches the login decode. `pkg/lapi/client_http.go:244-253`
- `getToken` POSTs `v2/watchers/login` via `sendQuery(..., false)`, unmarshals `Login`, and stores the token only when `login.Code == http.StatusOK && len(login.Token) > 0`. Otherwise it warns and returns `getToken statusCode:` plus `login.Code` (0 when `code` is omitted). `pkg/lapi/client_http.go:159-193`
- `Login` has `Code int` `json:"code"` (no omitempty). An omitted `code` unmarshals to 0. `pkg/lapi/client_http.go:31-35`
- Token is written on the stored transport `key`, not a write-once Client field. `pkg/lapi/client_http.go:182-189`
- Existing HTTP tests stub login as `{"code":200,"token":"fresh","expire":"later"}`, so they do not see the omitempty path. `pkg/lapi/zzz_client_http_test.go:57` `:111`
- `TestHunt_GetTokenAcceptsTwoXXTokenWithoutJSONCode` is not in this tree.

## Desired
- After a 2xx CAPI login, store `login.Token` when it is non-empty. Do not require `code == 200`.
- Keep the existing error when the token is empty.
- Add a regression test for a 2xx body that has `token` and no JSON `code`.

## Affected
- `pkg/lapi/client_http.go` (`getToken`)
- `pkg/lapi/zzz_client_http_test.go` (regression)
- `knowledge/research/ext_crowdsec_watchers_login-response/` (official login body)

## Out of scope
- Rewriting the login request JSON (`machine_id` / `password` / `scenarios` sprintf) unless a test cannot be written without it.
- Changing `Login` struct tags, expire parsing, CAPI host/route, 401 replay, or connection drain.
- The separate hunt `TestHunt_GetTokenLoginBodyIsValidJSON` (special characters in the login body).

## Unknowns
- Whether production CAPI `v2/watchers/login` omits `code` on a live 2xx today. Official model allows it; official JWT client does not check `Code`. No live CAPI body was captured.

## Tensions
- Ticket proof name `TestHunt_GetTokenAcceptsTwoXXTokenWithoutJSONCode` is a hunt that is not committed; the regression test is still to add.
- Official `WatcherAuthResponse` is LAPI swagger-generated; this plugin talks CAPI `v2/watchers/login`. Official JWT transport uses the same type for CAPI refresh (`knowledge/research/ext_crowdsec_watchers_login-response/`).
