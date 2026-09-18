# Explore
IssueKey: 2026-09-18-capi-login-token-without-code

## Concepts

Alone-mode CAPI login is `getToken` → `POST v2/watchers/login` through `sendQuery(..., false)`. `sendQuery` already returns the body only after HTTP 2xx (`pkg/lapi/client_http.go:244-253`). `getToken` then unmarshals `Login` and stores the token only when `login.Code == http.StatusOK && len(login.Token) > 0` (`pkg/lapi/client_http.go:181-193`). The token is written on the stored `transport.key`, not a write-once Client field.

```
sendQuery login (mayRenewToken=false)
  ├─ non-2xx                 ──► status error (never reaches decode)
  └─ 2xx body
        ├─ token non-empty + code==200  ──► Store transport.key     [works]
        ├─ token non-empty + code omitted ──► getToken statusCode:0 [dest BUG]
        └─ token empty                   ──► getToken statusCode:N  [keep]
```

Official CrowdSec `WatcherAuthResponse` marks `code` omitempty. Official `JWTTransport.refreshJwtToken` stores `Token` after HTTP 2xx and never reads `Code` (`knowledge/research/ext_crowdsec_watchers_login-response/`). This plugin’s `Login` has `json:"code"` with no omitempty; an omitted field unmarshals to `0`. Existing HTTP tests stub `{"code":200,"token":"fresh","expire":"later"}`, so they never see the omitempty path. Hunt `TestHunt_GetTokenAcceptsTwoXXTokenWithoutJSONCode` is not in this tree.

`startStream` in alone mode fails closed on `getToken` (`pkg/lapi/client_stream.go:31-35`). A 401 renewal also calls `getToken` (`pkg/lapi/client_http.go:237-241`). Both paths treat a successful CAPI login as failure when `code` is omitted.

HTTP success is already owned by `sendQuery`. The CAPI token string is owned by the login body’s `token` after that 2xx. `getToken` copies that string onto `transport.key`. JSON `code` is not an owner.

Consumed: `core_plugin_lapi_connection.md` (token on stored transport; Yaegi `atomic.Value`), `core_plugin_lapi_query-round-trip.md` (login passes `mayRenewToken=false`; 401 replay is a different job), `ext_crowdsec_watchers_login-response/` (official Token-after-2xx). No new research: prepare already wrote that folder. No live CAPI body was captured; official model and official JWT client are enough to proceed.

Not process-lifetime work. No `sync.Once` / package global. `Login` struct tags, expire parsing, CAPI host/route, 401 replay, connection drain, and the login-body JSON sprintf stay out of scope.

**Reproduced** (`go test ./pkg/lapi/ -run TestScratch_GetTokenAcceptsTwoXXTokenWithoutJSONCode -count=1`, throwaway file removed after the run):

1. 2xx body `{"token":"fresh","expire":"later"}` (no JSON `code`) → `getToken` returned `getToken statusCode:0`.
2. `transport.key` stayed `"stale-token"` (the test fixture). Token was not stored.

## Decisions

- After a 2xx CAPI login, store `login.Token` when it is non-empty. Drop the `login.Code == 200` conjunct. `sendQuery` already rejected non-2xx.
- Keep the existing empty-token error (`getToken statusCode:` plus `login.Code`). Do not rewrite that string, even when `Code` is `0`.
- Leave `Login` struct tags, expire parsing, CAPI host/route, 401 replay, and drain untouched.
- Add a committed regression in `pkg/lapi/zzz_client_http_test.go` for a 2xx body with `token` and no JSON `code`. Do not ship a `TestHunt_` name. Existing stubs that include `"code":200` stay.
- Spec host (propose runs FindSpecHost): fold the accept rule onto `core_plugin_lapi_connection` (`getToken` already writes the token there). Do not fold it into `core_plugin_lapi_query-round-trip` (that leaf is 401 replay, drain, and failure-message shape).
- Change name: `capi-login-token-without-code`.
- Usage: added the Token-after-2xx gotcha on `knowledge/devdocs/core_plugin_lapi_connection.md`. Official contract stays in the existing research folder.

## Open questions

- Q: Does production CAPI `v2/watchers/login` omit `code` on a live 2xx today?
  Decision: assumed — treat omitempty as possible. Official `WatcherAuthResponse` allows it; official JWT client never reads `Code`. Do not block on a live CAPI capture. Store a non-empty `token` after HTTP 2xx.
  By: explore

- Q: Who already owns the CAPI token (the auth identity written on later CAPI requests)?
  Decision: resolved — CrowdSec CAPI login body’s `token` after `sendQuery` HTTP 2xx. Official sibling is `JWTTransport.Token`. `getToken` copies that string onto the stored `transport.key`. Do not reconstruct success from JSON `code`. Do not invent a second token field on Client.
  By: explore

- Q: Does the accept-token requirement fold into `core_plugin_lapi_query-round-trip`?
  Decision: resolved — no. FindSpecHost fold onto `core_plugin_lapi_connection` (high). That leaf already owns the `getToken` token write. `query-round-trip` stays 401 replay, drain, and named failures.
  By: propose

- Q: What is the committed regression test name?
  Decision: assumed — `TestGetToken_TwoXXBodyWithoutJSONCode` in `pkg/lapi/zzz_client_http_test.go`. Not `TestHunt_*`. Prove store of `fresh` on a 2xx body with no `code`, and keep the empty-token error on a 2xx body with an empty `token`.
  By: explore

- Q: If a 2xx body has a non-empty `token` and a JSON `code` that is not 200, should we still store the token?
  Decision: resolved — yes. HTTP 2xx from `sendQuery` is the success owner. JSON `code` is not consulted.
  By: explore

- Q: Should `Login` grow `omitempty` on `code` (or drop `Code`)?
  Decision: resolved — no. Out of scope. Stop gating on `Code`; leave the struct tags as they are.
  By: explore
