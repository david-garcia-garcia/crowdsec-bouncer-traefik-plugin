## Context

See `proposal.md` Why. `sendQuery` already returns the body only after HTTP 2xx (`pkg/lapi/client_http.go`). `getToken` then unmarshals `Login` and stores the token only when `login.Code == http.StatusOK && len(login.Token) > 0`. Official `WatcherAuthResponse` marks `code` omitempty; official `JWTTransport.refreshJwtToken` assigns `Token` after HTTP 2xx and never reads `Code` (`knowledge/research/ext_crowdsec_watchers_login-response/`). The token owner is the login body's `token` after that 2xx. `getToken` copies it onto the stored `transport.key`.

FindSpecHost:

```
verdicts:
  - { deltaId: accept-capi-token-after-2xx, fold|new: fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_lapi_query-round-trip] }
```

Search: family `core_plugin_lapi` leaves `connection` (`getToken` already writes the token on the stored transport) and `query-round-trip` (401 replay, drain, named failures). This is a one-requirement accept-rule bugfix of the token write. Do not fold into `query-round-trip`.

## Goals / Non-Goals

**Goals:**

- Store a non-empty CAPI token after HTTP 2xx even when JSON `code` is omitted or not 200.
- Keep the empty-token error string as it is today.
- Prove the omitempty path in `pkg/lapi/zzz_client_http_test.go`.

**Non-Goals:**

- Changing `Login` struct tags or dropping `Code`.
- Expire parsing, CAPI host/route, 401 replay, drain.
- Rewriting the login request JSON sprintf.
- A second token field on Client.
- Folding this rule into `core_plugin_lapi_query-round-trip`.

## Decisions

1. **Drop the `login.Code == 200` conjunct.** Gate on `len(login.Token) > 0` after `sendQuery` 2xx. Alternative: treat omitted `code` as 200 — rejected (`Code` is not the success owner; official JWT client never reads it). Alternative: add `omitempty` on `Login.Code` — rejected (out of scope; would not fix a present non-200 `code` on 2xx).
2. **Keep `getToken statusCode:` plus `login.Code` on empty token.** Do not rewrite that string when `Code` is `0`. Alternative: a new `empty token` message — rejected (out of scope).
3. **Write the token on the stored transport.** Same Store-copy as today. Do not add a Client field.
4. **Regression `TestGetToken_TwoXXBodyWithoutJSONCode`** in `pkg/lapi/zzz_client_http_test.go`. Stub `{"token":"fresh","expire":"later"}`, assert nil error and stored key `fresh`. Keep existing `"code":200` stubs. Empty-token 2xx stays the existing `getToken statusCode:` error (same file). Not `TestHunt_*`.
5. **Fold onto `core_plugin_lapi_connection`.** ADDED requirement. Do not MODIFY the replaceable-transport requirement (where the token is written stays true).

## Risks / Trade-offs

- [A 2xx body with a non-empty token and a JSON `code` that is not 200 now stores the token] → Accepted. HTTP 2xx from `sendQuery` is the success owner (`explore.md`). Official JWT client never reads `Code`.
- [No live CAPI body was captured] → Official model allows omitempty; official JWT client does not check `Code`. Do not block on a live capture.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert.
