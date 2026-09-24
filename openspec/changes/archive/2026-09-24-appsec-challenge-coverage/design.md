## Context

See `proposal.md` — Why. Production already fail-closes empty challenge `user_body_content` in `applyAppsecServeHTTP` before `handleAppsecResponseServeHTTP` (and before `WriteHeader`). The envelope writer assigns `rw.Header()[http.CanonicalHeaderKey(name)] = values` for `user_headers` (skip hop-by-hop and `Set-Cookie`) then `Header().Add("Set-Cookie", cookie)` per `user_cookies`. Existing `TestHandleNextServeHTTPEmptyChallengeBodyBans` covers missing body as 403 + ban header with a nil `banTemplate`. Live spec already names empty-challenge ban; it did not name CSP replace or multi-cookie.

## Goals / Non-Goals

**Goals:**

- Prove both #397 protocol edges in `pkg/bouncer/zzz_bouncer_test.go` using `testBouncerWithAppsec` and `testClientRequest`.
- Assert operator ban page body for missing and empty-string challenge `user_body_content` (non-nil `banTemplate`).
- Assert exactly one CSP equal to the AppSec value after pre-setting CSP on `httptest.ResponseRecorder`, and two separate `Set-Cookie` values for two `user_cookies`.
- Name those two header/cookie scenarios on the folded live spec.

**Non-Goals:**

- Changing `applyAppsecServeHTTP` / `handleAppsecResponseServeHTTP` unless a new test fails.
- Reconstructing client address (fixtures keep `testClientRequest`; `pkg/ip.GetRemoteIP` owns it).
- e2e cases for these edges; captcha empty-body (already specified).

## Decisions

FindSpecHost (propose):

```yaml
verdicts:
  - { deltaId: challenge-csp-replace-and-cookies, fold|new: fold, spec-id: core_plugin_appsec_bot-detection, confidence: high, candidates: [core_plugin_appsec_bot-detection, core_plugin_appsec_client] }
```

Empty-challenge ban is already a live scenario on that leaf — no second delta.

1. **Seam: `pkg/bouncer/zzz_bouncer_test.go`** — Add tests next to `TestHandleNextServeHTTPEmptyChallengeBodyBans` and `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`. Reuse `testBouncerWithAppsec`. *Rejected:* e2e — real e2e has a happy-path challenge only.

2. **Empty/missing body** — Table or two cases: JSON omit (`{"action":"challenge","http_status":200}`) and explicit `user_body_content:""`. Non-nil `banTemplate` so the operator ban page is asserted (HTTP 403, `X-Remediation: ban`, rendered body). *Rejected:* treating the existing nil-template test as enough.

3. **CSP already on the writer** — `recorder.Header().Set("Content-Security-Policy", ...)` before `handleNextServeHTTP`. Same header map the envelope writer mutates. Assert `Values("Content-Security-Policy")` length 1 equals the AppSec value. *Rejected:* a custom ResponseWriter — recorder is the stand-in.

4. **Separate cookies** — two `user_cookies` strings; assert `Header().Values("Set-Cookie")` has both, not a comma-joined single value. Can share the CSP test or sit beside it.

5. **Production** — do not edit `pkg/bouncer/bouncer.go`. Explore throwaways passed on dest master. If a new test fails, stop and treat that as a new fact (then a production fix is in scope per Desired).

6. **Client address** — do not invent a second IP. Ban-page `ClientIP` stays on `clientRequest` from `pkg/ip.GetRemoteIP`.

## Risks / Trade-offs

- **[Risk]** A new test fails and forces a production change → **Mitigation:** Desired already allows that; explore reproduction passed; implement runs the new tests first and only then edits production if they fail.
- **[Trade-off]** `httptest.ResponseRecorder` starts empty, so "already on the writer" is a pre-set, not Traefik leftover headers → accepted; same map `handleAppsecResponseServeHTTP` mutates.
- **[Risk]** Header().Get hides multi-value CSP → **Mitigation:** assert `Values`, not `Get`.
