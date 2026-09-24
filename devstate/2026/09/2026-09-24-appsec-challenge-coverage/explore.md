# Explore

Problem this run covers: tests in this repo that prove AppSec challenge protocol against upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397 (empty/missing `user_body_content` must fail-closed to the operator ban page; AppSec `user_headers` of the same name replace, including CSP; each `user_cookies` value is its own `Set-Cookie`).

## Concepts

Units this change would touch:

- `applyAppsecServeHTTP` — `pkg/bouncer/bouncer.go` — queries AppSec and routes `challenge` with empty `UserBodyContent` to ban before the envelope writer.
- `handleBanServeHTTP` — `pkg/bouncer/bouncer.go` — operator ban page (remediation status, ban header, `banTemplate` when non-nil).
- `handleAppsecResponseServeHTTP` — `pkg/bouncer/bouncer.go` — writes the structured envelope: replace same-name `user_headers` (skip hop-by-hop and `Set-Cookie`), then `Header().Add("Set-Cookie")` per `user_cookies`.
- AppSec envelope tests — `pkg/bouncer/zzz_bouncer_test.go` — existing challenge/captcha/ban fixtures; new assertions belong here.
- Live spec — `openspec/specs/core_plugin_appsec_bot-detection/spec.md` — empty challenge `user_body_content` is already the operator ban page; CSP replace and multi-cookie are not named scenarios.

```
handleNextServeHTTP
        │
        ▼
applyAppsecServeHTTP
        │
        ├── action challenge && UserBodyContent == "" ──► handleBanServeHTTP
        └── other structured action ──► handleAppsecResponseServeHTTP
                                              │
                                              ├── rw.Header()[canonical] = values
                                              └── Header().Add("Set-Cookie") per cookie
```

Call sites that matter (roots searched: worktree `*.go` for `applyAppsecServeHTTP`, `handleAppsecResponseServeHTTP`, `UserBodyContent == ""`, `Header().Add("Set-Cookie")`):

- `applyAppsecServeHTTP`: 1 caller — `handleNextServeHTTP`.
- Empty-challenge fail-closed (`ActionChallenge` + `UserBodyContent == ""`): 1 site — `applyAppsecServeHTTP`.
- `handleAppsecResponseServeHTTP`: 1 caller — `applyAppsecServeHTTP`.
- Same-name header replace: 1 site — `handleAppsecResponseServeHTTP`.
- Per-cookie `Set-Cookie` add: 1 site — `handleAppsecResponseServeHTTP`.

Reproduce:

1. Empty/missing challenge `user_body_content` — **pass** (protocol present on dest master). Existing `TestHandleNextServeHTTPEmptyChallengeBodyBans` passed (missing field → HTTP 403 + `X-Remediation: ban`, `banTemplate` nil). Throwaway `TestExploreEmptyAndMissingChallengeBodyBansWithBanPage` (deleted after run) passed both `missing` (`{"action":"challenge","http_status":200}`) and `empty-string` (`user_body_content:""`) with a non-nil `banTemplate`: HTTP 403, ban header, body `<html>operator ban for 192.0.2.10</html>`. Not HTTP 200 with an empty body. Status is not committed before the empty-body check (`WriteHeader` lives in `handleBanServeHTTP` / `handleAppsecResponseServeHTTP` after that guard).
2. CSP replace versus append — **pass** (protocol present on dest master). No existing test pre-sets CSP. Throwaway `TestExploreChallengeCSPReplacesAndCookiesStaySeparate` (deleted after run) set `Content-Security-Policy: default-src 'self'` on `httptest.ResponseRecorder` before `handleNextServeHTTP`, then AppSec returned `script-src 'none'` plus two `user_cookies`. Result: exactly one CSP equal to the AppSec value; two separate `Set-Cookie` values. Not append.

Outside facts used: in-tree `knowledge/research/ext_crowdsec_appsec_bot-detection/` (challenge protocol: empty `user_body_content` → fail-closed ban; `user_headers` replace same name; each `user_cookies` entry is one `Set-Cookie`). Usage: `knowledge/devdocs/core_plugin_appsec.md`. Test-file naming: `knowledge/devdocs/std_go_test_zzz-prefix.md`. No new research write.

Client address: these tests do not reconstruct identity. Ban-page `ClientIP` and AppSec query IP stay on `clientRequest` from `pkg/ip.GetRemoteIP`; fixtures use `testClientRequest`.

## Decisions

- Chosen seam: `pkg/bouncer/zzz_bouncer_test.go` next to `TestHandleNextServeHTTPEmptyChallengeBodyBans` and `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`.
- Chosen approach: add tests that assert the two #397 protocol edges (operator ban page for missing and empty-string challenge body; one CSP equal to AppSec; each cookie its own `Set-Cookie`). Do not change production: reproduction shows the protocol behavior is present.
- Rejected: editing `applyAppsecServeHTTP` / `handleAppsecResponseServeHTTP` on dest master — the claimed #397 failures (200 empty body; CSP `Header().Add`) are not this tree's behavior.
- Rejected: proving these edges in e2e — real e2e has a happy-path challenge (`tests/e2e/real/appsec.Tests.ps1`); it does not assert empty-body fail-closed or CSP replace.
- Live contract: `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (empty challenge body is a ban). CSP replace and separate `Set-Cookie` values are not named scenarios there.

## Open questions

- Q: Does case 1 need a ban-page body assertion plus an explicit empty-string `user_body_content` case, or is `TestHandleNextServeHTTPEmptyChallengeBodyBans` enough?
  Rank: additive asked — new assertions on the existing AppSec test file; Desired names "operator ban page" and "missing or empty"
  Decision: assumed — not enough as written (`banTemplate` is nil; only the omitted-field JSON). Add or extend tests for missing and `user_body_content:""` with a non-nil `banTemplate` so the operator ban page is asserted.
  By: explore

- Q: Is a pre-set `Content-Security-Policy` on `httptest.ResponseRecorder` a fair stand-in for "already on the writer"?
  Rank: additive asked — test setup only; Desired names CSP already on the writer
  Decision: assumed — yes. `applyAppsecServeHTTP` runs before `next`, so origin cannot have written CSP. `recorder.Header().Set` before `handleNextServeHTTP` is the same map the envelope writer mutates. Reproduction used that stand-in and observed replace, not append.
  By: explore

- Q: Will a failing new test force a production change?
  Rank: additive asked — Desired: do not change production unless a test shows the protocol is absent
  Decision: resolved — no. Reproduction passed on dest master for both #397 paths. Propose and implement add tests only.
  By: explore

- Q: Where do the new tests live?
  Rank: additive asked — Affected names `pkg/bouncer/zzz_bouncer_test.go`
  Decision: assumed — that file, next to the existing AppSec envelope tests. Do not add an e2e case for these two protocol edges.
  By: explore

- Q: Should the live spec name CSP replace and multi-cookie scenarios?
  Rank: additive incidental — no In-scope line names a spec edit; adding scenarios to `core_plugin_appsec_bot-detection` leaves existing callers working
  Decision: assumed — propose adds those two scenarios to the existing live spec so the new tests have a named contract. Empty-challenge ban is already specified.
  By: explore

- Q: Who already owns the client address these tests would show on the ban page?
  Rank: additive asked — live spec "Client IP for AppSec is GetRemoteIP"; tests reuse that owner
  Decision: resolved — `clientRequest` / `pkg/ip.GetRemoteIP` owns it. Fixtures use `testClientRequest`. Do not invent a second address.
  By: explore
