# Explore

## Concepts

- **Bouncer** (`pkg/bouncer/bouncer.go`): per-router handler. On a stream cache miss it reads `StreamHealthy`. Unhealthy → `applyLapiFailureAction` (`passthrough` calls next, `captcha` remediates as captcha, default bans).
- **LAPI Client** (`pkg/lapi/client_stream.go` `handleStreamTicker`): a failed stream GET flips healthy off when `updateFailure >= lapiUpdateMaxFailure`. Default `0` flips on the first failure. `New` starts that poll in a goroutine (`pkg/lapi/client.go` `startStream`).
- **Failure action** (`pkg/configuration/configuration.go`): `bouncerLapiFailureAction` is `passthrough` | `ban` | `captcha`, default `ban`. It lives on the Bouncer, not on the client.

```
stream GET fails → ticker marks unhealthy
                       │
                       ▼
ServeHTTP cache miss → applyLapiFailureAction
                       ├─ passthrough → next
                       ├─ captcha → challenge
                       └─ ban → 403
```

Call sites that matter: `applyLapiFailureAction` has two production callers in `pkg/bouncer/bouncer.go` (stream-unhealthy miss, live lookup error). Roots searched: `*_test.go` under the worktree. Stream-unhealthy request tests: 1 file (`pkg/bouncer/zzz_servehttp_gaps_test.go`), and it calls `SetStreamHealthyForTest`. Live request tests: 1 file (`zzz_servehttp_request_path_test.go` `TestServeHTTP_LiveFailureAction`), ban and passthrough only.

Reproduce: absence. `rg` over `*_test.go` finds no test that fails `GET /v1/decisions/stream` and then asserts `ServeHTTP`. `bouncerLapiFailureAction: captcha` appears in config and owner tests only. The challenge page marker `CAPTCHA_CHALLENGE_PAGE` is asserted for AppSec failure (`zzz_constructor_test.go` `TestNew_AppsecCaptchaFailureActionServesChallenge`) and for forced decisions, not for a LAPI failure.

Outside facts: in-tree. Usage packet `knowledge/devdocs/core_plugin_middleware.md` already says a stream-unhealthy cache miss uses `bouncerLapiFailureAction`. No usage write.

## Decisions

- Stream proof goes through `New` against an httptest LAPI that returns 500 on the stream route, waits until `StreamHealthy` is false, then `ServeHTTP`. `passthrough` must call next. `ban` must not.
- Rejected: `SetStreamHealthyForTest`. The requirement says flipping the flag does not count.
- Rejected: calling `handleStreamTicker` on a bare client and skipping `New`. The live failure test already goes through `New` and `ServeHTTP`; the stream test should too.
- Captcha proof is a live HTTP 500 through `New` and `ServeHTTP`, same shape as `TestServeHTTP_LiveFailureAction`, asserting `X-Remediation: captcha` and `CAPTCHA_CHALLENGE_PAGE` the way `TestNew_AppsecCaptchaFailureActionServesChallenge` does.
- Rejected: a second captcha test on the unhealthy stream. Both paths share `applyLapiFailureAction`.
- Live contract: `openspec/specs/core_plugin_lapi_failure-action/spec.md` already requires these outcomes. No new requirement.

## Open questions

- Q: Must the stream assertion wait on the constructor's poll, or may it drive one poll by hand?
  Rank: additive asked — a new test; existing callers stay; Desired names a real failed stream GET
  Decision: resolved — `New` against a 500 stream, wait until `StreamHealthy` is false, then `ServeHTTP` for `passthrough` and `ban`.
  By: propose

- Q: Which LAPI failure should serve the captcha challenge?
  Rank: additive asked — a new test; Desired names a LAPI failure with `captcha`
  Decision: resolved — live HTTP 500 through `New` and `ServeHTTP`, assert the captcha page. Do not add a stream captcha twin.
  By: propose
