## 1. Formatter

- [ ] 1.1 Add unexported `formatRemediationHeader(kind, reason, origin string) string` in `pkg/bouncer/remediation_header.go`. Join `kind:reason` when origin is empty or `reason` is not `lapi`. Join `kind:reason:origin` only for `lapi` with a non-empty origin. Strip CR/LF/TAB from origin. Rewrite only the prefix `lists:` → `lists_`. Sanitize unknown AppSec action tokens (trim; strip CR/LF/TAB; `:` → `_`). Empty kind/reason MUST NOT invent `allow: pass`.
- [ ] 1.2 Add a helper that maps `OriginPlugin*` to closed reasons (`decision-header`, `lapi-failure`, `stream-unhealthy`, `cache-fail`, `unparseable-request`, `appsec-failure`) and every other origin to `lapi` plus that origin for encoding. Do not put plugin origins in the third field.
- [ ] 1.3 Add `pkg/bouncer/zzz_remediation_header_test.go`: empty origin, `crowdsec`, `lists:firehol_level1` → `lists_firehol_level1`, CR/LF/TAB strip, leftover colon inside a non-lists origin stays, each plugin origin, unknown AppSec `foo:bar` → `foo_bar:appsec`, empty name is out of scope of the formatter.

## 2. Ban and remediating writers

- [ ] 2.1 Add `headerReason` to `handleBanServeHTTP` (keep template `reason` and metrics `origin`). Set the custom header with `formatRemediationHeader("ban", headerReason, origin)` when the name is non-empty. `recordDropped` still uses metrics origin.
- [ ] 2.2 Thread `headerReason` through `banOrWarnForcedCaptcha`. Direct call sites: GetRemoteIP / nil IP → `unparseable-request`; cache fail → `cache-fail`; AppSec unpublished / Query error → `appsec-failure`; AppSec `action: ban` → `appsec`; empty-challenge → `appsec-challenge-empty`.
- [ ] 2.3 In `handleRemediationServeHTTP`, captcha kind with `!subscribeCaptcha` / unpublished / `!Valid` passes `captcha-downgrade`. Ban kind uses the origin helper. Usable captcha: format `captcha` + helper reason/origin and pass that value into `ServeHTTP`.
- [ ] 2.4 `handleClientDisconnectedServeHTTP` still writes `error:client-disconnected` (formatter `error`, `client-disconnected`, empty origin). Do not `WriteHeader`.
- [ ] 2.5 `handleAppsecResponseServeHTTP`: `captcha` → `captcha:appsec`; `challenge` → `captcha:challenge`; any other action → `{sanitized}:appsec`. Do not copy raw `decision.Action`. Do not change envelope copy besides this header.

## 3. Captcha dumb setter

- [ ] 3.1 Add a challenge-value argument to `captcha.Client.ServeHTTP`. On None/Reject, `writeRemediationHeader` uses that value. On Pass, write `captcha:solved` (no third field). Do not store the header name or the closed table on `Client`.
- [ ] 3.2 `WriteSolvedRedirect` writes `captcha:solved`. Do not remint the cookie or call the provider.
- [ ] 3.3 Update every `ServeHTTP(` test caller (`pkg/captcha/zzz_*.go`) with the extra argument (`""` unless the test asserts the header).

## 4. Assertions, README, e2e

- [ ] 4.1 Migrate header assertions: `pkg/bouncer/zzz_bouncer_test.go` (`ban` → structured; AppSec challenge/captcha relay; empty-challenge / structured-ban; disconnect stays `error:client-disconnected`), `pkg/bouncer/zzz_captcha_routing_test.go` (challenge `captcha:…`, fallback `ban:captcha-downgrade`), `pkg/captcha/zzz_routing_test.go` (`captcha:solved`), `zzz_constructor_test.go`, `zzz_plugin_test.go`, `zzz_servehttp_request_path_test.go`, `pkg/bouncer/zzz_ban_template_test.go` (new `headerReason` arg).
- [ ] 4.2 README “See the verdict in access logs” table and `BouncerRemediationHeadersCustomName`: structured grammar, closed rows, origin encoding, `error:client-disconnected` exact, header still off when empty. Note operators matching single-token `ban` / `captcha` / `solved-captcha` / raw AppSec action must update queries.
- [ ] 4.3 e2e in place (no new suite): `tests/e2e/real/simple-bouncer.Tests.ps1` `ban:lapi:cscli`; `tests/e2e/real/captcha.Tests.ps1` `captcha:lapi:cscli`, fallback `ban:captcha-downgrade`, ban-on-captcha-endpoint `ban:lapi:cscli`; `tests/e2e/mock/scenarios/custom-ban-page/run.sh` `ban:lapi:crowdsec`.
- [ ] 4.4 Do not add a public config key. Do not change `MetricsOrigin`, DecisionStore packing, usage-metrics labels, or incoming `bouncerDecisionHeader`. Do not write `knowledge/devdocs` this apply. Do not emit the header on pass / next / 503.
- [ ] 4.5 Run `go test ./pkg/bouncer/ ./pkg/captcha/ . -count=1` for the packages this change touches.
