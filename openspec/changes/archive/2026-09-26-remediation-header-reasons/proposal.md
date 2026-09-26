## Why

When `bouncerRemediationHeadersCustomName` is set, Traefik JSON access logs (`downstream_<Name>`) only see a kind token (`ban`, `captcha`, `solved-captcha`, a raw AppSec `action`, or `error:client-disconnected`). Operators cannot tell a LAPI ban from fail-closed, forced-decision, AppSec, or captcha-downgrade. Origins already exist internally for usage-metrics.

## What Changes

- **BREAKING.** When that header name is configured, write structured values `kind:reason` or `kind:reason:origin` from the closed vocabulary (`ban:lapi:crowdsec`, `captcha:solved`, `ban:captcha-downgrade`, …). Colon is the field separator; split at most three fields; no space after `:`.
- Keep `error:client-disconnected` exact (kind `error`, reason `client-disconnected`). Closed reasons never take a third field.
- LAPI third field is header-safe `MetricsOrigin`: strip CR/LF/TAB; prefix `lists:` → `lists_` only; empty origin omits the third field. Do not change `MetricsOrigin` or DecisionStore packing.
- Unknown AppSec JSON actions (not `ban` / `captcha` / `challenge`) emit `{sanitized-action}:appsec`.
- Pass / bypass / trusted / passthrough / remap-to-pass / widget / gate-cookie GET / disabled / startup 503 still omit the header. No new public config key. Empty name still disables.
- Update README, live specs, unit tests, and e2e assertions that pin the old tokens.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: vocabulary table and emit rules for `bouncerRemediationHeadersCustomName`; keep `error:client-disconnected` exact; captcha-downgrade and fail-closed reasons on the ban writer.
- `core_plugin_middleware_captcha-widget`: Pass 302 header `solved-captcha` → `captcha:solved`; challenge page writes the caller-supplied structured value.
- `core_plugin_middleware_captcha-routing`: Check-true form POST header `solved-captcha` → `captcha:solved`.
- `core_plugin_appsec_bot-detection`: AppSec relay / ban header is structured (`captcha:challenge`, `captcha:appsec`, `ban:appsec`, `ban:appsec-challenge-empty`, `{action}:appsec`), not the raw `action`.

## Impact

- `pkg/bouncer/bouncer.go` writers (`handleBanServeHTTP`, `handleAppsecResponseServeHTTP`, `handleClientDisconnectedServeHTTP`, `handleRemediationServeHTTP`) plus new `pkg/bouncer/remediation_header.go`.
- `pkg/captcha/captcha.go` `ServeHTTP` (challenge-value argument) and `WriteSolvedRedirect` / Pass constant `captcha:solved`.
- Tests that pin old tokens: `pkg/bouncer/zzz_bouncer_test.go`, `pkg/bouncer/zzz_captcha_routing_test.go`, `pkg/captcha/zzz_routing_test.go`, `zzz_constructor_test.go`, `zzz_plugin_test.go`, `zzz_servehttp_request_path_test.go`, plus new `pkg/bouncer/zzz_remediation_header_test.go`.
- e2e: `tests/e2e/real/simple-bouncer.Tests.ps1`, `tests/e2e/real/captcha.Tests.ps1`, `tests/e2e/mock/scenarios/custom-ban-page/run.sh`.
- README “See the verdict in access logs” and `BouncerRemediationHeadersCustomName`.
- Neighbors unchanged: incoming `bouncerDecisionHeader`, usage-metrics labels, DecisionStore packing, `MetricsOrigin`, AppSec envelope copy except the remediation header value.
- Usage packets stay for implement / `opd-devdocsimpact`.
