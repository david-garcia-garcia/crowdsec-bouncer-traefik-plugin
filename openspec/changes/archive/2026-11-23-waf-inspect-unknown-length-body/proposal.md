## Why

Both WAF legs skip the body of any HTTP/2 or HTTP/3 request that has no `Content-Length` (`wafhop.IsBodyUnreadable`, `pkg/wafhop/body.go`). On AppSec the default `bouncerAppsecFailureAction: ban` answers such a POST, PUT, or PATCH with a silent 403 and never asks AppSec. `restic init` against `rest-server` hits this: it sends an empty HTTP/2 POST without `Content-Length` (upstream issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405). On ModSec the default failure action is `passthrough`, so by default any client that leaves out the optional header gets its body past CRS uninspected. A DELETE without the header is never inspected on either leg. One failure action covers both "the WAF failed" and "the client sent no length", so an operator cannot let restic through without also failing open during a WAF outage. This change supersedes PR #204, which fixed AppSec only, on a base from before the leg split, `pkg/wafhop`, and the ModSec leg.

## What Changes

- Both legs read and inspect a body of unknown length (HTTP/1.1 chunked, HTTP/2, h2c, HTTP/3 without `Content-Length`) the same way they read one with a declared length, capped at the leg's body limit. The read is shared in `pkg/wafhop`. A body the first leg buffered whole is reused by the second (unchanged).
- New per-leg public keys `appsecBodyReadTimeoutSeconds` and `modsecBodyReadTimeoutSeconds` (default `30`, `< 1` rejected, no "disabled" value). Each one is the **total** time this leg waits to receive a body of unknown length. Each key is part of its leg's reclaim identity.
- When the deadline expires, the request is blocked whatever the leg's failure action says (fail-closed): HTTP 400 with remediation header `error:body-read-timeout`, no ban, no dropped-request metrics, no failure action, no gate record. A debounced WARN names the leg's timeout key and its bypass action (`bypassAppsec` / `bypassModsec`, or `bypass`).
- **BREAKING**: the "unreadable body" class is removed (`IsBodyUnreadable`, `IsMethodWithBody`, and both drop paths). Each leg's failure action again means only "the WAF failed". No key comes back that lets such a body pass uninspected (`crowdsecAppsecUnreadableBodyBlock` stays gone). With `passthrough`, a body without `Content-Length` is now inspected instead of skipped.
- **BREAKING**: `appsecBodyLimit <= 0` now means 10485760 (10 MiB). `0` no longer means "unlimited", and a negative value no longer fails validation. `modsecBodyLimit` keeps `>= 1` and its 413.
- An HTTP/2 or HTTP/3 DELETE body without `Content-Length` is inspected like one that has the header, on both legs.
- gRPC and Connect get no special case based on `Content-Type`. Unary calls end and are inspected. Client-streaming and bidirectional streams hit the deadline and are blocked. Operators exclude real streaming routes with `bouncerActionRules` + `bypassAppsec` / `bypassModsec` (or `bypass`). The docs show how and explain the trade-off.
- Unchanged: AppSec bodies over the limit (the first N bytes are inspected and the rest is forwarded); ModSec bodies over the limit (413); GET/HEAD body forwarding on AppSec; bodies with a declared `Content-Length` (no plugin deadline; Traefik `readTimeout` → 400 as today); FailureAction and BackOffAction defaults and the gate rules.

## Capabilities

### New Capabilities

None. Every delta folds into an existing leaf (`devstate/specs.md`).

### Modified Capabilities

- `core_plugin_wafhop_shared-request`: no unreadable-body class (neither leg skips a body because of its length or HTTP version); a body of unknown length is read under the leg's total read deadline; `ReadBody` has no uncapped mode; the deadline is classified before a client disconnect.
- `core_plugin_appsec_failure-action`: the failure action no longer covers a client request body. "One action covers 500, unreachable, and unreadable body" is renamed to "One action covers AppSec 500, unexpected status, and unreachable", and its unreadable-body clauses and scenarios are replaced. The backing-off skip of an unreadable body is removed. `crowdsecAppsecUnreadableBodyBlock` has no replacement.
- `core_plugin_appsec_client`: `appsecBodyLimit <= 0` is the 10 MiB cap (replaces "Zero body limit forwards the full body"); body forwarding does not depend on `Content-Length` or the HTTP version (renamed "Client body forwards only on body-bearing methods"); the reclaim identity adds `appsecBodyReadTimeoutSeconds` and hashes the effective body limit; a deadline expiry takes precedence over the client-disconnect classification.
- `core_plugin_modsecurity_inspect`: `Inspect` no longer takes the failure action; `ErrUnavailable` no longer covers a streamed body; a body of unknown length is read and inspected under `modsecBodyReadTimeoutSeconds`; the failure action does not apply to the deadline.
- `core_plugin_modsecurity_client`: the reclaim identity adds `modsecBodyReadTimeoutSeconds`.
- `core_plugin_middleware_bouncer`: the 400 `error:body-read-timeout` answer and its WARN for both legs; a new closed header row.
- `core_plugin_middleware_config-validation`: the two new keys (default 30, `< 1` rejected); `appsecBodyLimit` is no longer range-checked.

## Impact

- Code: `pkg/wafhop/body.go` (deadline, new sentinel, removed predicates, no uncapped mode), `pkg/appsec/{query.go,client.go,session.go,test_client.go}`, `pkg/modsecurity/{inspect.go,client.go,session.go}`, `pkg/bouncer/{bouncer_serve_appsec.go,bouncer_serve_modsec.go,bouncer_serve_waf.go,remediation_header.go}`, `pkg/configuration/configuration.go`.
- Signatures (deliberate reshape, `devstate` deviations row by explore): `appsec.Client.Query(req, pol, dl)` and `modsecurity.Client.Inspect(req, dl)`, where `dl` is the per-request read-deadline control the bouncer builds from `rw`. That is 1 production and 69 test calls for `Query`, and 1 production and 5 test calls for `Inspect`.
- Tests: unit tests in `pkg/wafhop`, `pkg/appsec`, `pkg/modsecurity`, `pkg/bouncer`, `pkg/configuration`; a `pkg/yaegitest` run of the deadline path; mock e2e `tests/e2e/mock/scenarios/appsec`; real e2e `tests/e2e/real/modsec.Tests.ps1` for the restic request shape and a stalled body through ModSec.
- Docs (`docs/`): `configuration.md` (new keys, `appsecBodyLimit` meaning, `bouncerModsecFailureAction`), `failure-modes.md`, `how-it-works.md`, `modsecurity.md`, `concepts.md`, `how-to/verdict-in-access-logs.md`, and a new `how-to/` page on streaming request bodies, listed in `how-to/README.md`.
- Operators: requests that used to get a 403 (restic) now reach the WAF. `passthrough` no longer lets bodies without `Content-Length` through uninspected. Streaming request bodies are blocked after the leg's timeout unless their route is excluded. `appsecBodyLimit: 0` now caps at 10 MiB. Every AppSec and ModSec Client is re-keyed once on upgrade (new identity field). No persistent storage is involved.
