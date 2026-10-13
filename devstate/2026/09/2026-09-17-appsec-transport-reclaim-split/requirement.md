# Requirement
IssueKey: 2026-09-17-appsec-transport-reclaim-split

## Problem
After PR #62, LAPI reclaim no longer splits on TLS, HTTP timeout, or per-router policy. AppSec still hashes TLS and the shared HTTP timeout into its own reclaim key, so a TLS- or timeout-only reload throws away a good `appsec.Client`. The residual is `knowledge/debt/2026-09-17-appsec-captcha-split.md`.

## Current (code)
- AppSec reclaim key is `appsec:` + FNV-64a of JSON `identity`: scheme, host, path, key, bodyLimit, httpTimeoutSeconds, tlsInsecureVerify, tlsCa, tlsCert (`pkg/appsec/session.go`).
- `Open` creates via `New` and does not adopt transport (`pkg/appsec/session.go`).
- `New` solders `http.Client` (TLS from `GetTLSConfigCrowdsec(..., true)` plus `HTTPTimeoutSeconds`) onto `Client.httpClient`. No `AdoptTransport`. `httpClient` is a write-once pointer field; readers do not take the mutex except `Close` (`pkg/appsec/client.go`).
- Per-router AppSec failure action is already on `Bouncer.appsecFailureAction` and passed as `appsec.Policy` at `Query`. It is not in the AppSec identity (`pkg/bouncer/bouncer.go`, `pkg/appsec/query.go`).
- Plugin `New` prepares then `appsec.Open` (`plugin.go`).
- Live spec still requires TLS, body limit, and HTTP timeout in the AppSec reclaim key (`openspec/specs/core_plugin_appsec_client/spec.md`).
- Session tests only assert same-config reclaim (`pkg/appsec/zzz_session_test.go`).
- LAPI shape to copy (read-only): `transport` in `atomic.Value`, `AdoptTransport` after Open, TLS/timeout off the hash (`pkg/lapi/client.go`, `pkg/lapi/client_http.go`, `pkg/lapi/session.go`). Do not edit those files.
- Debt file still open (`knowledge/debt/2026-09-17-appsec-captcha-split.md`).

## Desired
- Drop AppSec TLS fields and AppSec HTTP timeout from the AppSec reclaim key so a reload of those knobs reuses the Client.
- Keep any per-router AppSec policy off that key (failure action already is).
- Extract AppSec HTTP+auth/TLS into a transport stored on the Client in `atomic.Value` (not `atomic.Pointer[T]`; comment why, as LAPI does). Last `New` `AdoptTransport`s; do not mutate existing write-once scalars.
- Confirm exact AppSec keying in explore before locking the design. Do not assume a field-for-field LAPI mirror.
- When implement lands, delete `knowledge/debt/2026-09-17-appsec-captcha-split.md` and close that row on this run’s `issues.md` and card.
- Sync (merge `origin/master`, do not rebase a pushed branch) before implement and before pullrequest.

## Affected
- `pkg/appsec/` (session key, Client transport, tests).
- Minimal `pkg/bouncer/` only if Open/Query wiring needs it.
- `openspec/specs/core_plugin_appsec_client` (and, if explore proves a delta, `core_plugin_appsec_failure-action`, `core_plugin_appsec_bot-detection`, `core_plugin_middleware_captcha-gate`).
- `knowledge/devdocs/core_plugin_appsec.md` after apply (devdocsimpact).
- This run’s `issues.md` + delete of `knowledge/debt/2026-09-17-appsec-captcha-split.md` at implement.

## Out of scope
- `pkg/lapi/` any file.
- `openspec/specs/core_plugin_middleware_instance-reclaim/` (sibling rename).
- `openspec/specs/core_plugin_lapi_usage-metrics/` and `pkg/lapi/client_metrics.go`.
- `pkg/reclaim/` internals.
- Previous run bus `devstate/2026/09/2026-09-17-lapi-transport-router-policy/`.
- Captcha product work (debt: captcha stays on Bouncer). Fence allows `pkg/captcha/` only if AppSec adopt genuinely needs it.
- New public JSON/YAML keys.
- Moving `CrowdsecAppsecBodyLimit` off the key unless explore shows it is transport, not listener identity (ticket did not name it).

## Unknowns
- Whether `bodyLimit` stays on the AppSec key. It is on identity and on a write-once Client scalar today; ticket did not list it.
- Whether `HTTPTimeoutSeconds` is the only timeout (no AppSec-specific timeout field exists).
- Whether `plugin.go` can stay unchanged if `AdoptTransport` lives inside `appsec.Open`.
- Whether a sibling merge moves `origin/master` before implement (Sync then, not rebase).

## Tensions
- Live spec `core_plugin_appsec_client` currently requires TLS and HTTP timeout in the key; the ticket wants them out. That is a spec delta, not extra product scope.
- Ticket says “any per-router AppSec policy” out of the key; failure action is already out. Do not invent a second policy move.
- Ticket fence includes `pkg/captcha/`; debt and this ticket’s job are AppSec reclaim/transport, not a captcha split.
- Ticket forbids editing `pkg/reclaim/` internals; AppSec already uses `reclaim.OpenWithHooks` from `pkg/appsec/session.go`. Stay there.
- If design requires `pkg/lapi/`, instance-reclaim spec, usage-metrics, or `pkg/reclaim/` internals → `blocked`, do not edit.
