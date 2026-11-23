## Why

In `live` and `none` LAPI mode nothing bounds an outage: every cache miss waits up to `lapiHttpTimeoutSeconds` per GET (IP query plus one per mapped header scope), then gets `bouncerLapiFailureAction`, and the next miss does the same. The WAF legs do have a gate, but while it backs off the request always continues as if the WAF were not configured. That fail-open choice is hard-coded, so an operator cannot pick it per router, and copying it to LAPI would let banned IPs through during a LAPI outage. Replaces closed PR #102, which `pkg/admission` (#190) superseded.

## What Changes

- **Backoff action per gated leg, per router.** New keys `bouncerLapiBackOffAction`, `bouncerAppsecBackOffAction`, `bouncerModsecBackOffAction`. Values `ban` / `passthrough` / `captcha`, same validation as the matching `bouncer*FailureAction`. The gate state stays one per connection (owner middleware). Each router resolves its own action when the connection reports a gate skip. FailureAction keeps covering real failures (timeout, 5xx, refused connection, the requests that trip the gate, a failed probe).
- **LAPI live/none admission gate.** New owner key `lapiUnhealthyBackOffPeriodSecs` (default 10, `>= 0`, `0` = no gate). The gate is built only in `live` and `none` and is ignored in `stream` / `alone`. It reuses `pkg/admission` with leg `lapi`, logs `crowdsec lapi backoff started` / `ended`, and is admitted before each live GET (IP and every header scope). A denied GET sends no HTTP and caches nothing. Health is "LAPI answered": a failure is a transport error, timeout, missing transport, 5xx, 429, or body read error; a success is any 2xx (parse errors included) and any other 4xx (401/403 included). Live cache hits never consult the gate. The key joins the LAPI Client ownership key (live/none only), not the DecisionStore identity.
- **WAF legs.** A gate skip (denied admission, or an unreadable body while backing off) on AppSec and ModSec applies that leg's backoff action instead of a hard-coded continue. With the default `passthrough` the behaviour while backing off does not change. A ModSec body over `modsecBodyLimit` stays HTTP 413.
- **BREAKING (default changes):**
  - `bouncerAppsecFailureAction` default `ban` → `passthrough`. An empty value now means `passthrough` for AppSec and still means `ban` for LAPI. With the new default, a streamed POST/PUT/PATCH body without a length on a router that sets no AppSec action reaches AppSec as a headers-only GET.
  - `appsecUnhealthyBackOffPeriodSecs` default 30 → 10.
  - `modsecUnhealthyBackOffPeriodSecs` default 0 (off) → 10.
  - New gate on LAPI `live` / `none` (default 10), with `bouncerLapiBackOffAction` default `ban`.
- **Observability.** Verdict header reasons `<kind>:lapi-backoff`, `<kind>:appsec-backoff`, `<kind>:modsec-backoff`, distinct from `<leg>-failure`. Metrics origins stay each leg's existing failure origin (`plugin:lapi_failure`, `plugin:appsec_failure`, `plugin:modsec_failure`). At startup, one WARN per router and subscribed leg when the backoff action is stricter than the failure action (passthrough < captcha < ban). It never rejects the config.
- **Docs.** `docs/failure-modes.md`, `docs/configuration.md`, `docs/how-it-works.md`, `docs/how-to/crowdsec-down.md`, `docs/modsecurity.md`, `docs/how-to/verdict-in-access-logs.md`, `README.md` where it states these defaults, and `examples/modsecurity/dynamic.yml`.

## Capabilities

### New Capabilities

- `core_plugin_lapi_admission-gate`: the LAPI `live` / `none` admission gate on `lapi.Client`. Covers when it is built, admission before each live GET, the skip (no HTTP, no cache write), how outcomes are classified, the log lines, and Close.

### Modified Capabilities

- `core_plugin_lapi_failure-action`: a live gate skip uses the per-router `bouncerLapiBackOffAction` (default `ban`), not the failure action. That action stays off the Client identity.
- `core_plugin_lapi_reclaim-key`: the LAPI ownership key adds `lapiUnhealthyBackOffPeriodSecs` in `live` / `none` only. `SessionHex` is unchanged.
- `core_plugin_lapi_query-round-trip`: a non-2xx answer (reverse-proxy statuses included) is a typed status error with the status code. Its message is byte-identical to today's.
- `core_plugin_appsec_client`: "AppSec Client owns the admission gate" is replaced by four requirements (gate, admission order, health recording, log lines). The gate default goes from 30 to 10. A denied admission is a gate skip that the bouncer answers with `bouncerAppsecBackOffAction`.
- `core_plugin_appsec_failure-action`: "CrowdsecAppsecFailureAction is the public AppSec fallback" becomes "bouncerAppsecFailureAction is the public AppSec fallback": default `passthrough`, and empty means `passthrough`. "Unhealthy skip is not a failure action" is replaced by "AppSec gate skip uses bouncerAppsecBackOffAction" and "The AppSec failure action still covers admitted misses".
- `core_plugin_modsecurity_client`: "ModSec Client owns the admission gate" is replaced by "ModSec Client holds one admission gate" (default 0 → 10) and "ModSec backoff logs once per transition".
- `core_plugin_modsecurity_inspect`: the requirement "Gate skip continues without the sidecar and without the failure action" is replaced by "Gate skip answers with the ModSec backoff action".
- `core_plugin_middleware_bouncer`: the closed header vocabulary gets six `*-backoff` values. A gate skip on any leg answers with that leg's backoff action. A backoff `captcha` is a `bypassCaptcha` source. Startup logs the stricter-than WARN.
- `core_plugin_middleware_config-validation`: "WAF backoff periods are the only gate knobs" is replaced by "Backoff periods are the only gate knobs" (three legs, each defaulting to 10, all in `requiredInt0`). The three backoff actions are validated like failure actions. An empty failure or backoff action resolves per leg.
- `build_e2e_pester_crowdsec-stack`: the WAF gate cases use the new defaults and a router with a non-default backoff action. A new LAPI live outage-and-recovery suite runs through a dedicated `lapi-flaky` proxy. Failure-action routes on a permanently down backend pin that leg's period to 0.

## Impact

- Code: `pkg/configuration` (four keys, three defaults, per-leg resolvers replace `EffectiveFailureAction`, validation), `pkg/lapi` (gate on `Client`, `ErrGateSkip`, typed status error in `sendQuery`, classification and `Record` in `queryLiveDecisions`, ownership key), `pkg/bouncer` (three backoff-action fields, skip mapping on all three legs, explicit header reason for the LAPI action writer, `*-backoff` header tokens, startup WARN), `pkg/appsec` (switch to the AppSec resolver; default constant 30 → 10). `pkg/admission` and `pkg/modsecurity` do not change.
- Tests: unit tests in `pkg/configuration`, `pkg/lapi`, `pkg/bouncer`, `pkg/appsec`, `pkg/modsecurity`. The tests that pin the old defaults are updated (`TestNew_ModsecAndAppsecBackoffDefaults`, `TestNew_omittedBackoffHasNoGate`, the message in `pkg/appsec/zzz_gate_test.go`). `tests/docs` keeps checking that every key is documented. Real e2e: `waf_backoff.Tests.ps1`, the new `lapi_backoff.Tests.ps1` (domain `lapi`), compose service `lapi-flaky`, and pins on `/lapi-fail-*` and `/modsec-fail-*`.
- Devdocs: `core_plugin_appsec.md`, `core_plugin_modsecurity_client.md`, `core_plugin_modsecurity_inspect.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_query-round-trip.md`, `core_plugin_lapi_connection.md`, `core_plugin_middleware_config-validation.md`, `build_e2e_real.md`.
- Operators: the four default changes above are breaking. The PR title carries the 💥 gitmoji.
- Out of scope: a gate on the rate-limit leg, a gate on the stream / alone / CAPI poll path, a gate on the captcha provider, exponential cooldown or jitter, a configurable trip rule, plumbing the inbound context into LAPI HTTP, and new metrics origins.
