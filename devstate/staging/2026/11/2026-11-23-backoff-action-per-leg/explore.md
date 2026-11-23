# Explore

## Concepts

### Units this change touches

| Unit | Path | Job today | Change |
| --- | --- | --- | --- |
| Config, defaults, validation | `pkg/configuration/configuration.go` | `Config` fields, `New()` defaults (`:250-335`), `validateFailureAction` (`:199-212`), `EffectiveFailureAction` (empty → ban, `:223-229`), `EffectiveModsecFailureAction` / `EffectiveRateLimitFailureAction` (empty → passthrough, `:231-247`), `requiredInt0` (`:917-928`), failure-action validation (`:946-955`) | 4 new keys, 3 changed defaults, per-leg effective resolvers, validation of the 3 BackOffActions (same rule as FailureAction, captcha needs an instance) and `LapiUnhealthyBackOffPeriodSecs` in `requiredInt0` |
| Admission gate | `pkg/admission/admission.go` | `New` / `Admit` / `Record` / `BackingOff` / `Close`, nil gate admits all | Reused as is for the LAPI leg. No change |
| LAPI ownership key | `pkg/lapi/identity.go` (`ownership`, `ownershipFrom`, `OwnershipKey`) | Reclaim Open key of one `lapi.Client` (middleware name plus Client knobs) | Add the LAPI cooldown (Decision Q8) |
| LAPI DecisionStore identity | `pkg/lapi/session.go` (`streamSession`, `sessionFrom`, `SessionHex`) | Store identity (cursor, cache) | No change (Decision Q8, `deviations.md`) |
| LAPI Client | `pkg/lapi/client.go` (`Client`, `New :108`, `Close :193`) | Owns HTTP, store binding, tickers | Holds the `*admission.Gate` (built only in `live` / `none`), `Close` closes it, `MsgBackoffStarted` / `MsgBackoffEnded` constants |
| LAPI round trip | `pkg/lapi/client_http.go` (`sendQuery :229-269`, `isReverseProxyError :124`) | One LAPI/CAPI exchange; every non-2xx and every transport error is a plain wrapped `error` | Non-2xx returns a typed status error with a byte-identical message (Decision Q4) |
| LAPI live query | `pkg/lapi/client_decisions.go` (`queryLiveDecisions :94-131`, `mergeLiveScope :179-190`) | One live GET per IP / header scope, parse, strongest decision | `Admit` before the GET, `Record` after it, `ErrGateSkip` on deny, no WARN per skipped scope |
| LAPI live lookup | `pkg/lapi/client_live.go` (`handleNoStreamCache :27-68`) | IP query, then scope queries, cache writes, first scope error wins | No structural change: a skip already writes nothing (IP error returns before any memo; a scope error blocks the clean IP memo, `:49-55`) |
| Bouncer per-router state | `pkg/bouncer/bouncer.go` (`Bouncer :20-48`, `New :64-140`) | Resolves `appsecFailureAction`, `lapiFailureAction`, `modsecFailureAction` | Three BackOffAction fields, per-leg resolvers, startup stricter-than WARN |
| LAPI serve | `pkg/bouncer/bouncer_serve_lapi.go` (`serveLAPI :19-80`, `applyLapiFailureAction :85-95`) | Live lookup error → FailureAction with a header reason derived from the origin | `lapi.ErrGateSkip` → BackOffAction, explicit header reason |
| AppSec serve | `pkg/bouncer/bouncer_serve_appsec.go` (`answerAppsecQueryError :89-107`) | `ErrGateSkip` → `return false` (`:91-93`) | `ErrGateSkip` → BackOffAction |
| ModSec serve | `pkg/bouncer/bouncer_serve_modsec.go` (`serveModSec :24-58`) | `ErrGateSkip` → `return false` (`:41-43`) | `ErrGateSkip` → BackOffAction |
| Verdict header | `pkg/bouncer/remediation_header.go` (reasons `:17-33`, `headerReasonFromOrigin :89-112`) | Closed reason tokens; failure reasons derived from the metrics origin | Three `*-backoff` tokens, passed explicitly, never derived from the origin |
| Captcha / ban writers | `pkg/bouncer/bouncer_serve_captcha.go` (`handleCaptchaKindServeHTTP :68`, `banWarnCaptchaRule :125`, `bypassesCaptcha :48`), `pkg/bouncer/bouncer_serve_remediation.go` (`handleRemediationServeHTTP :20`) | `banWarnCaptchaRule` and `handleCaptchaKindServeHTTP` already take an explicit header reason; `handleRemediationServeHTTP` derives it from the origin | Reused; the backoff captcha path calls `handleCaptchaKindServeHTTP` with the explicit reason |
| AppSec query | `pkg/appsec/query.go` (`resultForFailureAction :74-83`, `Query :118-208`, `newAppsecBodyRequest :262-283`) | Resolves the FailureAction itself (`EffectiveFailureAction` at `:75`, `:265`) | Switch to the AppSec resolver (empty → passthrough). Skip paths unchanged |
| AppSec client | `pkg/appsec/client.go` | Gate with `DefaultAppsecUnhealthyBackOffPeriodSecs` | Only the default moves (30 → 10) |
| ModSec inspect / client | `pkg/modsecurity/inspect.go :44-110`, `pkg/modsecurity/client.go :49-62` | Unreadable body while backing off and denied admission return `ErrGateSkip` | No change; the default moves (0 → 10) in config |
| Metrics origins | `pkg/lapi/client_metrics.go :20-34` | `plugin:lapi_failure`, `plugin:appsec_failure`, `plugin:modsec_failure` | No new origin; backoff answers count under these |
| Usage docs | `docs/failure-modes.md`, `docs/configuration.md`, `docs/how-it-works.md`, `docs/how-to/crowdsec-down.md`, `docs/modsecurity.md`, `docs/how-to/verdict-in-access-logs.md`, `README.md`, `examples/modsecurity/dynamic.yml` | Say only the WAFs back off, AppSec default ban and 30 s, ModSec gate off, no failure action while skipping | Rewrite per requirement section 6. `tests/docs` `TestConfigurationDocCoversEverySetting` fails until the 4 new keys have a `docs/configuration.md` entry |
| Devdocs packets | `knowledge/devdocs/build_e2e_real.md`, `core_plugin_appsec.md`, `core_plugin_modsecurity_client.md`, `core_plugin_modsecurity_inspect.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_query-round-trip.md`, `core_plugin_lapi_connection.md`, `core_plugin_middleware_config-validation.md` | Name the old defaults (AppSec 30 s, ModSec off) and the old skip rule | Devdocs impact phase; listed here so propose plans the edit |

### How they connect

```
 router A (Bouncer, per-router actions)          owner middleware (connection, shared gate)
 ┌──────────────────────────────────────┐        ┌────────────────────────────────────────┐
 │ serveLAPI ── LiveLookup ─────────────┼──────▶ │ lapi.Client                            │
 │   err == lapi.ErrGateSkip            │        │   handleNoStreamCache                  │
 │     → bouncerLapiBackOffAction       │        │     queryLiveDecisions (ip=, scope=…)  │
 │     header <kind>:lapi-backoff       │        │       gate.Admit ─ deny → ErrGateSkip  │
 │     origin plugin:lapi_failure       │        │       sendQuery → classify → Record    │
 │   other err → bouncerLapiFailureAct. │        │   gate: admission.Gate (live/none)     │
 ├──────────────────────────────────────┤        ├────────────────────────────────────────┤
 │ answerAppsecQueryError               │        │ appsec.Client.Query                    │
 │   ErrGateSkip → AppsecBackOffAction  │◀───────┤   unreadable body + BackingOff / deny  │
 │     header <kind>:appsec-backoff     │        │     → ErrGateSkip                      │
 ├──────────────────────────────────────┤        ├────────────────────────────────────────┤
 │ serveModSec                          │        │ modsecurity.Client.Inspect             │
 │   ErrGateSkip → ModsecBackOffAction  │◀───────┤   unreadable body + BackingOff / deny  │
 │     header <kind>:modsec-backoff     │        │     → ErrGateSkip                      │
 └──────────────────────────────────────┘        └────────────────────────────────────────┘
   router B uses the same Clients (Watch) with its own actions; the gate state is one per connection.
```

### Call sites that matter (roots searched: every non-vendor `*.go` under the worktree)

- `EffectiveFailureAction`: 4 production callers. `pkg/appsec/query.go:75` (`resultForFailureAction`), `pkg/appsec/query.go:265` (`newAppsecBodyRequest`, unreadable-body choice), `pkg/bouncer/bouncer.go:101` (AppSec), `pkg/bouncer/bouncer.go:110` (LAPI). No test calls it directly.
- `EffectiveModsecFailureAction`: `pkg/bouncer/bouncer.go:111`, `pkg/modsecurity/inspect.go:49`, `pkg/bouncer/zzz_modsec_test.go:44`, `pkg/configuration/zzz_configuration_test.go:1204-1208`.
- `ErrGateSkip` handling: `pkg/bouncer/bouncer_serve_appsec.go:91`, `pkg/bouncer/bouncer_serve_modsec.go:41`. Producers: `pkg/appsec/query.go:123,138`, `pkg/modsecurity/inspect.go:52,74`.
- `applyLapiFailureAction`: 3 callers, `pkg/bouncer/bouncer_serve_lapi.go:25` (no client), `:61` (stream unhealthy), `:69` (live error).
- `sendQuery` / `crowdsecQuery`: `queryLiveDecisions` (`client_decisions.go:101`, live), `streamQuery` (`client_stream.go:116`, stream/alone), `getToken` (`client_http.go:185`, alone login), the alone 401 replay (`client_http.go:256`), and `crowdsecQuery` itself (`:223`). Only the first is classified for the gate.
- Message assertions on `sendQuery` errors in tests: `pkg/lapi/zzz_client_http_test.go:206` (`getToken statusCode:`), `:396` (`statusCode:503`). A typed error with the same `Error()` text keeps both.

### Reproduce

- **LAPI live/none re-hits a dead backend: reproduced.** Throwaway test (written in `pkg/lapi`, run, deleted; not committed): a live and a none Client against an `httptest` server answering 503, 20 `LiveLookup` calls with one mapped header scope. Result: `mode=live lookups=20 failures=20 backendHits=20` and `mode=none lookups=20 failures=20 backendHits=20`. Every miss calls LAPI again; with a timeout instead of a 503, every miss waits `lapiHttpTimeoutSeconds`. The IP query fails first, so the scope query is never sent (1 hit per lookup, not 2).
- **WAF `ErrGateSkip` ignores any per-router action: reproduced with the in-tree test.** `go test ./pkg/bouncer -run TestServeHTTP_modsecGateSkipPassesWithoutFailureAction` passes: a router with `bouncerModsecFailureAction: ban` gets 5 `ban:modsec-failure`, then the request reaches the origin with no header and no sidecar call. No per-router knob exists for that skip (`bouncer_serve_modsec.go:41-43`, `bouncer_serve_appsec.go:91-93`).
- **Unit tests that pin the old WAF defaults: measured.** Throwaway edit of `configuration.New()` (AppSec FailureAction passthrough, AppSec cooldown 10, ModSec cooldown 10), `go test ./... -count=1`, reverted. Fails: `pkg/configuration` `TestNew_ModsecAndAppsecBackoffDefaults`, `pkg/modsecurity` `TestNew_omittedBackoffHasNoGate`. Every other package passes. `pkg/appsec/zzz_gate_test.go:44-48` compares to the constant and only its message says 30.
- **AppSec empty-action resolution: measured.** Throwaway edit mapping an empty AppSec action to passthrough in `pkg/appsec/query.go:75,265` and `pkg/bouncer/bouncer.go:101`, `go test ./pkg/appsec ./pkg/bouncer . -count=1`, reverted: all pass. The 14 `Query(..., Policy{})` calls in `pkg/appsec/zzz_query_test.go` do not depend on empty meaning ban.

### Outside facts used

In-tree only. `backendbackoff.Gate.Allow` read from `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff/allow.go:8-43`.

### Notes for later phases

- Pre-existing asymmetry, not widened: an AppSec or ModSec failure-action captcha that downgrades to a ban (captcha client unusable) shows ban-template reason `LAPI`, because `handleRemediationServeHTTP` hard-codes `configuration.ReasonLAPI` (`bouncer_serve_remediation.go:24-26`). The backoff captcha path should pass its leg's reason (`APPSEC` / `MODSEC`) to `handleCaptchaKindServeHTTP` directly. Follow-up in `issues.md`.
- Real e2e routes that run against a dead backend and would trip the new default gates: `/lapi-fail-ban` and `/lapi-fail-pass` (`docker-compose.test.yml:348-380`, none mode on `crowdsec:9`; `Test-Integration.ps1:240-241` polls them for readiness, `failure_action.Tests.ps1:14-23` asserts them), `/modsec-fail-pass|ban|captcha` (`config/dynamic/modsec.yml`, no `modsecUnhealthyBackOffPeriodSecs`), and `/waf-backoff-default` (`waf_backoff.Tests.ps1:49-79` asserts the old AppSec defaults: ban, 30 s). `/lapi-fail-pass` is exactly the stricter-than case (FailureAction passthrough, default BackOffAction ban): after 5 requests it would answer 403 `ban:lapi-backoff`.
- `tests/e2e/mock` live/none scenarios run against a healthy mocklapi; `tls-system-ca` sends one failing request. Not affected.
- Live contracts to modify in propose: `core_plugin_appsec_client` (default 30, skip "SHALL NOT apply FailureAction"), `core_plugin_appsec_failure-action` (default ban, "Unhealthy skip is not a failure action"), `core_plugin_modsecurity_inspect` ("Gate skip continues without the sidecar and without the failure action"), `core_plugin_modsecurity_client` (default off), `core_plugin_lapi_failure-action` (live error), `core_plugin_lapi_reclaim-key` (ownership knobs), `core_plugin_lapi_query-round-trip` (typed status error), `core_plugin_middleware_bouncer` (header reasons), `core_plugin_middleware_config-validation` (new keys), `build_e2e_pester_crowdsec-stack` (routes, pins, LAPI cycle).

## Decisions

- Per-leg effective resolvers in `pkg/configuration`: `EffectiveLapiFailureAction` (empty → ban), `EffectiveAppsecFailureAction` (empty → passthrough), the existing `EffectiveModsecFailureAction` and `EffectiveRateLimitFailureAction`, and `EffectiveLapiBackOffAction` (empty → ban), `EffectiveAppsecBackOffAction` / `EffectiveModsecBackOffAction` (empty → passthrough). `EffectiveFailureAction` is removed and its 4 callers migrate.
- `CreateConfig` defaults: `BouncerAppsecFailureAction: passthrough`, `AppsecUnhealthyBackOffPeriodSecs: 10`, `ModsecUnhealthyBackOffPeriodSecs: 10`, `LapiUnhealthyBackOffPeriodSecs: 10`, `BouncerLapiBackOffAction: ban`, `BouncerAppsecBackOffAction: passthrough`, `BouncerModsecBackOffAction: passthrough`.
- LAPI gate: built in `lapi.New` only for `live` / `none`, closed in `Close`, key `lapi`, lines `crowdsec lapi backoff started` / `ended`. `Admit(context.Background())` before each GET in `queryLiveDecisions`; deny → `lapi.ErrGateSkip`, no HTTP, nothing cached.
- LAPI health classification on the live path only, through a typed status error returned by `sendQuery` for every non-2xx (message unchanged), classified in `queryLiveDecisions` before parsing.
- `ErrGateSkip` from every leg maps to that leg's BackOffAction in the bouncer; header `<kind>:<leg>-backoff`; metrics origin = the leg's failure origin.
- Header reason passed explicitly to the writers; `headerReasonFromOrigin` keeps mapping each failure origin to its failure reason.
- Stricter-than WARN logged once per router and subscribed leg in `bouncer.New`.
- Real e2e LAPI backoff through a dedicated nginx proxy that only one new route uses.
- Rejected: an "inherit FailureAction" rule for BackOffAction (owner chose static defaults). Rejected: classifying inside `sendQuery` with a gate parameter (stream/alone and `getToken` share it; a typed error keeps them untouched). Rejected: plumbing the inbound context into `Admit` / `sendQuery` (out of scope). Rejected: putting the cooldown in `SessionHex` (would drop the DecisionStore on a cooldown change). Rejected: stopping `crowdsec` in e2e (shared by every suite, `build_e2e_real.md` Gotchas).
- Live contract: yes, the ten specs listed under Notes for later phases.

## Open questions

- Q: Can the real e2e stack stop LAPI for a live-backoff test without breaking other suites?
  Rank: additive asked — new compose service, new route, new cases; existing suites keep their routes; requirement section 7 asks for the LAPI live backoff case when the stack allows it
  Decision: assumed — yes, without stopping `crowdsec`. Add compose service `lapi-flaky` (`nginx:alpine`, container `lapi-flaky-test`, `config/lapi-flaky.conf` with `resolver 127.0.0.11` and a `set $lapi http://crowdsec:8080` `proxy_pass`, the `appsec-flaky.conf` shape). Add one `live` middleware/router `/lapi-cycle` in a file-provider YAML with `lapiHost: lapi-flaky:80`, its own key `BOUNCER_KEY_LAPI_BACKOFF` (next free `c51a1c70…1c`, registered in the crowdsec env list), `lapiUnhealthyBackOffPeriodSecs: 10`, `lapiHttpTimeoutSeconds: 2`, `lapiMetricsUpdateIntervalSeconds: 0`, `reclaimGraceSeconds: 2`, JSON log, verdict header. Cycle: one fresh `X-Forwarded-For` per request (live caches a clean answer for `lapiDefaultDecisionSeconds`); stop `lapi-flaky-test`, 5 × `ban:lapi-failure`, then fast `ban:lapi-backoff` (assert elapsed well under the 2 s timeout), exactly one `crowdsec lapi backoff started`; start it, wait for 200, exactly one `crowdsec lapi backoff ended`; `AfterAll` starts the container. Place it in `waf_backoff.Tests.ps1` (domain `modsec`, which already owns stop/start cycles) or a new `lapi_backoff.Tests.ps1` registered in `PesterDomains.ps1` `lapi`; propose picks. Non-default WAF BackOffAction: a second router subscribing to the `/appsec-cycle` AppSec instance by name with `bouncerAppsecBackOffAction: ban`, proving the shared gate and the per-router action in the same outage.
  By: explore

- Q: What does an empty or omitted `bouncerAppsecFailureAction` mean now, and how is the default made per leg?
  Rank: bounded asked — changes `EffectiveFailureAction`, whose 4 production callers were enumerated (`pkg/appsec/query.go:75,265`, `pkg/bouncer/bouncer.go:101,110`; roots: every non-vendor `*.go`) and migrate here; requirement section 2 names AppSec FailureAction `passthrough` and LAPI `ban`
  Decision: resolved — owner: empty AppSec means `passthrough`, empty LAPI stays `ban`. Replace the shared `EffectiveFailureAction` with per-leg resolvers next to the existing `EffectiveModsecFailureAction` / `EffectiveRateLimitFailureAction`: `EffectiveLapiFailureAction` (ban) for `bouncer.go:110`, `EffectiveAppsecFailureAction` (passthrough) for `bouncer.go:101` and `query.go:75,265`; same shape for the three BackOffActions. `validateFailureAction`'s comment ("empty treated as ban") becomes per leg. Measured: no existing test depends on empty meaning ban for AppSec (the `Policy{}` tests in `pkg/appsec/zzz_query_test.go` pass with empty → passthrough).
  By: explore

- Q: Does ModSec's unreadable-body path while backing off also resolve to the BackOffAction?
  Rank: additive asked — no new call site: `modsecurity.Inspect` already returns `ErrGateSkip` there (`inspect.go:48-53`), only the bouncer mapping changes; requirement section 4 "`ErrGateSkip` in AppSec and ModSec now applies `bouncer<Leg>BackOffAction`"
  Decision: resolved — owner: yes. General rule: every `ErrGateSkip` (denied admission or unreadable body while backing off, AppSec and ModSec alike) → that leg's BackOffAction in the bouncer. `pkg/appsec` and `pkg/modsecurity` stay as they are.
  By: explore

- Q: How do a backoff answer's header reason and its metrics origin differ when `applyLapiFailureAction` derives the reason from the origin?
  Rank: bounded asked — changes `applyLapiFailureAction` (3 callers, `bouncer_serve_lapi.go:25,61,69`, all migrated); requirement section 5 names the `<leg>-backoff` reason and the reused failure origin
  Decision: resolved — owner: decoupled. The LAPI action writer takes the header reason as a parameter (`lapi-failure`, `stream-unhealthy`, or `lapi-backoff`) instead of `headerReasonFromOrigin(origin)`; its captcha branch calls `bypassesCaptcha` then `handleCaptchaKindServeHTTP` with that reason, the ban branch `banWarnCaptchaRule` with it. The AppSec and ModSec backoff writers do the same with `appsec-backoff` / `modsec-backoff` and `OriginPluginAppsecFailure` / `OriginPluginModsecFailure`. `headerReasonFromOrigin` is unchanged.
  By: explore

- Q: Which live LAPI GET outcomes count as a failure for the gate, and how is that decided without changing stream/alone polling?
  Rank: bounded asked — changes the `sendQuery` error type; its callers were enumerated (`queryLiveDecisions`, `streamQuery`, `getToken`, the alone 401 replay, `crowdsecQuery`; `pkg/lapi/*.go`) and only `queryLiveDecisions` reads the new type; requirement section 3 lists the success and failure sets
  Decision: resolved — owner: failure = transport error / timeout, missing transport, any 5xx, 429, body read error; success = any 2xx (parsed or not, JSON and duration parse errors included) and every 4xx other than 429 (401/403 included: FailureAction still applies). `sendQuery` returns an unexported typed status error (status code plus the current message text, byte-identical, so `zzz_client_http_test.go:206,396` and stream logs do not change) for the reverse-proxy branch and the non-2xx branch. `queryLiveDecisions` classifies right after `crowdsecQuery` and before parsing, then `Record`s. Stream, alone, `getToken` and the 401 renewal ignore the type.
  By: explore

- Q: Can `admission.Gate.Admit(context.Background())` block?
  Rank: additive asked — reads existing code; requirement section 3 chooses `context.Background()`
  Decision: resolved — no. `Admit` only checks `ctx.Err()` (never true for `Background`) and calls `backendbackoff.Gate.Allow`, which takes one mutex, reads the key state and returns a `Permit` and a wait duration without sleeping or waiting on a channel (`vendor/.../backendbackoff/allow.go:8-43`). It returns an error only after `Close` (`errClosed`). LAPI treats that admission error as a failure (FailureAction, no HTTP), the same as AppSec (`query.go:134-135`) and ModSec (`inspect.go:66-72`).
  By: explore

- Q: What happens to a streamed POST/PUT/PATCH body without a length on a router with no `bouncerAppsecFailureAction`?
  Rank: additive asked — behaviour follows from the new default, no code; requirement section 2 changes the AppSec default
  Decision: resolved — owner: accepted. With the default `passthrough`, `newAppsecBodyRequest` (`query.go:264-268`) sends that request to AppSec as a headers-only GET instead of applying the failure action. Document it in `docs/failure-modes.md:142`, `docs/configuration.md` (`bouncerAppsecFailureAction`) and `docs/modsecurity.md:35` where they describe the rule; no code.
  By: explore

- Q: Which LAPI identity carries `lapiUnhealthyBackOffPeriodSecs`?
  Rank: additive asked — adds one field to the existing ownership payload; existing callers of `OwnershipKey` keep working; requirement section 3 asks to add the key to the LAPI identity "like AppSec does in `pkg/appsec/session.go`"
  Decision: assumed — the LAPI `ownership` payload in `pkg/lapi/identity.go` (`OwnershipKey`, the Client Open key), not `streamSession` in `pkg/lapi/session.go` (`SessionHex`, the DecisionStore identity). AppSec's `identity` in `pkg/appsec/session.go` is its Open key, so the matching LAPI unit is `ownership`; the gate lives on `lapi.Client`, which `OwnershipKey` reclaims. Putting it in `SessionHex` would open a new DecisionStore (cache, stream cursor) on a cooldown change. Set the field only in `live` / `none` (0 otherwise), so a stream/alone Client does not reopen for a knob it ignores. Test shape: `TestKey_NoneMetricsIntervalSplitsClientKeepsStore` (`zzz_session_test.go:105`). Recorded in `deviations.md`.
  By: explore

- Q: When does the stricter-than WARN fire, given a router does not know its LAPI connection's mode at `New`?
  Rank: additive asked — new log line in `bouncer.New`; requirement section 5 "Proposed (include)"
  Decision: assumed — once per router and leg in `bouncer.New`, only for legs the router subscribes to (`Subscriptions`), when the effective BackOffAction ranks above the effective FailureAction (passthrough < captcha < ban). For LAPI, skip it when this router opens LAPI itself in `stream` / `alone` (its own `LapiMode`); a router that only subscribes cannot know the mode and warns. Message names both keys and values, e.g. `crowdsec bouncer backoff action stricter than failure action` with `leg`, `failureAction`, `backOffAction`. Never an error.
  By: explore

- Q: Which existing tests and e2e routes depend on the old defaults or on an ungated LAPI?
  Rank: bounded asked — edits existing tests and compose routes; enumerated by a measured default flip (`go test ./...`) and a grep of `tests/e2e` for dead backends; requirement section 7 "Update every existing test and e2e assertion that depends on the old defaults"
  Decision: assumed — unit: `pkg/configuration` `TestNew_ModsecAndAppsecBackoffDefaults`, `pkg/modsecurity` `TestNew_omittedBackoffHasNoGate`, the message of `pkg/appsec/zzz_gate_test.go:44-48`, plus new tests for the per-leg resolvers (no existing AppSec `Policy{}` test needs a change, measured). E2E: pin `lapiUnhealthyBackOffPeriodSecs=0` on `/lapi-fail-ban` and `/lapi-fail-pass` (otherwise the readiness probe and `failure_action.Tests.ps1` see `ban:lapi-backoff`); pin `modsecUnhealthyBackOffPeriodSecs: "0"` on the three `/modsec-fail-*` middlewares in `config/dynamic/modsec.yml`; rewrite the `/waf-backoff-default` case for the new defaults (passthrough, 10 s: origin 200 throughout, listener hits ≤ 5, one `backoff started`); update the header comments of `waf-backoff.yml` and `waf_backoff.Tests.ps1`. Mock AppSec scenarios already set `bouncerAppsecFailureAction: ban` explicitly (`tests/e2e/mock/scenarios/appsec`, `appsec-captcha`, `request-bypass-rules`); for them only the packaged cooldown moves (30 → 10), and `appsec` and `request-bypass-rules` pin it to `0`.
  By: explore

- Q: What does a mixed outcome across the IP query and the header-scope queries of one lookup resolve to?
  Rank: additive asked — no new rule: `handleNoStreamCache` already returns the IP error first and otherwise the first scope error (`client_live.go:31-66`); requirement section 3 gates every scope GET
  Decision: assumed — keep the existing order. IP query skipped → `ErrGateSkip` → BackOffAction. IP query answered and the first failing scope skipped → BackOffAction; first failing scope a real failure → FailureAction. An active remediation from any answered query still wins over both. `mergeLiveScope` does not WARN for `ErrGateSkip` (one line per skipped request would defeat the gate's single WARN).
  By: explore
