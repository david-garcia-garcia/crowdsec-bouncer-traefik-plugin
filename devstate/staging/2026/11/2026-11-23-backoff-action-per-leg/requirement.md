# Requirement
IssueKey: 2026-11-23-backoff-action-per-leg

The caller spec below is a complete, owner-approved product design (issueHost: local). It is copied in full and verbatim from `ticket/source.md`. The sections after it are prepare grounding against `origin/master` @ `aa6d0be3`; they do not change the spec.

---

# Per-router backoff action for every gated leg, a LAPI live/none admission gate, and new failure defaults

Owner-approved design (chat, 2026-11-23). Replaces closed PR #102 (six `backendBackoff*` knobs, superseded by `pkg/admission` from #190). Every decision below is DECIDED by the owner unless marked "proposed"; do not reopen them.

## Problem

1. In `live` / `none` LAPI mode there is no admission gate (`docs/failure-modes.md` rule 3: "Only the WAFs back off"). With LAPI down, every cache miss waits up to `lapiHttpTimeoutSeconds` (default 10) per GET (IP query plus one per mapped header scope) and then gets `bouncerLapiFailureAction`. The next request does the same.
2. While the AppSec / ModSec gate is backing off, the request always continues as if the WAF were not configured (`ErrGateSkip` → `return false` in `pkg/bouncer/bouncer_serve_appsec.go` and `pkg/bouncer/bouncer_serve_modsec.go`). That fail-open choice is hard-coded; an operator cannot pick it per router. Copying that semantic to LAPI would let banned IPs through during a LAPI outage.

## Design

### 1. Two actions per gated leg, both per router

| Situation | Setting | Values |
| --- | --- | --- |
| Real failure: timeout, 5xx, refused connection, the requests that trip the gate, a failed probe | `bouncer<Leg>FailureAction` (exists) | `ban` / `passthrough` / `captcha` |
| The gate is backing off and the backend is not called | `bouncer<Leg>BackOffAction` (NEW) | `ban` / `passthrough` / `captcha` |

New keys: `bouncerLapiBackOffAction`, `bouncerAppsecBackOffAction`, `bouncerModsecBackOffAction`. Same scope, validation and value set as the matching `bouncer*FailureAction` (per router). The gate state stays per connection (owner middleware); the action is resolved by the bouncer of each router when the client returns `ErrGateSkip`.

### 2. Defaults (owner-chosen, static per leg, no "inherit FailureAction" rule)

| Leg | FailureAction | BackOffAction | Cooldown `<leg>UnhealthyBackOffPeriodSecs` |
| --- | --- | --- | --- |
| AppSec | `passthrough` (CHANGED from `ban`) | `passthrough` | `10` (CHANGED from 30) |
| ModSec | `passthrough` (unchanged) | `passthrough` | `10` (CHANGED from 0 = off) |
| LAPI live/none | `ban` (unchanged) | `ban` | `10` (NEW key `lapiUnhealthyBackOffPeriodSecs`) |

The three CHANGED defaults are breaking default changes: the PR/commit title uses the 💥 gitmoji and the docs say so.

### 3. LAPI live/none admission gate

- New key `lapiUnhealthyBackOffPeriodSecs` (`int64`, default 10, must be >= 0, `0` = no gate). Set on the middleware that connects to LAPI (connection owner), like `appsecUnhealthyBackOffPeriodSecs`. Add it to `requiredInt0` validation and to the LAPI session identity (`pkg/lapi/session.go`), like AppSec does in `pkg/appsec/session.go`.
- Reuse `pkg/admission` (`admission.New`, `Admit`, `Record`, `BackingOff`, `Close`). Gate key/leg `lapi`. Log lines `crowdsec lapi backoff started` (WARN, `retryIn`) and `crowdsec lapi backoff ended` (INFO). Gate owned by `lapi.Client`, closed with it. Shared by every router that uses the connection (owner Open + SetAlias, routers Watch — every leg is shared).
- Build the gate only in `live` and `none` modes. In `stream` / `alone` no gate is built and the key is ignored (they already have `lapiUpdateMaxFailure` / `StreamHealthy`). Document that.
- `Admit` before EACH live GET in `queryLiveDecisions` (the IP query and every header-scope query), not once per lookup.
- Denied → no HTTP; return a sentinel `lapi.ErrGateSkip` with an empty remediation; nothing is written to the live cache. `serveLAPI` maps it to `bouncerLapiBackOffAction`.
- Admitted → GET, then `Record`:
  - failure: transport error / timeout, any 5xx (including 502/503/504 from `isReverseProxyError`), body read error, missing transport;
  - success: 2xx parsed (ban, captcha or no decision — health is "LAPI answered", not the remediation kind); 401/403 (wrong key: configuration error, not an outage — FailureAction keeps applying on every request, same rule as the AppSec 401); JSON / duration parse errors (LAPI answered; FailureAction still applies as today).
- `Admit` gets `context.Background()` (or equivalent). Do NOT plumb the inbound request context into the LAPI GET in this change (`sendQuery` builds the request without a ctx today; changing that changes cancel semantics).
- Live cache hits are unchanged and never consult the gate.

### 4. WAF legs

- `ErrGateSkip` in AppSec and ModSec now applies `bouncer<Leg>BackOffAction` instead of the hard-coded continue. With the default `passthrough` the behaviour while backing off is unchanged.
- AppSec unreadable-body path (`errUnreadableBody` while `gate.BackingOff()`) also resolves to the BackOffAction (it already returns `ErrGateSkip`).
- ModSec body over `modsecBodyLimit` stays HTTP 413 (not a backoff case).

### 5. Observability

- Verdict header reason for a backoff action: `<kind>:<leg>-backoff` (`ban:lapi-backoff`, `captcha:appsec-backoff`, `ban:modsec-backoff`), distinct from `<leg>-failure`.
- Metrics origin (cscli `origin`): REUSE each leg's existing failure origin (e.g. `plugin:lapi_failure`); do not add new origins.
- Proposed (include): at startup, log one WARN per router and leg when the BackOffAction is stricter than the FailureAction (order passthrough < captcha < ban), e.g. `bouncerLapiFailureAction: passthrough` with the default `bouncerLapiBackOffAction: ban`. Never reject the config for it.

### 6. Docs (usage docs under `docs/`)

- `docs/failure-modes.md`: "At a glance" table (AppSec / ModSec / LAPI live/none rows and the "connection not there" row that today says "Ban on LAPI and AppSec"), rule 3 ("Only the WAFs back off" becomes false), the LAPI section (live/none), the "When a WAF is down" section (two actions, new defaults, state diagram text "no failure action" → "backoff action"), verdict header table, alerting lines.
- `docs/configuration.md`: new keys `bouncerLapiBackOffAction`, `bouncerAppsecBackOffAction`, `bouncerModsecBackOffAction`, `lapiUnhealthyBackOffPeriodSecs`; changed defaults of `bouncerAppsecFailureAction`, `appsecUnhealthyBackOffPeriodSecs`, `modsecUnhealthyBackOffPeriodSecs` (and the text of `bouncerAppsecFailureAction` that says the action "does not apply" while backing off).
- `docs/how-it-works.md` connection/router table, `docs/how-to/crowdsec-down.md`, `docs/modsecurity.md` (says the gate is "off by default"), `docs/how-to/verdict-in-access-logs.md` if it lists reasons, README if it lists these defaults.

### 7. Tests

- Unit: LAPI live and none — trip after 5 failures, next lookup does not hit the test server and gets the BackOffAction, header-scope GETs are gated too, probe after cooldown recovers and logs `ended`, 401 does not trip, stream/alone build no gate, `0` builds no gate, nothing cached on skip.
- Unit: per-router BackOffAction for all three legs and all three values; defaults; validation of the new keys; the stricter-than WARN.
- Update every existing test and e2e assertion that depends on the old defaults (AppSec FailureAction `ban`, AppSec cooldown 30, ModSec gate off).
- Real e2e (`tests/e2e/real/waf_backoff.Tests.ps1`): cover a non-default BackOffAction on a WAF, and add LAPI live backoff (stop LAPI, trip, fast `ban:lapi-backoff`, restart, recovery) if the real stack allows stopping LAPI without breaking other suites; otherwise record why on the card.

## Out of scope

- Rate-limit leg (has FailureAction, no gate).
- Exponential cooldown, jitter, configurable trip rule (fixed in `pkg/admission` on purpose).
- Plumbing the inbound context into LAPI HTTP.

---

# Prepare grounding (dest `master` @ `aa6d0be3`)

## Current (code)

- LAPI live/none has no gate. `queryLiveDecisions` GETs through `crowdsecQuery` with no admission step: `pkg/lapi/client_decisions.go:94`. The IP query is in `handleNoStreamCache` (`pkg/lapi/client_live.go:21-80`); each header scope is another `queryLiveDecisions` call from `mergeLiveScope` (`pkg/lapi/client_decisions.go:183`).
- `sendQuery` builds the GET with `http.NewRequest` (no ctx). Missing transport, transport error, 502/503/504 (`isReverseProxyError`, `pkg/lapi/client_http.go:124`), any non-2xx (including 401/403 outside alone mode) and a body read error all come back as a plain wrapped `error`, with no typed classification: `pkg/lapi/client_http.go:229-270`.
- JSON / duration parse errors are returned by `queryLiveDecisions` after the GET: `pkg/lapi/client_decisions.go:110-124`.
- `serveLAPI` maps a live/none lookup error with a non-active kind to `applyLapiFailureAction(..., ReasonLAPI, OriginPluginLapiFailure)`: `pkg/bouncer/bouncer_serve_lapi.go:64-71`. Stream/alone unhealthy miss uses `ReasonTECH` + `OriginPluginTechStreamFail`: `pkg/bouncer/bouncer_serve_lapi.go:56-62`.
- The LAPI session identity (`streamSession`, `sessionFrom`) has no backoff field: `pkg/lapi/session.go`. AppSec carries `UnhealthyBackOffPeriodSecs` in its identity: `pkg/appsec/session.go:30,49`. ModSec does the same: `pkg/modsecurity/session.go:34`.
- `lapi.Client` holds no gate; `Close` is `pkg/lapi/client.go:193`.
- `pkg/admission`: `New` returns a nil gate when `PeriodSecs <= 0`; `Config` has `Leg`, `PeriodSecs`, `MsgStarted`, `MsgEnded`; methods `Admit(ctx)`, `Report`, `Record`, `BackingOff`, `Close`, `Inner`: `pkg/admission/admission.go:25-158`.
- AppSec gate: `admission.New` with `gateKey = "appsec"` and `MsgBackoffStarted` / `MsgBackoffEnded` ("crowdsec appsec backoff started" / "ended"): `pkg/appsec/client.go:25-31,89-94`. ModSec gate: same shape with `modsec`: `pkg/modsecurity/client.go:25-31,59-62`.
- AppSec `ErrGateSkip` (`pkg/appsec/query.go:64`) is returned on a denied admission (`pkg/appsec/query.go:137-138`) and on `errUnreadableBody` while `gate.BackingOff()` (`pkg/appsec/query.go:120-124`). The bouncer returns `false` (continue) on it: `pkg/bouncer/bouncer_serve_appsec.go:91-93`.
- ModSec `ErrGateSkip` (`pkg/modsecurity/inspect.go:30`) is returned on an unreadable body while backing off (`pkg/modsecurity/inspect.go:48-53`) and on a denied admission. The bouncer returns `false` on it: `pkg/bouncer/bouncer_serve_modsec.go:41-43`. Body over `modsecBodyLimit` → 413: `pkg/bouncer/bouncer_serve_modsec.go:44-47`.
- Per-router failure actions live on `Bouncer` (`appsecFailureAction`, `lapiFailureAction`, `modsecFailureAction`), resolved with `EffectiveFailureAction` / `EffectiveModsecFailureAction`: `pkg/bouncer/bouncer.go:22-35,101-111`. No BackOffAction field: not found.
- Defaults: `DefaultAppsecUnhealthyBackOffPeriodSecs = 30` (`pkg/configuration/configuration.go:67`); `BouncerAppsecFailureAction: ban`, `BouncerLapiFailureAction: ban`, `BouncerModsecFailureAction: passthrough` (`pkg/configuration/configuration.go:262,270,271`); `ModsecUnhealthyBackOffPeriodSecs: 0` (`pkg/configuration/configuration.go:320`). `lapiUnhealthyBackOffPeriodSecs`: not found.
- `EffectiveFailureAction("")` → `ban` (shared by LAPI and AppSec): `pkg/configuration/configuration.go:223-229`. `validateFailureAction` accepts empty, `passthrough`, `ban`, `captcha`, and rejects `captcha` without a captcha instance: `pkg/configuration/configuration.go:199-214`.
- `requiredInt0` holds `AppsecUnhealthyBackOffPeriodSecs` and `ModsecUnhealthyBackOffPeriodSecs`, no LAPI key: `pkg/configuration/configuration.go:917-928`.
- Verdict header reasons: `lapi-failure`, `appsec-failure`, `modsec-failure`; no `*-backoff` reason: `pkg/bouncer/remediation_header.go:19-29`.
- Startup WARN when BackOffAction is stricter than FailureAction: not found.
- Docs: rule 3 "Only the WAFs back off" `docs/failure-modes.md:53`; "At a glance" AppSec row ("Ban the first failures, then ... 30 seconds") `docs/failure-modes.md:28`; "When a WAF is down" `docs/failure-modes.md:93-149`; verdict and alerting lines `docs/failure-modes.md:204-212`. `docs/configuration.md:362,410,656,684` say the failure action does not apply while the gate skips. `docs/modsecurity.md:207` says the gate is "off by default"; `docs/modsecurity.md:35` states the skip rule for unknown-length bodies. `docs/how-it-works.md:67-68` connection/router table. `docs/how-to/crowdsec-down.md:18` says only AppSec and ModSec have a gate. `docs/how-to/verdict-in-access-logs.md:17,31` list the `*:lapi-failure` reasons. `README.md:22` names the three failure actions without defaults.
- Real e2e: `tests/e2e/real/waf_backoff.Tests.ps1`; LAPI live/none suites `tests/e2e/real/mode_live.Tests.ps1`, `tests/e2e/real/mode_none.Tests.ps1`; `tests/e2e/real/failure_action.Tests.ps1`.

## Desired

As the spec above, sections 1 to 7. Nothing added.

## Affected

- `pkg/configuration/configuration.go` (new keys, defaults, validation).
- `pkg/lapi` (gate on `Client`, `ErrGateSkip`, failure/success classification in the live GET path, session identity).
- `pkg/bouncer` (`serveLAPI`, `answerAppsecQueryError`, `serveModSec`, BackOffAction fields, header reasons, startup WARN).
- `pkg/appsec`, `pkg/modsecurity` only if the skip path needs to carry more than today.
- Unit tests under `pkg/**/zzz_*_test.go` that pin the old defaults; real e2e under `tests/e2e/real/`.
- Usage docs listed in spec section 6.

## Out of scope

- The spec's own "Out of scope" list above.
- Inferred, not taken: a gate on the stream / alone / CAPI poll path; a gate on the captcha provider; new metrics origins.

## Unknowns

- Classification of LAPI 4xx other than 401/403 (400, 404, 429). The spec names 2xx and 401/403 as success and 5xx / transport / body read / missing transport as failure; other 4xx are not named.
- `sendQuery` is shared with stream and alone polling (including the alone-mode 401 token renewal). How the live-path classification is added without changing stream/alone behaviour is for explore.
- `sendQuery` returns plain wrapped errors; whether classification needs a typed error or the status code is an explore question.
- Whether `Admit(context.Background())` can block in `pkg/admission` (spec section 3 chooses it; explore measures).
- Whether the real e2e stack can stop LAPI without breaking other suites (spec section 7 already allows recording why not).
- Effect of the AppSec default `passthrough` on the unknown-length body path: `newAppsecBodyRequest` sends headers only (GET) when the effective AppSec failure action is `passthrough` (`pkg/appsec/query.go:264-268`). The new default changes what an unconfigured router does with a streamed POST/PUT/PATCH body. Docs that describe that path need the same check.

## Tensions

- Spec section 2 changes the AppSec FailureAction default to `passthrough`, but `EffectiveFailureAction` maps an empty value to `ban` for LAPI and AppSec alike (`pkg/configuration/configuration.go:223-229`), and `validateFailureAction` documents "empty (treated as ban at runtime)". `CreateConfig` sets the value explicitly, so the default holds there; a path that leaves the field empty would still get `ban`. The spec does not say which wins.
- Spec section 4 names the AppSec unreadable-body skip path. ModSec has the same path (`pkg/modsecurity/inspect.go:48-53`) returning `ErrGateSkip`. The generic rule in section 4 ("`ErrGateSkip` in AppSec and ModSec now applies BackOffAction") covers it; the explicit bullet names only AppSec.
- Spec section 5 keeps the failure metrics origin and adds a `<leg>-backoff` header reason. `applyLapiFailureAction` derives the header reason from the origin (`headerReasonFromOrigin(origin)`, `pkg/bouncer/bouncer_serve_lapi.go:92`), so one origin must now yield two reasons.
