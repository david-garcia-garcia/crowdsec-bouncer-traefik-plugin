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
