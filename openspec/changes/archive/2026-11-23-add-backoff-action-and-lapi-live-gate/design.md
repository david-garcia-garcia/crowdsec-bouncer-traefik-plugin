## Context

See `proposal.md` (Why) and the run's `explore.md` for the unit map and the measured reproductions. Constraints that shape the approach:

- `pkg/admission` already wraps `backendbackoff.Gate` for AppSec and ModSec: `New` returns a nil gate when the period is `<= 0`, and a nil gate admits everything. `Admit(ctx)` only checks `ctx.Err()` and takes one mutex, so it never blocks. It errors only after `Close`.
- Each leg is shared: the owner middleware opens the Client (and its gate) and publishes it under an instance name, and routers `Watch` it. Gate state therefore lives on the Client. The action has to be resolved on the router (`Bouncer`), which already holds `lapiFailureAction`, `appsecFailureAction`, and `modsecFailureAction`.
- `sendQuery` (`pkg/lapi/client_http.go`) is shared by the live GET, stream / alone polling, CAPI login, and the alone 401 replay. It returns plain wrapped errors today.
- `applyLapiFailureAction` derives the header reason from the metrics origin (`headerReasonFromOrigin`). A backoff answer has to reuse the failure origin and still show a different reason.
- `EffectiveFailureAction` maps an empty value to `ban` for LAPI and AppSec alike. AppSec's new default is `passthrough`.

## Goals / Non-Goals

**Goals:**
- Bound a LAPI live/none outage the way the WAF legs already are, without letting banned IPs through by default.
- Make the answer during a backoff a per-router choice on every gated leg.
- Keep stream / alone polling, CAPI login, and the live cache semantics as they are.

**Non-Goals:**
- No change to `pkg/admission` (trip rule, cooldown, log wrapper).
- No inbound context into LAPI HTTP or `Admit`.
- No gate on the stream / alone poll, the rate-limit leg, or the captcha provider. No new metrics origins.

## Decisions

1. **Per-leg resolvers replace `EffectiveFailureAction`.** `pkg/configuration` gets `EffectiveLapiFailureAction` (empty → `ban`), `EffectiveAppsecFailureAction` (empty → `passthrough`), and `EffectiveLapiBackOffAction` (empty → `ban`), `EffectiveAppsecBackOffAction` / `EffectiveModsecBackOffAction` (empty → `passthrough`). These sit next to the existing `EffectiveModsecFailureAction` and `EffectiveRateLimitFailureAction`. The four production callers of `EffectiveFailureAction` migrate (`pkg/appsec/query.go` ×2, `pkg/bouncer/bouncer.go` ×2), and the shared function is removed. `New()` sets the same defaults explicitly. *Alternative:* keep one shared resolver and rely on `New()` defaults. Rejected: a path that leaves the field empty would still get `ban` for AppSec. *Alternative:* a BackOffAction that inherits FailureAction. Rejected by the owner, who chose static defaults.

2. **Validation reuses `validateFailureAction`.** The three backoff keys go through the same rule (value set, `captcha` needs a captcha instance name after owner-fill). Errors name the Go field. `LapiUnhealthyBackOffPeriodSecs` joins `requiredInt0`. Its comment ("empty treated as ban") becomes per leg.

3. **LAPI gate lives on `lapi.Client`, built only in live/none.** `lapi.New` calls `admission.New` with `Leg: "lapi"`, `MsgBackoffStarted` / `MsgBackoffEnded` constants (`crowdsec lapi backoff started` / `ended`), and the period. It does so only when the mode is `live` or `none`; otherwise the gate stays nil. `Close` closes it. Sharing comes for free: subscribers load the same Client. *Alternative:* a gate per router. Rejected: it multiplies the probes and breaks "one connection, one health state".

4. **LAPI cooldown joins the ownership key, not `SessionHex`** (explore Q8, `deviations.md`). `ownershipFrom` in `pkg/lapi/identity.go` adds `UnhealthyBackOffPeriodSecs`, set to the configured value in `live` / `none` and to `0` otherwise, so a stream/alone Client does not reopen for a knob it ignores. A change opens a new Client and keeps the DecisionStore. *Alternative:* `streamSession` / `SessionHex` as the ticket literally says. Rejected: that would drop the cache and the stream cursor on a cooldown change.

5. **Classification through a typed status error, read only by the live path.** `sendQuery` returns an unexported `statusError{code int, msg string}` for the reverse-proxy branch and the non-2xx branch. `Error()` returns today's exact text, so `zzz_client_http_test.go` assertions and stream logs do not change. `queryLiveDecisions` does `Admit(context.Background())`:
   - deny → `ErrGateSkip`, no HTTP;
   - admission error → a failure error, no HTTP;
   - admitted → `crowdsecQuery`, then classify before parsing. Failure: transport error, `crowdsecQuery: missing transport`, `statusError` with 5xx or 429, `crowdsecQuery:readBody`. Success: nil error (2xx), or a `statusError` with any other 4xx. Then `Record`, then parse as today, so parse errors still return an error and FailureAction still applies.

   Stream, alone, `getToken`, and the 401 replay ignore the type. *Alternative:* classify inside `sendQuery` behind a gate parameter. Rejected: it touches every caller and risks stream/alone behaviour.

6. **Skip propagation in `pkg/lapi`.** `lapi.ErrGateSkip` is a sentinel. `handleNoStreamCache` keeps its order: an IP-query error returns before any memo, and a scope error blocks the clean IP memo. So a skip writes nothing to the cache without a structural change. `mergeLiveScope` does not WARN when the error is `ErrGateSkip`. An active remediation from an answered query still wins, as it does over failures today.

7. **Bouncer maps every skip to the leg's backoff action.**
   - `serveLAPI`: `errors.Is(err, lapi.ErrGateSkip)` → `applyLapiBackOffAction`.
   - `answerAppsecQueryError`: `appsec.ErrGateSkip` → `applyAppsecBackOffAction`.
   - `serveModSec`: `modsecurity.ErrGateSkip` → `applyModsecBackOffAction`.

   Each writer switches on the router's resolved action. `passthrough` returns false. `ban` calls `banWarnCaptchaRule(..., <leg reason>, <leg>-backoff, <leg failure origin>)`, so a captcha action rule is superseded with the WARN, as for a failure-action ban. `captcha` checks `bypassesCaptcha`, then calls `handleCaptchaKindServeHTTP(..., banReason, "<leg>-backoff", origin)`, which already downgrades to `ban:captcha-downgrade` without a usable captcha. `pkg/appsec` and `pkg/modsecurity` do not change: both skip paths (denied admission, unreadable body while backing off) already return `ErrGateSkip`.

8. **Header reason is explicit.** `applyLapiFailureAction` takes the header reason as a parameter (`lapi-failure`, `stream-unhealthy`). Its three callers pass it. The new `applyLapiBackOffAction` passes `lapi-backoff`. `remediation_header.go` adds `headerReasonLapiBackoff`, `headerReasonAppsecBackoff`, `headerReasonModsecBackoff`. `headerReasonFromOrigin` is unchanged: a failure origin still maps to `<leg>-failure`. The backoff captcha passes the leg's ban reason (`LAPI` / `APPSEC` / `MODSEC`) directly, so it does not inherit the `handleRemediationServeHTTP` `ReasonLAPI` asymmetry (follow-up already in `issues.md`).

9. **Stricter-than WARN in `bouncer.New`** (explore Q9). After the actions are resolved, for each subscribed leg (`Subscriptions.LAPI`, `.AppSec`, `.ModSec`) the router compares ranks with `passthrough=0 < captcha=1 < ban=2`. When backoff ranks above failure, it logs one WARN `crowdsec bouncer backoff action stricter than failure action` with `leg`, `failureAction`, `backOffAction`. For LAPI the WARN is skipped when this router opens LAPI itself in `stream` / `alone` (`LapiEnabled` and `LapiMode`). A pure subscriber cannot see the owner's mode, so it always warns.

10. **Real e2e.** LAPI gets its own Pester file `tests/e2e/real/lapi_backoff.Tests.ps1`, registered in `PesterDomains.ps1` domain `lapi` (owner direction: keep `waf_backoff.Tests.ps1` on the WAFs). Compose adds `lapi-flaky` (`nginx:alpine`, container `lapi-flaky-test`, `config/lapi-flaky.conf` in the `appsec-flaky.conf` shape: `resolver 127.0.0.11` plus a `set $lapi http://crowdsec:8080` `proxy_pass`, so nginx starts while crowdsec is not resolvable yet). One file-provider `live` route `/lapi-cycle` uses:
    - `lapiHost: lapi-flaky:80`;
    - its own key `BOUNCER_KEY_LAPI_BACKOFF` = `c51a1c7000000000000000000000001f`, registered in the crowdsec env list;
    - `lapiUnhealthyBackOffPeriodSecs: 10`, `lapiHttpTimeoutSeconds: 2`, `lapiMetricsUpdateIntervalSeconds: 0`, `reclaimGraceSeconds: 2`;
    - JSON log and the verdict header.

    Every request carries a fresh `X-Forwarded-For`, because live mode caches a clean answer. In `waf_backoff`, a second router subscribes to the `/appsec-cycle` AppSec instance by name with `bouncerAppsecBackOffAction: ban`: one outage proves both the shared gate and the per-router action. `/waf-backoff-default` is rewritten for the new defaults. The unreachable failure-action routes pin their period to 0: `/lapi-fail-ban` and `/lapi-fail-pass` pin `lapiUnhealthyBackOffPeriodSecs`, and the three `/modsec-fail-*` pin `modsecUnhealthyBackOffPeriodSecs`. Without the pin, `/lapi-fail-pass` would answer `ban:lapi-backoff` after 5 requests, and the readiness probe in `Test-Integration.ps1` would fail.

## Risks / Trade-offs

- [Breaking defaults surprise operators who relied on AppSec `ban` or an ungated ModSec] → 💥 gitmoji on the PR title; `docs/failure-modes.md` and `docs/configuration.md` call out each change and the key to restore the old behaviour.
- [`bouncerLapiFailureAction: passthrough` routers start banning during an outage (default backoff `ban`)] → the startup WARN names both keys; docs show `bouncerLapiBackOffAction: passthrough` for operators who want fail-open.
- [A subscriber that cannot see the owner's mode warns for LAPI even when the owner is `stream`] → accepted: the WARN is advisory and never rejects the config (explore Q9).
- [Admission error after `Close` during a reclaim race] → treated as a failure (FailureAction, no HTTP), the same as AppSec and ModSec today.
- [Gate state survives a Pester rerun on the same stack (10 s)] → the LAPI and AppSec cycles wait out the cooldown before asserting, and `AfterAll` restarts the container.
- [`statusError` message drift breaks existing log or test expectations] → `Error()` returns the pre-formatted text, and the two message assertions in `pkg/lapi/zzz_client_http_test.go` stay as they are.

## Migration Plan

- Operators who want the old behaviour:
  - `bouncerAppsecFailureAction: ban` (old AppSec default);
  - `appsecUnhealthyBackOffPeriodSecs: 30`;
  - `modsecUnhealthyBackOffPeriodSecs: 0`;
  - `lapiUnhealthyBackOffPeriodSecs: 0` on live/none LAPI owners.
- No storage migration: the DecisionStore identity (`SessionHex`) and Redis keys do not change. A live/none Client reopens once on upgrade, because the ownership payload gains a field. The reclaim key hash changes the same way any process restart does.
- Rollback: revert the release. No persisted state depends on the new keys.
