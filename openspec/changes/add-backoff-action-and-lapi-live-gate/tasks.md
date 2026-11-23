# Tasks

Spec ids:
- New: `core_plugin_lapi_admission-gate`.
- Folds: `core_plugin_lapi_failure-action`, `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_query-round-trip`, `core_plugin_appsec_client`, `core_plugin_appsec_failure-action`, `core_plugin_modsecurity_client`, `core_plugin_modsecurity_inspect`, `core_plugin_middleware_bouncer`, `core_plugin_middleware_config-validation`, `build_e2e_pester_crowdsec-stack`.

Decisions are numbered in `design.md`. Each group lands its own unit tests and devdocs. Usage docs land with the group that completes the behaviour they describe. The real-stack Pester work comes last because it needs groups 1–3 together on real Traefik.

## 1. Configuration: keys, defaults, per-leg resolvers, validation

- [ ] 1.1 `pkg/configuration`: add the four keys, change the three defaults, and replace `EffectiveFailureAction` with per-leg resolvers (design 1).
  - Add `LapiUnhealthyBackOffPeriodSecs` (`lapiUnhealthyBackOffPeriodSecs`, `int64`), `BouncerLapiBackOffAction`, `BouncerAppsecBackOffAction`, `BouncerModsecBackOffAction` (alphabetical in `Config`).
  - `New()` defaults: AppSec FailureAction `passthrough`; AppSec, ModSec, and LAPI periods 10; LAPI backoff `ban`; AppSec and ModSec backoff `passthrough`. Set `DefaultAppsecUnhealthyBackOffPeriodSecs` to 10.
  - Add `EffectiveLapiFailureAction`, `EffectiveAppsecFailureAction`, `EffectiveLapiBackOffAction`, `EffectiveAppsecBackOffAction`, `EffectiveModsecBackOffAction`. Remove `EffectiveFailureAction` and migrate its four callers (`pkg/appsec/query.go:75,265`, `pkg/bouncer/bouncer.go:101,110`).
  - Verify: `go build ./...` passes, and `go vet ./...` is clean.
- [ ] 1.2 `pkg/configuration` validation (design 2): run the three backoff keys through `validateFailureAction` with their own field names; add `LapiUnhealthyBackOffPeriodSecs` to `requiredInt0`; make the "empty" comment per leg.
  - Verify with `pkg/configuration` tests: unknown backoff value fails naming the field; `captcha` without a captcha instance fails; owner-filled captcha passes; `-1` LAPI period fails; stream with a LAPI period passes; shipped defaults for all six actions and three periods; empty AppSec → `passthrough`, empty LAPI → `ban`.
  - Update `TestNew_ModsecAndAppsecBackoffDefaults` to the new defaults.
- [ ] 1.3 Old-default tests outside `pkg/configuration`: update `pkg/modsecurity` `TestNew_omittedBackoffHasNoGate` (omitted now builds a 10 s gate; add a `0` → no gate case) and the message in `pkg/appsec/zzz_gate_test.go:44-48`. Verify: `go test ./pkg/configuration ./pkg/modsecurity ./pkg/appsec -count=1` passes.
- [ ] 1.4 `docs/configuration.md`: entries for the four new keys; new defaults of `bouncerAppsecFailureAction`, `appsecUnhealthyBackOffPeriodSecs`, `modsecUnhealthyBackOffPeriodSecs`; replace the "does not apply while the gate skips" text (`:362,410,656,684`) with the backoff action. `examples/modsecurity/dynamic.yml` comments if they state the old default. Verify: `go test ./tests/docs -count=1` passes (`TestConfigurationDocCoversEverySetting`).
- [ ] 1.5 Devdocs `knowledge/devdocs/core_plugin_middleware_config-validation.md`: per-leg resolvers, the backoff keys, the three periods. Verify: `node <skillsRoot>/opd-mcp/scripts/cli.mjs validate-artifact-names <worktree>` is clean.

## 2. LAPI live/none admission gate

- [ ] 2.1 `pkg/lapi/client_http.go`: `sendQuery` returns an unexported `statusError` (code plus pre-formatted text) on the reverse-proxy branch and the non-2xx branch (design 5). Verify: `pkg/lapi/zzz_client_http_test.go:206,396` still pass unchanged; a new test asserts `errors.As` yields the code for 401, 429, and 503 and none for a transport error.
- [ ] 2.2 `pkg/lapi/client.go`: `MsgBackoffStarted` / `MsgBackoffEnded` constants; `lapi.New` builds the gate with `admission.New` (`Leg: "lapi"`) only in `live` / `none`; `Close` closes it; exported sentinel `ErrGateSkip` (design 3). Verify with unit tests: live and none with the default build a gate; `0` builds none; stream and alone build none; `Close` closes it.
- [ ] 2.3 `pkg/lapi/identity.go`: `ownershipFrom` adds the period, set only in `live` / `none` (design 4). Verify with tests shaped like `TestKey_NoneMetricsIntervalSplitsClientKeepsStore`: a live period change → new `OwnershipKey`, same `SessionHex`; a stream period change → same `OwnershipKey`.
- [ ] 2.4 `pkg/lapi/client_decisions.go` (design 5, 6): `queryLiveDecisions` admits with `context.Background()` before the GET (deny → `ErrGateSkip`; admission error → failure, no HTTP), classifies and `Record`s before parsing. `mergeLiveScope` does not WARN on `ErrGateSkip`.
  - Verify with `httptest` unit tests for live and none:
    - 5 × 503 trip, and the 6th lookup does not hit the server;
    - a mapped header-scope GET is gated too;
    - 429 trips; 401 never trips;
    - a 200 with bad JSON records success;
    - nothing is cached on a skip (IP skip, and clean IP plus skipped scope);
    - an active ban from the IP query outranks a skipped scope;
    - after the cooldown the probe recovers and logs `crowdsec lapi backoff ended` once, after one `started` (test log sink, `std_go_test_log-sink`);
    - stream polling against a 503 server never touches a gate.
- [ ] 2.5 Yaegi: the root Yaegi test and `make yaegi_test` equivalent in the CI GOPATH layout. Verify: they pass with the gate in `lapi.New`.
- [ ] 2.6 Devdocs: `core_plugin_lapi_connection.md` (the Client holds the live gate), `core_plugin_lapi_reclaim-key.md` (the period on the ownership key, live/none only), `core_plugin_lapi_query-round-trip.md` (status error, unchanged text). Verify: `validate-artifact-names` is clean.

## 3. Bouncer: backoff action per router on every leg

- [ ] 3.1 `pkg/bouncer/bouncer.go`: fields `lapiBackOffAction`, `appsecBackOffAction`, `modsecBackOffAction`, resolved in `New` with the per-leg resolvers. Verify: `pkg/bouncer` tests read the resolved defaults.
- [ ] 3.2 `pkg/bouncer/remediation_header.go`: `lapi-backoff`, `appsec-backoff`, `modsec-backoff` tokens. `applyLapiFailureAction` takes the header reason as a parameter, and its three callers pass `lapi-failure` / `stream-unhealthy` (design 8). Verify: the existing header tests pass unchanged, and `headerReasonFromOrigin` still maps each failure origin to `<leg>-failure`.
- [ ] 3.3 Skip mapping (design 7):
  - `serveLAPI`: `lapi.ErrGateSkip` → `applyLapiBackOffAction`.
  - `answerAppsecQueryError`: `appsec.ErrGateSkip` → `applyAppsecBackOffAction`.
  - `serveModSec`: `modsecurity.ErrGateSkip` → `applyModsecBackOffAction`.
  - Writers: ban via `banWarnCaptchaRule` with the leg reason, `<leg>-backoff`, and the failure origin; captcha via `bypassesCaptcha` then `handleCaptchaKindServeHTTP`.
  - Verify with `pkg/bouncer` tests for each leg and value (`passthrough`, `ban`, `captcha`):
    - header, status, RemediationReason, and the `dropped` origin;
    - captcha without a usable client → `ban:captcha-downgrade`;
    - `bypassCaptcha` lets a backoff captcha through;
    - a backoff ban supersedes a captcha rule with `warnCaptchaSuperseded`;
    - two routers on one gate answer differently;
    - the AppSec unreadable body while backing off and the ModSec unreadable body while backing off get the backoff action;
    - ModSec over-limit is still 413.
  - Update `TestServeHTTP_modsecGateSkipPassesWithoutFailureAction` to assert the default backoff `passthrough`.
- [ ] 3.4 Stricter-than WARN in `bouncer.New` (design 9). Verify with tests:
  - LAPI subscriber with FailureAction `passthrough` and the default backoff → one WARN with `leg`, `failureAction`, `backOffAction`;
  - defaults → no WARN;
  - a stream LAPI owner → no LAPI WARN;
  - an unsubscribed leg → no WARN;
  - `New` never fails.
- [ ] 3.5 Usage docs: `docs/failure-modes.md`:
  - "At a glance": the AppSec, ModSec, and LAPI live/none rows, and the "connection not there" row;
  - rule 3;
  - the LAPI live/none section;
  - "When a WAF is down" (two actions, new defaults, state diagram text "no failure action" → "backoff action");
  - the verdict header table and the alerting lines.

  Also update `docs/how-it-works.md:67-68`, `docs/how-to/crowdsec-down.md:18`, `docs/modsecurity.md:35,207`, `docs/how-to/verdict-in-access-logs.md:17,31`, and `README.md` where it states these defaults. Mark the three breaking defaults and the new LAPI gate, each with the key that restores the old behaviour. Verify: `go test ./tests/docs -count=1` passes, and a grep for `Only the WAFs back off`, `off by default`, and `30 seconds` in `docs/` finds no stale statement.
- [ ] 3.6 Devdocs: `core_plugin_appsec.md` (Gate skip Language → backoff action; default 10; FailureAction default `passthrough`; "Default stays `ban`" removed), `core_plugin_modsecurity_client.md` (default 10; drop "Default ModSec backoff is off"), `core_plugin_modsecurity_inspect.md` (skip → backoff action). Verify: `validate-artifact-names` is clean, and no packet still says the AppSec default is 30 or that the ModSec gate is off by default.
- [ ] 3.7 Whole Go suite. Verify: `go test ./... -count=1`, `make lint`, and the Yaegi test all pass.

## 4. Real-stack e2e

- [ ] 4.1 Pins for permanently down backends (design 10): `lapiUnhealthyBackOffPeriodSecs=0` on `/lapi-fail-ban` and `/lapi-fail-pass` (compose labels), and `modsecUnhealthyBackOffPeriodSecs: "0"` on the three `/modsec-fail-*` middlewares in `config/dynamic/modsec.yml`. Mock e2e needs no edit: its AppSec scenarios set `bouncerAppsecFailureAction: ban` explicitly, and `appsec` and `request-bypass-rules` already pin the cooldown to `0` (explore Q10). Verify: `failure_action.Tests.ps1` and `modsec.Tests.ps1` pass on the local stack, and `make e2e_mock` passes.
- [ ] 4.2 `waf_backoff`:
  - Rewrite `/waf-backoff-default` for the new defaults: origin 200 throughout, at most 5 listener hits, one `crowdsec appsec backoff started`.
  - Add a second router that subscribes to the `/appsec-cycle` AppSec instance with `bouncerAppsecBackOffAction: ban`, and assert `ban:appsec-backoff` on it while the cycle route passes, with no listener hit.
  - Update the header comments of `waf-backoff.yml` and `waf_backoff.Tests.ps1`.

  Verify: `waf_backoff.Tests.ps1` passes on the local stack (port remap per the repo's local e2e note).
- [ ] 4.3 LAPI live backoff:
  - Compose service `lapi-flaky` (`config/lapi-flaky.conf`, container `lapi-flaky-test`).
  - Key `BOUNCER_KEY_LAPI_BACKOFF` in the crowdsec env list.
  - File-provider route `/lapi-cycle` (new YAML under `config/dynamic/`).
  - `tests/e2e/real/lapi_backoff.Tests.ps1`: stop, 5 × `ban:lapi-failure`, then a fast `ban:lapi-backoff`, one `started`; start, 200, one `ended`; `AfterAll` starts the container.
  - Register the file in `PesterDomains.ps1` domain `lapi` and update the header comment.

  Verify: `lapi_backoff.Tests.ps1` passes locally; `Assert-PesterDomainPartition` passes; the `lapi` domain run (`Test-Integration.ps1`) passes with the new file.
- [ ] 4.4 Devdocs `knowledge/devdocs/build_e2e_real.md`: the `lapi-flaky` service, `/lapi-cycle`, the new default case, the subscriber backoff router, and the period pins. Verify: `validate-artifact-names` is clean.
- [ ] 4.5 Integration: run the Pester domains `lapi`, `appsec`, `modsec`, and `lifecycle` on one local stack. Verify: all pass; record the result in `handoff.yaml` `localTests`.

## Workflow follow-up

- Code review, devdocs impact, archive (spec sync of the 11 deltas, `validate_spec_map --write`), then pull request with the 💥 gitmoji title.
