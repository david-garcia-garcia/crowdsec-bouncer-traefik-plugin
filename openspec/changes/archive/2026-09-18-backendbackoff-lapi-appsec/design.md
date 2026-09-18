## Context

See `proposal.md` Why. Dest requires `traefik-middleware-utilities v1.0.3` (`950b08de86b6fd9ea68ac1d205e17a379ec60522`). That tag already contains `backendbackoff`; dest `vendor/modules.txt` lists only `reclaim` and `simpleredis` because dest does not import the package yet. Live/none `LiveLookup` always GETs; AppSec `Query` always `Do`s. Stream/alone already skip per-request LAPI via `UpdateMaxFailure` / `StreamHealthy`. Research: `knowledge/research/ext_traefik-middleware-utilities_backendbackoff/`. Explore identity-owner Decisions: client address is `pkg/ip.GetRemoteIP` via `clientRequest.remoteIP`; Allow ctx and AppSec `Host` are the inbound `*http.Request`; backend key is the Client-composed URL stem, not the reclaim key.

FindSpecHost:

```
verdicts:
  - { deltaId: lapi-live-gate, fold|new: new, spec-id: core_plugin_lapi_backend-backoff, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_lapi_query-round-trip, core_plugin_lapi_failure-action, core_plugin_lapi_reclaim-key] }
  - { deltaId: appsec-query-gate, fold|new: new, spec-id: core_plugin_appsec_backend-backoff, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_appsec_failure-action, core_plugin_appsec_bot-detection] }
  - { deltaId: shared-knobs-validate, fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
```

Search: family `core_plugin_lapi` leaf `connection` is replaceable transport (explore: do not fold the gate there). `query-round-trip` is drain / 401 / CAPI body after admit. `failure-action` already covers a query error. Admission is a new capability. Family `core_plugin_appsec` leaf `client` is reclaim / forward / drain; Allow/Report is past a one–three-requirement fold. Family `core_plugin_middleware` leaf `config-validation` already owns `CreateConfig` / `ValidateParams` — shared knobs are a small adjustment.

## Goals / Non-Goals

**Goals:**

- Import and vendor published `backendbackoff` on `v1.0.3`.
- One Gate per live/none LAPI Client and per AppSec Client; nil Gate on stream/alone LAPI.
- Allow before each live GET / AppSec Do; Report after an admitted attempt; Close from existing Close hooks.
- Shared knobs with package defaults; `ValidateParams` uses the published `New` reject set.

**Non-Goals:**

- Version bump, in-tree copy, `pkg/health`, traefik-modsecurity.
- Product enabled flag or a second Tracker.
- Gating stream polls, metrics POST, captcha siteverify, Redis, or Range.
- Putting knobs on the reclaim key.
- New FailureAction enums.
- Sleeping on Allow's wait.

## Decisions

1. **Stay on `v1.0.3` and vendor after import.** The tag already has the package. Alternative: bump — rejected (no newer tag; master == `v1.0.3`). Alternative: copy into `pkg/` — rejected (owner declined #55).
2. **One shared knob set on `configuration.Config`, mapped by one owner.** `configuration.BackendBackoffConfig()` returns `backendbackoff.Config` (seconds → `time.Duration`). Both Client `New`s call it. `ValidateParams` calls `backendbackoff.New` then `Close` so reject rules cannot drift. Alternative: LAPI vs AppSec knob sets — rejected (same pattern as `HTTPTimeoutSeconds`). Alternative: mirror reject rules by hand — rejected (owner already validates).
3. **CreateConfig defaults = package defaults.** Always pass a full Config so omit does not hit the partial-Config Jitter-0 footgun. Explicit `backendBackoffJitter: 0` still disables jitter only.
4. **Construct the Gate only in live/none `lapi.New` and `appsec.New`.** Stream/alone leave the field nil. Nil Allow admits; nil Close is a no-op (published `(*Gate).Close` panics on nil — nil-check in product). Alternative: product enabled flag — rejected (published `New` has no skip-off).
5. **One Allow per `queryLiveDecisions` GET and one Allow per AppSec `Do`.** Key is the stem without `RawQuery` so IP and header scopes share one backend identity. After the Gate trips, later scope GETs in the same lookup also skip. Alternative: one Allow per `LiveLookup` — rejected (remaining scopes would still hammer a dead LAPI).
6. **Thread `req.Request.Context()` into `LiveLookup`.** AppSec already has `httpReq.Context()`. Do not use constructor ctx or `context.Background()`. Debug-log Allow wait; do not sleep.
7. **LAPI Report success on any remediation value (ban, captcha, or none).** Failure on query/HTTP/parse/duration-parse. Health is "backend answered."
8. **AppSec Report failure only on Do error, 502/503/504, and HTTP 500.** Inbound `isBodyUnreadable` never Does and never Reports. After an admitted Do, `errAppsecReadBody` / parse / 200/403 / oversized-body Report success; FailureAction on those paths stays.
9. **Distinct skip error strings** (`queryLiveDecisions:skipped`, `appsecQuery:skipped`). Do not reuse `unreachable` / `banned`. Denied Allow returns that error so existing fail-closed / active-ban-outranks / `resultForFailureAction` stay.
10. **Existing tests that call `LiveLookup` gain a context argument.** Use the test request context or `t.Context()` where the suite already has one.

## Risks / Trade-offs

- [Published Gate has no skip-off] → Always construct live/none and AppSec Gates. Operators who want "never skip" cannot; document that. Do not invent an enabled flag.
- [Partial Config Jitter 0 disables jitter] → CreateConfig writes `0.10`. Explicit 0 is intentional.
- [ValidateParams constructs a throwaway Gate] → Startup only; Close immediately. Uses the owner's reject set.
- [LiveLookup signature grows a `context.Context`] → In-tree callers and tests only; not a YAML break.
- [Two routers sharing one Client first-win the knobs] → Same as `updateMaxFailure`. Last `New` still adopts TLS/timeout.

## Migration Plan

New JSON/YAML keys only. Omit keeps package defaults. Rollback is revert. No reclaim-key migration.
