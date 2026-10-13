## Context

See proposal.md — Why. Dest `master` already last-writes timeout on LAPI/AppSec `AdoptTransport` and omits HTTP timeout from reclaim identity. All three clients still read raw `config.HTTPTimeoutSeconds`. Official CrowdSec `lapi_timeout` / `appsec_timeout` default 200ms (`ext_crowdsec_bouncers_failure-action`); this change keeps dest 10 and inherit-from-shared. Closed PR #41 put effective timeout back into identity — do not reuse it.

FindSpecHost:

```
verdicts:
  - { deltaId: inherit-knobs-and-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
  - { deltaId: lapi-effective-timeout-adopt, fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection] }
  - { deltaId: appsec-effective-timeout-query, fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }
  - { deltaId: timeout-out-of-reclaim-identity, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_appsec_client] }
  - { deltaId: captcha-siteverify-client-timeout, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_captcha-siteverify] }
```

No new leaf. `captcha-siteverify` is JSON classification, not client construct — fold captcha Timeout onto `bouncer`. Leaves are precise; no Issues rename note.

## Goals / Non-Goals

**Goals:**
- One inherit owner on `Config`. Three call sites pass their knob.
- Existing LAPI/AppSec `newTransport` and bouncer captcha `http.Client` use effective seconds. Store effective seconds on transport so `fieldsDiffer` last-writes.
- Timeout-only YAML Adopts, does not Open. Identity owners unchanged.
- Tests fail if a call site still reads raw `HTTPTimeoutSeconds`.

**Non-Goals:**
- backendbackoff, captcha reclaim / `AdoptTransport` for siteverify, `sync.Once` / package-global client.
- Official 200ms defaults. Putting timeout into reclaim identity (PR #41).
- Usage Language for unimplemented knobs (devdocsimpact after apply).
- `cache.Set`, captcha gate cookie, Range, module path, HTML-path deprecations.

## Decisions

1. **One method `(*Config) EffectiveHTTPTimeoutSeconds(override int64) int64`.** Returns `HTTPTimeoutSeconds` when `override == 0`, else `override`. Does not coerce negative. Alternative: three `EffectiveLapi` wrappers — rejected; hides that the result is seconds and copies one job. Alternative: package func like `EffectiveFailureAction` — rejected; explore owns a method on `Config` so call sites stay `cfg.EffectiveHTTPTimeoutSeconds(cfg.CrowdsecLapiHTTPTimeoutSeconds)`.
2. **New knobs join `requiredInt0` (`< 0` invalid).** Shared `HTTPTimeoutSeconds` stays in `requiredInt1` (`< 1` invalid). `CreateConfig` / `configuration.New` leave the three knobs at 0 (Go zero). Alternative: treat negative as inherit — rejected; explore assumed invalid.
3. **Store effective seconds on `transport.httpTimeoutSeconds`.** `newTransport` sets both `http.Client.Timeout` and the stored int64 from the helper. Then override 0 + shared 10 versus override 10 both store 10 and `fieldsDiffer` does not replace; a shared-default change with override still 0 does replace. Alternative: store the raw override — rejected; Adopt would miss a shared-default reload and would replace when 0 and 10 mean the same Timeout.
4. **Reuse identity owners.** Do not add knobs or effective seconds to `pkg/lapi/session.go` `streamSession`, `pkg/lapi/identity.go` `identity`, or `pkg/appsec/session.go` `identity`. Those functions already omit HTTP timeout. Alternative: put effective timeout in the key to isolate routers — rejected; dest last-write invariant; PR #41 declined.
5. **Captcha stays per-Bouncer.** `bouncer.New` builds the `http.Client` with effective captcha seconds. No reclaim. Assert Timeout via a test-only `HTTPClientForTest` on `captcha.Client` (httpClient is unexported and only stored when a provider is set). Alternative: hanging siteverify — extra wait for a field we can read. Alternative: package-global client / `sync.Once` — rejected; sister reclaim uses Traefik `New` ctx as holder.
6. **AppSec hang test goes through `appsec.New` / `Open`, not `newQueryClient`.** `newQueryClient` injects a custom `*http.Client` and would not fail if `newTransport` still read raw `HTTPTimeoutSeconds`. Listener never accepts; override 1s + passthrough; wall time well under 10s.
7. **README.** Reword `HTTPTimeoutSeconds` from “LAPI only” to the shared default (LAPI, AppSec, captcha siteverify). Document the three knobs next to it. Example `crowdsecAppsecHttpTimeoutSeconds: 1` with `crowdsecAppsecFailureAction: passthrough`.

## Risks / Trade-offs

- [Two routers last-write a shared LAPI/AppSec Timeout] → Same as dest TLS. Document; do not Open a sibling Client.
- [Override 0 and override 10 both mean 10] → Store effective seconds so Adopt does not churn the pool.
- [Captcha `httpClient` unexported] → `HTTPClientForTest` (test in the name). Do not export a production Timeout getter.
- [Hang test injected via `newQueryClient`] → Would pass on dest. Construct through `New`/`Open`.

## Migration Plan

New keys default 0 (inherit). Existing `httpTimeoutSeconds: 10` keeps today’s behavior. Rollback is revert. No identity or Redis key migration.

## Open Questions

None — ticket decisions stand on `explore.md`.
