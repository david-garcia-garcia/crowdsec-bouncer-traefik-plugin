## Context

See `proposal.md` Why. Dest `master` hashes per-router policy and LAPI HTTP/TLS into stream `streamSettings` and live `identity`, so a policy- or TLS-only Traefik reload `Open`s a new `lapi.Client` and pays `startup=true`. `Bouncer` already owns AppSec failure action. Yaegi v0.16 cannot take a generic instantiation from another package as a struct field (`ext_traefik-middleware-utilities_packages`). Ticker work reads write-once Client scalars without the mutex.

FindSpecHost:

```
verdicts:
  - { deltaId: settings-hash-and-last-wins-transport, fold|new: fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease] }
  - { deltaId: failure-action-owner-on-bouncer, fold|new: fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim, core_plugin_appsec_failure-action] }
  - { deltaId: bouncer-holds-redis-fail-closed-and-live-ttl, fold|new: fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action] }
  - { deltaId: transport-extract-atomic-value, fold|new: fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
```

No new leaf. `instance-reclaim` is a vague leaf name — Issues note, no rename.

## Goals / Non-Goals

**Goals:**
- Same Client (no extra `startup=true`) after a failure-action-only reload.
- Same Client + last-`New` transport after a TLS/timeout-only reload.
- Per-router LAPI failure action, Redis fail-closed, and live TTL on Bouncer.
- Transport field is `atomic.Value`.

**Non-Goals:**
- Shared `DecisionStore` / reclaim of `cache.Client` / atomic Redis `updated` lease.
- Narrowing the reclaim key to cursor-only (delete Peek / union `scopes=` / replace `pkg/reclaim`).
- AppSec, captcha, or moving `MetricsReporter`.
- Making remaining write-once Client scalars mutable.
- Updating usage Language in this change folder (implement / devdocsimpact).

## Decisions

1. **Drop the same fields from stream settings and live identity.** `identity.go` replicates the knob cluster. Dropping only `streamSettings` would still split live/none Clients and `CachePrefix`.
2. **`StreamStartupBlock` stays write-once on Client.** First incarnation keeps it. Not on Bouncer. Not in the hash. Not mutable after `startStream`.
3. **Unexported `transport` in `client_http.go`.** HTTP client, header name, and CAPI token already live there. Field on `Client` is `atomic.Value`. Call site after Open: `AdoptTransport(cfg)`.
4. **Not `atomic.Pointer[T]`.** Yaegi v0.16. Same pattern as `rangeMembership`.
5. **`LiveLookup(remoteIP, scopes, defaultDecisionSeconds)`.** Bouncer passes `config.DefaultDecisionSeconds`. No Client field.
6. **Concurrent `AdoptTransport`:** last `Store` wins; `closeIdle` the replaced `*http.Client`. No extra mutex around write-once scalars. Do not keep a plain mutable `httpClient` beside the `atomic.Value`.
7. **`logInfo` key:** stream/alone log `SessionKey`; live/none log `Key`. Reasons stay `started|sleeping|waking|closed`. New INFO names transport replace and joiner `ignored` vs `adopted`. Reclaim table lines stay DEBUG.
8. **Remaining hash fields still first-wins** via `PeekLivePrefix` (intervals, Redis host/auth/db, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`).
9. **Fold, do not invent a per-router-policy leaf.** Hash / last-wins / Bouncer Redis+TTL → `instance-reclaim`. Failure-action owner → `failure-action`. Transport file → `connection`.

## Risks / Trade-offs

- [Two routers last-write live TTL] → Accepted on the ticket. Document on the Bouncer requirement; do not add a Client field to “fix” it.
- [CAPI token on transport vs `c.crowdsecKey`] → Token must move with HTTP so `AdoptTransport` cannot leave a stale key on a write-once field. `getToken` Stores back onto the current transport.
- [Yaegi rejects `atomic.Pointer[transport]`] → Use `atomic.Value` and type-assert on load, like `rangeMembership`.
- [Grace wait helpers fail if the key still moves] → Tests keep `waitStreamSessionInGrace` / `waitPluginStreamInGrace`; they pass because `SessionKey` no longer moves on those knobs.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert. Catalog users pick up the reclaim-key narrowing with the next plugin release; in-process Clients from an old snapshot die on grace.
