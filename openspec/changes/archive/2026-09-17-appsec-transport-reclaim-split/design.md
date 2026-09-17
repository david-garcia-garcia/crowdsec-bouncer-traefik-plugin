## Context

See `proposal.md` Why. Dest `master` hashes AppSec TLS content and shared `HTTPTimeoutSeconds` into `pkg/appsec` `identity`, so a TLS- or timeout-only Traefik reload `Open`s a new `appsec.Client`. Per-router `crowdsecAppsecFailureAction` is already on `Bouncer` and `appsec.Policy` at `Query`. `httpClient` is a write-once pointer; `Query` reads it without the mutex. Yaegi v0.16 cannot take a generic instantiation from another package as a struct field (`atomic.Pointer[T]`). AppSec is not a field-for-field LAPI mirror: one `Key`, no stream settings, no CAPI token, `bodyLimit` is a request-copy cap.

FindSpecHost:

```
verdicts:
  - { deltaId: appsec-reclaim-key-and-transport, fold|new: fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_appsec_failure-action, core_plugin_lapi_connection] }
```

No new leaf. Do not fold into `core_plugin_middleware_instance-reclaim` (sibling rename) or `core_plugin_lapi_connection` (LAPI-only).

## Goals / Non-Goals

**Goals:**
- Same Client after an AppSec TLS- or timeout-only reload.
- Last `New` adopts HTTP+auth on that Client.
- Transport field is `atomic.Value`.

**Non-Goals:**
- Moving `bodyLimit` off the key.
- Moving failure action (already per-router).
- Captcha product work, `pkg/lapi/` edits, `pkg/reclaim/` internals.
- Making remaining write-once Client scalars mutable.
- Updating usage Language in this change folder (implement / devdocsimpact).

## Decisions

1. **Keep `bodyLimit` on identity.** It is the request-copy cap on a write-once Client scalar, not HTTP transport.
2. **Keep key on identity.** A key change still opens a new Client. Put the same key on `transport` so `Query` does not read a write-once `appsecKey`.
3. **Unexported `transport` in `pkg/appsec/client_http.go`.** HTTP client, API key, timeout, AppSec TLS extras. Field on `Client` is `atomic.Value` with the Yaegi comment. Call site after Open: `AdoptTransport(cfg)`.
4. **Not `atomic.Pointer[T]`.** Yaegi v0.16. Same comment as `pkg/lapi/client.go`.
5. **Remove write-once `httpClient` and `appsecKey`.** Do not mutate them in place. `Query` / `Close` load `currentTransport()`.
6. **Leave `appsecScheme` / `appsecHost` / `appsecPath` / `appsecBodyLimit` write-once.** Readers do not take the mutex.
7. **`plugin.go` unchanged.** `AdoptTransport` lives inside `appsec.Open`.
8. **INFO `appsec transport replaced`** with reclaim `Key` when timeout/TLS extras change. No `ignored` joiner path (one `Key`, no `PeekLivePrefix`).
9. **Client IP stays on `bouncer` `clientRequest`.** `Query` takes that `ip`. Do not reconstruct `RemoteAddr`.
10. **Fold only `core_plugin_appsec_client`.** failure-action / bot-detection / captcha-gate have no reclaim-key delta.

## Risks / Trade-offs

- [Yaegi rejects `atomic.Pointer[transport]`] → Use `atomic.Value` and type-assert on load.
- [Concurrent `AdoptTransport`] → last `Store` wins; `closeIdle` the replaced `*http.Client`. No extra mutex around write-once scalars.
- [Shared `HTTPTimeoutSeconds` also keys LAPI] → LAPI already dropped it. Do not edit `pkg/lapi/` here.
- [Sibling `master` move] → Sync (merge `origin/master`, no rebase) before implement and before pullrequest.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert. In-process Clients from an old snapshot die on grace.
