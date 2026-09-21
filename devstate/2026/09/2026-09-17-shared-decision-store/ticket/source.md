Context: four changes already landed on master. master is currently `01d7835`. A series of tickets just split `pkg/lapi` by lifetime, and this ticket is the next step in that story. Read these before you design anything:
- `openspec/changes/archive/2026-09-17-lapi-transport-router-policy/` — moved per-router policy onto the `Bouncer`, extracted the LAPI HTTP+auth transport into its own type held in an `atomic.Value`, added `AdoptTransport(cfg)` so the last `New` wins the transport, and dropped per-router policy, `StreamStartupBlock`, HTTP timeout and the three TLS fields out of the settings hash that keys reclaim.
- `openspec/changes/archive/2026-09-17-appsec-transport-reclaim-split/` — the same treatment for AppSec.
- `openspec/changes/archive/2026-09-17-extract-metrics-reporter/` — extracted `MetricsReporter` off `Client`; it POSTs through an injected `crowdsecQueryFunc` instead of owning an `*http.Client`.
- The live spec leaves `openspec/specs/core_plugin_lapi_reclaim-key/spec.md` and `openspec/specs/core_plugin_middleware_bouncer/spec.md` (a docs ticket just split the old `core_plugin_middleware_instance-reclaim` dump into those two).

Requirement, part 1: share one DecisionStore. This ticket takes the follow-up recorded in `knowledge/debt/2026-09-17-shared-decision-store.md`. Read that file as the ticket source.

The problem: every `lapi.Client` owns its own `cache.Client`, and the in-memory backend is per-Client by construction — `pkg/cache/cache.go` `Client.New` says "memory clients ignore it and each own a map" and builds `&localCache{store: ttl_map.New()}`, so the `keyPrefix` that namespaces Redis keys (`prefixed()` on `redisCache`) does nothing for memory. The consequence is that two `lapi.Client` incarnations on different reclaim keys keep two independent decision caches, and the stream lease does not coordinate between them.

Two things to build:
1. Make the decision store a reclaim entry of its own, keyed by the CrowdSec cursor identity plus the store parameters, so routers can share remediations without sharing a LAPI poller. `cache.Client.Close()` (`pkg/cache/cache.go`) is the natural dispose hook — verify it is safe to call more than once before you rely on that, and say what you found.
2. Make the stream lease atomic. Today `pkg/lapi/client_stream.go` uses the key `cacheTimeoutKey = "updated"`: it reads whether the lease is present (the `handleStreamCache:alreadyUpdated` path) and then writes it with `c.cacheClient.Set(cacheTimeoutKey, ..., leaseDuration)` where `leaseDuration` is `updateInterval - 1`. That read-then-write is not atomic, so two pollers can both decide they own the tick. Make it a single atomic operation via Redis `EVAL` (the vendored SimpleRedis in this repo supports `EVAL`; check how other callers use it) with a correct fallback for the in-memory backend.

Hard constraints, because this plugin runs under Traefik's Yaegi interpreter:
- Do NOT use `atomic.Pointer[T]`. Yaegi v0.16 cannot handle a generic instantiation from another package as a struct field. Use `atomic.Value` with a comment saying why, as `pkg/lapi/client.go` does for `transport` and `rangeMembership`.
- Do NOT convert existing write-once scalar fields on `Client` into mutable ones. Their readers do not take the mutex.

Requirement, part 2: close a small spec gap in the same change. The leaf `openspec/specs/core_plugin_lapi_reclaim-key/spec.md` is missing two facts about the reclaim key it describes. Fix the text in this ticket:
1. It does not name `RedisCacheReadHosts`, even though that field IS part of the hashed settings snapshot (`streamSettings` in `pkg/lapi/session.go`, and `identity` in `pkg/lapi/identity.go`). Name it.
2. It does not explain a deliberate asymmetry: `decisionScopeHeaders` IS in the stream/alone settings hash but is NOT in the live/none `identity`. That is correct, not a bug, and the spec should say why. The reason, which I verified in the code: `c.decisionScopeHeaders` is only read on stream paths — `streamQuery()` builds the `&scopes=` parameter sent to LAPI, and `storeStreamDecision` filters which header scopes get cached. Live and none never read it, because the bouncer passes scopes per call through `LiveLookup(remoteIP, scopes, defaultDecisionSeconds)`. So two live routers with different scope headers can safely share one Client, while two stream routers cannot.
If your own reading of the code contradicts either statement, do not silently write the spec anyway — report the disagreement.

Scope fence: Do NOT do the next ticket's work. A separate debt file, `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`, owns narrowing the reclaim key to the CrowdSec cursor row, and it runs after this one. Specifically, in this ticket:
- Do NOT delete `Peek`, `PeekLivePrefix` or `View` from `pkg/reclaim/`
- Do NOT change `scopes=` from first-wins to a union of the live routers
- Do NOT replace `pkg/reclaim` with an import of traefik-middleware-utilities, and do not diverge `pkg/reclaim` from its upstream copy more than you must
- Do NOT rework the session prefix or the settings-hash membership beyond what the shared store genuinely needs
Also leave alone: `pkg/appsec/`, `pkg/captcha/`, and `pkg/lapi/client_metrics.go` / the `MetricsReporter`.

When implement lands the work, close the debt per skill:sbs-dev-workflow:Issues: delete `knowledge/debt/2026-09-17-shared-decision-store.md` and record the closure on your own run's `issues.md` and delivery card. Leave `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md` in place — it is still open. Do NOT edit or stage any previous run's bus folder under `devstate/2026/09/`.
