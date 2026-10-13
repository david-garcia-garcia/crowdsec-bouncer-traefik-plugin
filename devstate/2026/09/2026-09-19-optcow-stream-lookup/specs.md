# Specs
change: 2026-09-19-optcow-stream-lookup

FindSpecHost Search: `openspec/specs/map.md`, `openspec/specs/*/spec.md`, `openspec/changes/2026-09-19-optcow-stream-lookup/specs/*/spec.md`.
Candidates: `core_cache_client_decision-store`, `core_cache_redis_utilities-client`, `core_cache_client_isolated-store`, `core_plugin_decisionstore_store` (new remaining unit), `core_plugin_lapi_stream-apply`, `core_plugin_decisions_scopes`, `core_plugin_middleware_bouncer`, `core_plugin_lapi_stream-lease`, `core_plugin_lapi_stream-single-flight`, `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_usage-metrics`, `core_plugin_middleware_captcha-routing`, `std_go_logger_debug-attrs`, `build_ci_github_module-path`.
Removed unit: `core_cache_*` leaves that named `pkg/cache` / `cache.Client` as the DecisionStore bag are renamed or REMOVED in this change (not parked as Issues). Archived change folders keep historical ids.

verdicts:
  - { deltaId: core_cache_client_decision-store, new, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_cache_client_decision-store, core_cache_client_isolated-store] }
    notes: Removed unit rename. Remaining unit is pkg/decisionstore.Store (engine, memory COW, Redis SimpleRedis, intern, Range, pack, lookup). Old id REMOVED.
  - { deltaId: core_plugin_decisionstore_store, new, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_cache_client_decision-store] }
    notes: Legal 4th part `store` under family core_plugin_decisionstore. Writes the remaining unit.
  - { deltaId: core_cache_redis_utilities-client, fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_cache_redis_utilities-client, core_plugin_decisionstore_store] }
    notes: Remaining Redis engine (writer+replicas, nextReader, void SET/DEL, miss vs unreachable, v1.0.5) belongs on the store. Acquire REMOVED. This leaf REMOVED.
  - { deltaId: core_cache_client_isolated-store, fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_cache_client_isolated-store, core_cache_client_decision-store] }
    notes: SessionHex prefix isolation lives on the store. This leaf REMOVED.
  - { deltaId: core_plugin_lapi_stream-lease, fold, spec-id: core_plugin_lapi_stream-lease, confidence: high, candidates: [core_plugin_lapi_stream-lease, core_plugin_lapi_stream-single-flight] }
    notes: REMOVED entire leaf. Lease dropped; single-flight stays on stream-single-flight.
  - { deltaId: core_plugin_lapi_stream-apply, fold, spec-id: core_plugin_lapi_stream-apply, confidence: high, candidates: [core_plugin_lapi_stream-apply] }
    notes: Small adjustment. Apply through Store BeginTick/Put/Delete/PublishTick/ApplyRangeBatch.
  - { deltaId: core_plugin_decisions_scopes, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes] }
    notes: Drop leftover U+001F / GetInt leftover. Lookup is Store. Range via Store membership. PreferRemediation stays.
  - { deltaId: core_plugin_middleware_bouncer, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer] }
    notes: One Store lookup; LiveLookup kind+origin fields.
  - { deltaId: core_plugin_lapi_reclaim-key, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key] }
    notes: Prefix owner citation → core_plugin_decisionstore_store.
  - { deltaId: core_plugin_lapi_stream-single-flight, fold, spec-id: core_plugin_lapi_stream-single-flight, confidence: high, candidates: [core_plugin_lapi_stream-single-flight, core_plugin_lapi_stream-lease] }
    notes: Drop lease wording; intra-instance lock remains.
  - { deltaId: core_plugin_lapi_usage-metrics, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics] }
    notes: Overflow origin id 0 / empty OriginName, not leftover string.
  - { deltaId: core_plugin_middleware_captcha-routing, fold, spec-id: core_plugin_middleware_captcha-routing, confidence: high, candidates: [core_plugin_middleware_captcha-routing] }
    notes: Drop Cache().Acquire / stream-lease wording.
  - { deltaId: std_go_logger_debug-attrs, fold, spec-id: std_go_logger_debug-attrs, confidence: high, candidates: [std_go_logger_debug-attrs] }
    notes: Drop cache.Client Get/GetMany/Set/Delete Debug scenarios.
  - { deltaId: build_ci_github_module-path, fold, spec-id: build_ci_github_module-path, confidence: high, candidates: [build_ci_github_module-path] }
    notes: Drop pkg/cache Yaegi import scenario; name pkg/decisionstore.

Do not invent extra families. Domain `plugin` already allowlisted. Family `core_plugin_decisionstore` is new component under that pair (map refresh at archive).
