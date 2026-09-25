# Specs
change: request-bypass-rules

FindSpecHost (Search then verdict, one per delta). Live catalog: remaining request-policy skip and constructor compile/empty/invalid are live promises. REMOVED of dest exclude SHALL is fold, not skip. No skip on the two folds.

Search: `openspec/specs/map.md` families `core_plugin_middleware`, `build_e2e_mock`. Walked `openspec/specs/*/spec.md` (exclude SHALL on `core_plugin_middleware_bouncer` and `core_plugin_middleware_config-validation`; forced-decision live spec does not name exclude). Walked `openspec/changes/request-bypass-rules/specs/` after write. Explore fold list accepted. Identity-owner Decision: no new spec family; matcher is `pkg/httprule` implementation of the bouncer contract, not a catalog leaf (later utilities move).

- fold `core_plugin_middleware_bouncer` confidence: high candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_forced-decision]
- fold `core_plugin_middleware_config-validation` confidence: high candidates: [core_plugin_middleware_config-validation]
- skip `core_plugin_middleware_forced-decision` — no live SHALL names exclude; forced-c-after-skip stays on the bouncer leaf. Usage retarget is docs, not a delta folder
- skip `core_plugin_middleware_httprule` — no live public API; matcher is not a plugin catalog promise
- skip `build_e2e_mock_dual-bouncer` — mock scenario is verification, not a production-path SHALL

`proposal.md` New vs Modified matches (New none, Modified the two folds).

Archive FindSpecHost (Search then verdict). Same two delta folders. Live catalog: request-policy skip and constructor compile/empty/invalid remain live promises. REMOVED of dest exclude SHALL is fold, not skip. Cleanup/absence ADDED: none.

Search: `openspec/specs/map.md` family `core_plugin_middleware`. Walked live `openspec/specs/*/spec.md` and `openspec/changes/request-bypass-rules/specs/`. Matcher still not a catalog leaf.

- fold `core_plugin_middleware_bouncer` → `core_plugin_middleware_bouncer` confidence: high candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_forced-decision, core_plugin_lapi_failure-action, core_plugin_appsec_client, core_plugin_middleware_captcha-routing, core_plugin_ip_radix-lookup]
- fold `core_plugin_middleware_config-validation` → `core_plugin_middleware_config-validation` confidence: high candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer]
