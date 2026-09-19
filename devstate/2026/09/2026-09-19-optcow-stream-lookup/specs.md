# Spec map (propose)

Change: `2026-09-19-optcow-stream-lookup`  
DestBranch: `master`  
FindSpecHost run before each delta write.

| Delta folder | Verdict | Spec id | Confidence | Notes |
| --- | --- | --- | --- | --- |
| `specs/core_cache_client_decision-store` | fold | `core_cache_client_decision-store` | high | Stream store ownership + intern overflow on memory path |
| `specs/core_plugin_lapi_stream-apply` | fold | `core_plugin_lapi_stream-apply` | high | Apply through store tick; no Client liveTick |
| `specs/core_plugin_decisions_scopes` | fold | `core_plugin_decisions_scopes` | high | Stream lookup + GetMany exclusion on memory stream |
| `specs/core_plugin_middleware_bouncer` | fold | `core_plugin_middleware_bouncer` | high | Single Client stream lookup entry |

Candidates considered: `core_cache_client_isolated-store` (cache utility only — no stream Ip owner), `core_plugin_lapi_reclaim-key` (reclaim unchanged).
