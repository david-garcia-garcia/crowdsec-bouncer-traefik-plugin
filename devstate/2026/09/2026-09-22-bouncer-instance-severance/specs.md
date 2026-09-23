# Specs
change: bouncer-instance-severance

## FindSpecHost verdicts

| delta folder | verdict | spec-id | confidence | notes |
|--------------|---------|---------|------------|-------|
| core_plugin_middleware_instance-slots | new | core_plugin_middleware_instance-slots | high | Large new slot/publish/subscribe capability; no catalog leaf |
| core_plugin_middleware_config-validation | fold | core_plugin_middleware_config-validation | high | E2/E3/E4 and appsec mode removal |
| core_plugin_middleware_bouncer | fold | core_plugin_middleware_bouncer | high | Late bind, startup block, drop store exclusive New |
| core_plugin_lapi_reclaim-key | fold | core_plugin_lapi_reclaim-key | high | Ownership key + SessionHex scope/Redis rules |
| core_plugin_lapi_scope-union | fold | core_plugin_lapi_scope-union | high | REMOVED union; ADDED opener-only scopes |
| core_plugin_appsec_client | fold | core_plugin_appsec_client | high | Middleware name in ownership key |
| build_e2e_pester_crowdsec-stack | fold | build_e2e_pester_crowdsec-stack | high | instance_severance.Tests.ps1 ADDED |

Verdict: synced — live SHALLs folded into catalog; instance-slots created
