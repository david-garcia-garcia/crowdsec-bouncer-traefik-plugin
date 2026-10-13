# Specs
change: 2026-09-21-appsec-cancelled-body-ban
- modified core_plugin_appsec_failure-action (client disconnect is not a FailureAction)
- modified core_plugin_appsec_client (Query returns ErrClientDisconnected; AppSec not called)
- modified core_plugin_middleware_bouncer (TRACE, optional error:client-disconnected header, no ban)
- { deltaId: client-body-dropped-during-buffer, fold, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_client] }
- { deltaId: client-disconnected-stop, fold, spec-id: core_plugin_appsec_client + core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_middleware_bouncer, core_plugin_appsec_failure-action] }
