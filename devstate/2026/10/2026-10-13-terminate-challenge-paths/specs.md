# Specs
change: terminate-unanswered-challenge-paths
- fold core_plugin_appsec_bot-detection (high) — unanswered challenge-prefix 404; candidates: core_plugin_appsec_bot-detection, core_plugin_middleware_bouncer, core_plugin_appsec_failure-action
- fold core_plugin_appsec_failure-action (high) — passthrough carve-out on the same prefix; candidates: core_plugin_appsec_failure-action, core_plugin_appsec_bot-detection
