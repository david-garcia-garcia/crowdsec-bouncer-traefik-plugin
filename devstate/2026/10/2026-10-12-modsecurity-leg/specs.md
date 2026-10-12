# Specs
change: modsecurity-leg
- fold core_plugin_middleware_bouncer — fourth binding, serve order, bypassModsec, ban:modsec (high; candidates: core_plugin_middleware_bouncer)
- fold core_plugin_middleware_instance-slots — fourth group modsec (high; candidates: core_plugin_middleware_instance-slots)
- fold core_plugin_middleware_config-validation — open-vs-subscribe + modsec* keys (high; candidates: core_plugin_middleware_config-validation)
- fold core_plugin_appsec_failure-action — backoff skip is not FailureAction; default ban stays (high; candidates: core_plugin_appsec_failure-action)
- fold core_plugin_appsec_client — Gate + backoff knobs on ownership key (high; candidates: core_plugin_appsec_client)
- new core_plugin_modsecurity_client — reclaim CRS sidecar client (high; no existing family leaf)
- new core_plugin_modsecurity_inspect — copy-then-classify protocol (high; no existing family leaf)
- fold build_e2e_pester_crowdsec-stack — domain modsec + CRS sidecar (high; candidates: build_e2e_pester_crowdsec-stack)
