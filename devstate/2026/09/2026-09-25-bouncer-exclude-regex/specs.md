# Specs
change: bouncer-exclude-regex
- fold core_plugin_middleware_bouncer — request-policy host+path exclude; confidence high; candidates: core_plugin_middleware_bouncer, core_plugin_middleware_forced-decision, core_plugin_appsec
- fold core_plugin_middleware_config-validation — invalid RE2 fails ValidateParams; confidence high; candidates: core_plugin_middleware_config-validation
- skip core_plugin_middleware_forced-decision — no live promise change (exclude sits after forced b)
- skip core_plugin_appsec — Query contract unchanged
