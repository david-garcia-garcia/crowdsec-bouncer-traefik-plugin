# Specs
change: plugin-constructor-rollback-appsec-captcha
- modified core_plugin_middleware_bouncer (failed-New rollback, no caller-Config mutation, derived bind ctx wording)
- modified core_plugin_middleware_config-validation (appsec mode without AppSec warns and still starts)
- modified core_plugin_appsec_failure-action (captcha failure action works in appsec mode)
