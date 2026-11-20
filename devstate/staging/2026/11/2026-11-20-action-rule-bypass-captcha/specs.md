# Specs
change: action-rule-bypass-captcha
- fold core_plugin_middleware_bouncer (added "bypassCaptcha lets a request through where a captcha would be served"; modified "Action rules fold every matching row") — confidence high
- fold core_plugin_middleware_config-validation (modified "Invalid action rules fail ValidateParams") — confidence high
- fold core_plugin_lapi_origin-based-decision-remap (added "A ban-to-captcha edge does not apply on a captcha-bypass request") — confidence high
