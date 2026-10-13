# Specs
change: recaptcha-enterprise
- new core_plugin_middleware_captcha-assessments (high) — Cloud assessments Pass
- new core_plugin_middleware_captcha-widget (high) — Validate outcomes, ServeHTTP retry / omit-boot, template
- new core_plugin_middleware_captcha-enterprise-config (high) — provider token and enterprise knobs
- fold core_plugin_middleware_config-validation (high) — secret not required for recaptcha-enterprise
- fold core_plugin_middleware_captcha-siteverify (high) — Validate Outcome; empty token is None
- fold core_plugin_middleware_instance-slots (high) — ownership includes enterprise knobs
