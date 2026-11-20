# Specs
change: add-redis-rate-limit-leg
- added core_plugin_ratelimit_client (new — Redis-backed counter: open/share, Redis key layout, sync rate, 250ms step budget, failure action) — confidence high
- added core_plugin_ratelimit_buckets (new — bucket match, key parts, evaluation order, deny/log/final, deny response, unsupported values) — confidence high
- fold core_plugin_middleware_bouncer (added "The rate limit runs between the LAPI step and the AppSec step"; modified "Structured remediation header values", "Action rules fold every matching row") — confidence high
- fold core_plugin_middleware_config-validation (added "Rate-limit settings are validated only when the leg is enabled") — confidence high
- fold core_plugin_lapi_usage-metrics (added "Rate-limit drops use plugin origins") — confidence high
- fold build_e2e_pester_crowdsec-stack (added "Real stack covers the Redis rate limit") — confidence medium
