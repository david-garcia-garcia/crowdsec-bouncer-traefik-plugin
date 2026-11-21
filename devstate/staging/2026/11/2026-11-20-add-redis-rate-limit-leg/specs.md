# Specs
change: add-redis-rate-limit-leg
- added core_plugin_ratelimit_client (new — Redis-backed counter: open/share, Redis key layout, sync rate, 250ms step budget, failure action) — confidence high
- added core_plugin_ratelimit_buckets (new — bucket match, key parts, evaluation order, deny/log/final, deny response, unsupported values) — confidence high
- fold core_plugin_middleware_bouncer (added "The rate limit runs between the LAPI step and the AppSec step"; modified "Structured remediation header values", "Action rules fold every matching row") — confidence high
- fold core_plugin_middleware_config-validation (added "Rate-limit settings are validated only when the leg is enabled") — confidence high
- fold core_plugin_lapi_usage-metrics (added "Rate-limit drops use plugin origins") — confidence high
- fold build_e2e_pester_crowdsec-stack (added "Real stack covers the Redis rate limit") — confidence medium

## Archive (2026-11-21)
FindSpecHost re-run: same six verdicts (4 fold, 2 new, 0 skip), confidence high. Synced into `openspec/specs/`; change moved to `openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/`.
- core_plugin_middleware_bouncer: the two MODIFIED blocks were written before master's ModSec leg merged in. A full-block replace would have dropped ModSec text (`bypassModsec`, `ban:modsec`, `ban:modsec-failure`, `captcha:modsec-failure`, the ModSec skip bullet, two ModSec scenarios). Landed by a three-way merge (propose-time baseline, current baseline, delta): the rate-limit edits plus all ModSec text. Blank lines inserted between table rows and scenario bullets in those two blocks were dropped to match the delta layout.
