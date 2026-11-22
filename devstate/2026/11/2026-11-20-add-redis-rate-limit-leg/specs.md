# Specs
change: share-rate-limit-leg-and-bucket-actions
- fold core_plugin_middleware_instance-slots (modified "Named LAPI and AppSec slots are separate tables", "Lifecycle logs match e2e grep contract"; added "Rate limit publishes on reclaim group ratelimit") — confidence high
- fold core_plugin_ratelimit_client (renamed + modified "The rate-limit counter is opened once per middleware and Redis settings" → "The rate-limit client is opened on the owner with its policy", reverses "SHALL NOT be published"; modified "Counters are shared across replicas through Redis keys", "A Redis failure applies the rate-limit failure action within a fixed time budget") — confidence high
- fold core_plugin_ratelimit_buckets (modified "Matching buckets are charged in list order"; renamed + modified "A deny bucket answers …" → "A ratelimit bucket answers …"; removed "Bucket values not in this version fail validation", replaced by added "Bucket algorithm, action, and store values are validated"; added "A captcha bucket answers with the router's captcha", "The captcha page's own requests are not charged", "Rate-limit captcha downgrades log on transitions") — confidence high
- fold core_plugin_middleware_bouncer (modified "Bouncer binds clients through atomic late bind", "A missing subscribed client uses that leg's failure action", "Structured remediation header values", "bypassCaptcha lets a request through where a captcha would be served", "Unsubscribed captcha kind warns then bans", "The rate limit runs between the LAPI step and the AppSec step") — confidence high
- fold core_plugin_middleware_config-validation (modified "Instance open versus subscribe validation"; removed "Rate-limit settings are validated only when the leg is enabled", replaced by added "Rate-limit settings are validated only on the owner") — confidence high
- fold core_plugin_lapi_usage-metrics (modified "Rate-limit drops use plugin origins") — confidence high
- fold build_e2e_pester_crowdsec-stack (modified "Real stack covers the Redis rate limit"; added "Real stack covers the shared rate-limit leg", "Real stack covers captcha buckets") — confidence high

FindSpecHost (2026-11-21): 7 deltas, 7 fold, 0 new, 0 skip. Every delta modifies requirements its leaf already owns, so fold is the only host for those blocks; the added requirements per leaf stay within one–three, except `core_plugin_ratelimit_buckets` (four added, one of which replaces the removed validation block one-for-one, so three new behaviours). A REMOVED + ADDED pair is used where a kept scenario name would have stated the opposite of the new rule ("Captcha action is rejected", "Captcha failure action without a captcha instance fails"); OpenSpec 2.0 rejects a MODIFIED block that drops a scenario. The leg-descriptor extraction (task group 1) has no live promise of its own (Live catalog) and adds no delta; the instance-slots changes come from the fifth group only.

## Archive (2026-11-22)
FindSpecHost re-run (Task sub-agent, archive time): 7 deltas, 7 fold, 0 new, 0 skip; every MODIFIED / REMOVED / RENAMED header matches its leaf (the two MODIFIED blocks titled with a RENAMED TO name apply after the rename).
- build_e2e_pester_crowdsec-stack — fold, high
- core_plugin_lapi_usage-metrics — fold, high
- core_plugin_middleware_bouncer — fold, high
- core_plugin_middleware_config-validation — fold, high
- core_plugin_middleware_instance-slots — fold, high
- core_plugin_ratelimit_buckets — fold, medium: addendum C brought the ADDED blocks to seven (six new behaviours, three of them the token bucket), past the one–three fold threshold; kept fold because the delta also renames, modifies, and removes blocks only this leaf owns, and the proposal declares no new capability. A separate token-bucket leaf under `core_plugin_ratelimit` would need the change rewritten; left to the human.
- core_plugin_ratelimit_client — fold, high (two ADDED blocks from the owner-unavailable work, not in the propose-time journal above)
Synced with the OpenSpec 2.0 merge (RENAMED, REMOVED, MODIFIED full-block replace, ADDED; totals +13 ~17 -2 →2), checked first on a scratch copy: no scenario or code token dropped except those the REMOVED / MODIFIED blocks retire (`deny`, "Captcha action is rejected", "Token bucket is rejected", "Captcha failure action without a captcha instance fails"); `openspec validate --specs` 42/42, `validate-spec-map` (write, then check) and `validate-artifact-names` clean. Change moved to `openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/`.

---

# Specs — round 1 (history)
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
