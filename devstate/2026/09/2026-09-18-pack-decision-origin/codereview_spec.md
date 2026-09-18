# Spec

1. [wrong] Lookup resolves origin only on drop — `pkg/bouncer/bouncer.go:215` — `openspec/changes/pack-decision-origin/specs/core_plugin_decisions_scopes/spec.md` Requirement: Lookup resolves origin only on drop said origin name resolve (`table[id]` or the leftover U+001F suffix) SHALL run only when the bouncer reports a drop (`IncDropped`); ServeHTTP calls `resolveStoredOrigin` on every active cache hit, including captcha custom-resource and solved-cookie allow-through that never call `IncDropped`
   → Move `resolveStoredOrigin` to immediately before `recordDropped` / `IncDropped`
   Status: done
   Argument: f7bd466 cache hit now passes unresolved `stored`; `recordDropped` calls `resolveStoredOrigin` immediately before `IncDropped`.
