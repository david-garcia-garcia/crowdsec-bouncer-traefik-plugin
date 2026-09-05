## Context

See proposal.md — Why. Traefik calls `New` once per router-handler build and cancels that context on reload ~1 ms before the next `New`. Sister plugins (geoblock, modsecurity) already bind that context with `pkg/reclaim`. This module still uses package globals and `New(_ context.Context`. After merge, Redis is in-tree `pkg/simpleredis`; memory cache is still a process `ttl_map`. Client address is already owned by `pkg/ip.GetRemoteIP`.

## Goals / Non-Goals

**Goals:**
- One Traefik process, two Crowdsec configs, isolated tickers and caches.
- Copy reclaim; thin Yaegi root; Connection vs Bouncer split.
- Tests that fail if first-wins remains.

**Non-Goals:**
- Changing `.traefik.yml` `import` or public JSON field names.
- Rewriting `pkg/reclaim` vs copying geoblock.
- Keying Connection by Traefik middleware name.
- Renaming `pkg/simpleredis` or Dragonfly e2e.

## Decisions

1. **Copy `pkg/reclaim` from traefik-geoblock** (table.go, default.go, tests). Same stdlib contract. Alternative: `sync.Once` — rejected; never disposes and cannot survive reload grace.

2. **Reclaim value is `CrowdsecConnection`, not Bouncer.** Bouncer holds `next`. Alternative: reclaim a Plugin that embeds Connection — extra type with no second job.

3. **Connection key omits middleware name.** Same LAPI + two aliases share one ticker. Different LAPI/mode/redis/interval → two Connections. Alternative: WAF `plugin:name:hash` — would split tickers per alias and still first-win two backends that reused a name.

4. **Isolated cache:** drop package `ttl_map`; each `localCache` holds its map. Redis: prefix keys with connection identity. Alternative: Redis `SELECT` per connection — operators already set `RedisCacheDatabase`; prefix still needed when two Connections share db.

5. **Captcha on Bouncer**, cache Client from Connection (grace isolated per backend). AppSec HTTP client on Connection (in the key); Bouncer chooses whether to call it on pass.

6. **`create` takes no args** (Yaegi). Tickers start inside Connection constructor; `Close()` stops them.

## Risks / Trade-offs

- [Yaegi subpackage load] → already shipping `pkg/cache`; keep `New`/`CreateConfig` on root.
- [Two Connections, one Redis db without prefix] → prefix is required in spec.
- [Operators who relied on first-wins] → two configs now both run; document as intended.
- [Mock e2e needs two LAPI processes] → mocklapi already a binary; scenario starts two.

## Migration Plan

Deploy as a plugin version bump. No config key migration. Rollback: previous tag restores globals (single backend only).
