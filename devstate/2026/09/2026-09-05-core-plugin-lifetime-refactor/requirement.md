# Requirement
IssueKey: 2026-09-05-core-plugin-lifetime-refactor

## Problem
Traefik instantiates this middleware once per route. Stream polling, decision cache, LAPI health, and metrics currently live as package globals mixed into the same `Bouncer` type that also answers HTTP. The Traefik plugin entry (`CreateConfig` / `New`) sits in that same root package. The ticket wants a dedicated plugin package and a first-class CrowdSecConnection instance (cache, stream ticker, connection lifetime) separate from the per-route Bouncer (request handling only). Coverage of that split must be thorough; `TestNew` is an empty table today.

## Current (code)
- Traefik catalog import is the module root (`/.traefik.yml` `import: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`). Yaegi loads `CreateConfig` and `New` from package `crowdsec_bouncer_traefik_plugin`.
- `CreateConfig` and `New` live in `/bouncer.go` (lines 75–128) in that root package, next to `Bouncer`, stream helpers, LAPI/CAPI/AppSec queries, and metrics. `/version.go` is the only other root production file.
- `Bouncer` holds both per-route fields (`next`, `name`, ban template, trusted-IP checkers) and connection fields (LAPI/AppSec HTTP clients, cache client, captcha client, stream route, keys, update interval) (`/bouncer.go` 81–123, constructed 202–264).
- Process-wide globals own stream/metrics lifetime: `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, `updateFailure`, `streamTicker`, `metricsTicker`, `lastMetricsPush`, `blockedRequests` (`/bouncer.go` 65–73). Comment at `/bouncer.go` 47–62 states Traefik creates one instance per route and that stream/cache params take the first middleware’s values.
- First `New` that sees `streamTicker == nil` starts `handleStreamTicker` and `startTicker`; later routes skip (`/bouncer.go` 302–317). Same pattern for `metricsTicker` (`/bouncer.go` 319–326). Tickers close over that first `*Bouncer`.
- In-memory cache is another process singleton (`/pkg/cache/cache.go` 31 `var cache = ttl_map.New()`), not owned by a connection type.
- Subpackages already exist and are imported by the root plugin: `/pkg/cache`, `/pkg/captcha`, `/pkg/configuration`, `/pkg/ip`, `/pkg/logger`. `Config` is already `configuration.Config`, not a root `Config`.
- `/bouncer_test.go` `TestNew` (43–70) has `// TODO: Add test cases.` and an empty table. Grep of `*_test.go` finds no `streamTicker` / `isCrowdsecStreamHealthy` tests.
- Local-plugin load path is documented in `knowledge/research/ext_traefik_plugins_localplugins/notes.md` (module root bind-mount). Constructor/package-layout finding was not in that folder at prepare time (research subagent launched).

## Desired
- The Traefik plugin (Yaegi entry: `CreateConfig`, `New`, catalog import) lives in its own package, not mixed with connection or request logic.
- CrowdSecConnection is the instance that owns cache, stream ticker, and related CrowdSec connection lifetime (LAPI/CAPI stream, stream health, metrics push as part of that lifetime).
- Bouncer only handles what happens on a request for an incoming route (trusted IP, cache lookup / live query via the connection, remediation, AppSec-on-pass as today).
- Test coverage of the new lifetime (one connection vs many bouncers, ticker start-once, request path using the connection) is explicit and not an empty `TestNew`.

## Affected
- `/bouncer.go` (split)
- `/bouncer_test.go`, `/bouncer_logging_test.go`
- `/pkg/*` (new packages or moves)
- `/.traefik.yml` only if the Yaegi import/package must change
- Traefik local-plugin and e2e load (`tests/e2e/`, compose bind-mount of module root)

## Out of scope
- Renaming or changing public JSON config keys (`configuration.Config` field tags).
- Multiple simultaneous CrowdSec LAPI connections per Traefik process (not asked; today is one global stream).
- Changing decision-scope semantics, captcha providers, or Redis protocol.
- Sibling ticket `2026-09-05-integrate-redis-backend`.

## Unknowns
- Whether Yaegi requires `CreateConfig`/`New` to remain in the module-root package (`crowdsec_bouncer_traefik_plugin`) while internals move, vs moving the plugin package and changing `.traefik.yml` `import` / `basePkg`.
- CrowdSecConnection cardinality: still one per process (matching today’s globals) vs keyed by LAPI host/key (would change first-wins behavior).
- Whether captcha client and AppSec HTTP client belong on Connection or on Bouncer (today they sit on `Bouncer` but AppSec host is listed as first-wins in `/bouncer.go` 47–62).
- How far “exquisite” coverage goes: compiled `go test` of the new types vs additional Yaegi/e2e lifetime cases.

## Tensions
- Official plugin skeleton wants `Config` + `CreateConfig` + `New` on the plugin package (`https://github.com/traefik/plugindemo`); this repo already returns `*configuration.Config` from the root and already uses `pkg/` subpackages in production Yaegi.
- First-middleware-wins globals (`/bouncer.go` 47–62) vs an explicit Connection instance: extracting a type without changing cardinality keeps today’s operator-visible behavior; keying connections would be a product change not in the ticket.
- User asked two splits (plugin package vs connection/bouncer) in one change; Traefik catalog import must keep loading.
- Empty `TestNew` vs the coverage bar: tests must pin lifetime, not only ServeHTTP status codes.
