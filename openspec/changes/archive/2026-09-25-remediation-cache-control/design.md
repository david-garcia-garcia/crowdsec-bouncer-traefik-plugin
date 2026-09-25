## Context

See proposal.md Why. Dest `Client.ServeHTTP` sets `Content-Type` and the optional remediation header, then `WriteHeader(200)` and executes the challenge template; it does not set `Cache-Control`. Dest `handleBanServeHTTP` sets the optional remediation header and `Content-Type`, then `WriteHeader(remediationStatusCode)`; HEAD and nil-template return before the body. AppSec relay already copies `user_headers` (including `Cache-Control` when the engine sends it). Explore Decisions are accepted: exact `no-cache, no-store` on the two existing writers, next to `Content-Type` and before `WriteHeader`; extend the existing header tests; leave Pass 302, AppSec relay, and CDN configuration unchanged. Vendor value is `knowledge/research/ext_crowdsec_bouncers_cache-control/`.

## Goals / Non-Goals

**Goals:**

- Same `Cache-Control` string on both writers this plugin owns.
- Header present on HEAD and empty-body bans the same way `Content-Type` already is.
- Assertions on the existing challenge 200 and ban header tests.

**Non-Goals:**

- Pass 302 / `WriteSolvedRedirect`.
- `Set-Cookie` on the challenge page, or a status-code change.
- AppSec `handleAppsecResponseServeHTTP` or changing its `no-store` mock fixtures.
- A shared helper package or Traefik Config field.
- Extra directives (`private`, `max-age=0`, `must-revalidate`, `Pragma`).
- e2e coverage or a new `zzz_` test file.
- Writing `knowledge/devdocs` this phase.
- Modeling CDN cache keys or TTLs.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Seam | `Header().Set("Cache-Control", "no-cache, no-store")` on `Client.ServeHTTP` (non-`Pass`) and `handleBanServeHTTP`, next to `Content-Type`, before `WriteHeader` | Two writers already own their response headers. One Set each; all ban call sites inherit. |
| Value | Exactly `no-cache, no-store` | HAProxy SPOA docs/config/Go writer, AppSec challenge protocol example, and engine `setChallengeResponse` agree. |
| Literal | Identical literal next to each Set | No new package, no Config field. Unexported const in either file is also fine; do not invent a shared owner. |
| Tests | Assert on existing challenge 200 body case in `pkg/captcha/zzz_servehttp_test.go` and on `TestHandleBanServeHTTPContentType` plus the method table in `pkg/bouncer/zzz_bouncer_test.go` | Affected names those files. Do not add a neighbor `zzz_` file. |
| Catalog | Fold `core_plugin_middleware_captcha-widget` and `core_plugin_middleware_bouncer` | Small header SHALLs on the leaves that already own challenge render and ban request policy. |

**Alternatives rejected:** Pass 302 header; AppSec default when the engine omits `Cache-Control`; extra directives; a shared helper or Config key; a new spec family; e2e.

## Risks / Trade-offs

- **CDN may ignore `Cache-Control`** → Accepted. The plugin lever is the header. CDN configuration is out of scope.
- **AppSec mock fixtures still say `no-store`** → Leave them. They are relay input, not this writer.
- **HEAD / nil-template bans gain a header with no body** → Same as `Content-Type` today. Set before `WriteHeader`.

## Migration Plan

- Deploy. No config rewrite. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore wrote them.
