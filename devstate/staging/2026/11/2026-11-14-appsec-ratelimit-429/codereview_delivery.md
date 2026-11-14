# Delivery

## Motivation

CrowdSec AppSec `RateLimit()` blocks reach the bouncer as a listener 403 whose JSON body is `{"action":"ban","http_status":429}`. The bouncer ignored `http_status` and answered the client with `bouncerRemediationStatusCode` (403 by default). Clients that back off on 429 therefore saw a plain 403 ban and kept retrying against a path the operator meant to throttle. A throwaway test reproduced it: AppSec stub answering that envelope gave the client 403 with header `ban:appsec`.

This is upstream issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/421, fixed upstream by https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/422. This fork does the same job but cannot copy #422's patch, because this fork's master has no root `bouncer.go` for it to edit.

Two further gaps were open. Nothing exercised `RateLimit()` against a real CrowdSec, so the 429 path had no end-to-end proof. And the real-stack e2e image, `crowdsecurity/crowdsec:v1.8.0`, cannot run it: `RateLimit()` first ships in CrowdSec v1.8.2 (from this run's research notes, not re-verified here).

Priority: P2 — rate-limited clients get the wrong status and keep retrying, with the throttle still enforced (limited blast radius).

## Implementation

`handleBanServeHTTP` keeps its signature and now delegates to a new status-taking writer, `handleBanStatusServeHTTP`, passing `bouncerRemediationStatusCode`. The other nine callers are untouched. The AppSec ban case in `applyAppsecServeHTTP` calls the writer directly with a status from a small helper, `appsecBanStatusCode`: 429 when the AppSec response's `HTTPStatus` is 429, otherwise `bouncerRemediationStatusCode`. Template, `Content-Type`, `Cache-Control`, the `ban:appsec` header, dropped metrics and HEAD-without-body are unchanged. There is no `Retry-After`, and the `pkg/appsec` listener-status mapping is unchanged.

Proof: a table-driven unit test covers 429, 429 over a configured 503, 429 on HEAD, 403, 418 and a missing `http_status`. The real e2e adds a CrowdSec appsec-config `e2e/rate-limit` (`RateLimit("e2e-rate-limit", "2/m")` on `/ratelimit`, per client IP) loaded on the 7422 listener alongside `crs-inband`, plus an AppSec-only `/ratelimit` router and middleware (`lapiEnabled=false`). The Pester case uses a fresh client IP per run, expects 200 twice, then 429 with the e2e ban page and `ban:appsec`. A second case checks a CRS ban on the same listener still returns 403. The e2e CrowdSec image moves from v1.8.0 to v1.8.2.

README (ban table and `BouncerRemediationStatusCode`), devdocs, research notes and the `core_plugin_appsec_bot-detection` OpenSpec delta record the 429 exception.

## What this changes
**Operators.** An AppSec ban with `http_status` 429 (CrowdSec `RateLimit()`, which needs CrowdSec 1.8.2+) now returns 429 regardless of `bouncerRemediationStatusCode`; every other AppSec ban keeps that setting. The e2e CrowdSec image moved from v1.8.0 to v1.8.2 (test infra only).
**Admin users.** None.
**Developers.** AppSec ban status is no longer always `bouncerRemediationStatusCode`: 429 is the one exception, via `appsecBanStatusCode`. `handleBanServeHTTP` is unchanged for its other callers. The e2e stack gains the `/ratelimit` route and `e2e/rate-limit` config, and needs CrowdSec v1.8.2.
**End users.** A client blocked by an AppSec rate limit now gets 429 with the same ban page, so clients that back off on 429 can do so.
