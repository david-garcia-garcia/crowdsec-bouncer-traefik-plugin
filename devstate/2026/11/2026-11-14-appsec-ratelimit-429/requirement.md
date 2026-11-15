# Requirement
IssueKey: 2026-11-14-appsec-ratelimit-429

## Problem
CrowdSec AppSec `RateLimit()` blocks arrive as `{"action":"ban","http_status":429}` on a listener 403. The bouncer answers the client with `bouncerRemediationStatusCode` (403 by default), so clients that back off on 429 keep retrying. Upstream fixed it in maxlerebourg/crowdsec-bouncer-traefik-plugin#422 (issue #421).

## Current (code)
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` `case appsec.ActionBan`: calls `handleBanServeHTTP(rw, req, ReasonAPPSEC, headerReasonAppsec, "appsec")`; `decision.HTTPStatus` is not read.
- `pkg/bouncer/bouncer.go` `handleBanServeHTTP`: always `rw.WriteHeader(b.remediationStatusCode)`; shared by LAPI, action rules, failure actions, captcha downgrade, AppSec ban, AppSec empty challenge.
- `pkg/appsec/query.go` `Query`: listener 200/403 parsed into `appsec.Response` (`HTTPStatus` from `http_status`); other listener codes use FailureAction.
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md` "Structured ban keeps the operator ban template": ban uses `handleBanServeHTTP` (operator template / remediation status), header `ban:appsec`.
- `README.md` remediation table and `BouncerRemediationStatusCode` entry: ban status is `bouncerRemediationStatusCode`.
- `tests/e2e/real/config/docker-compose.test.yml`: CrowdSec image `crowdsecurity/crowdsec:v1.8.0`; one custom AppSec config `appsec-configs/e2e-origin-scheme-grant.yaml`. No `RateLimit()` config: not found.

## Desired
- AppSec ban with `http_status` 429 → client 429, same operator ban template, `Content-Type`, `Cache-Control`, header `ban:appsec`, dropped metrics (`appsec`/`ban`); HEAD has no body.
- AppSec ban with any other `http_status` (403, 418, 0, missing) → `bouncerRemediationStatusCode`.
- 429 wins over a configured `bouncerRemediationStatusCode`.
- No `Retry-After`. Header stays `ban:appsec`. Limited to AppSec.
- Unit tests for 429 / 403 / 418 / missing / 503-configured / HEAD.
- Real e2e: AppSec `RateLimit()` on a dedicated path; exceed it and see 429 with the ban page. Bump the CrowdSec image if v1.8.0 lacks `RateLimit()`.
- README documents the 429 exception.
- Delivery card cites upstream issue #421 and PR #422.

## Affected
- `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`, `handleBanServeHTTP`)
- `pkg/bouncer` unit tests
- `tests/e2e/real/config/docker-compose.test.yml`, `tests/e2e/real/config/appsec-configs/`, a `tests/e2e/real/*.Tests.ps1`
- `README.md`
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`
- `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware_ban-page.md`

## Out of scope
- Generic rate-limiter leg, `Retry-After`
- Honouring other AppSec ban status codes
- AppSec captcha/challenge relay
- `pkg/appsec/query.go` listener status mapping
- Copying upstream #422's patch (edits root `bouncer.go`, absent on master)

## Unknowns
- Whether `crowdsecurity/crowdsec:v1.8.0` ships the `RateLimit()` AppSec helper and its exact syntax/hook (`pre_eval` in the upstream issue).
- Whether a version bump of the CrowdSec image changes other e2e outcomes.
- How a `RateLimit()` key is scoped (per IP or global) — affects e2e isolation from other tests.

## Tensions
- Spec "Structured ban keeps the operator ban template" says ban uses the remediation status; this change makes 429 an exception.
- README says ban status is always `bouncerRemediationStatusCode`.
