# Requirement
IssueKey: 2026-09-05-bot-detection

## Problem

CrowdSec 1.8.0 AppSec bot-detection returns a structured challenge (HTML body, `__crowdsec_challenge` cookie, `/crowdsec-internal/challenge/*` callback) instead of a bare WAF 403. This plugin treats any non-200 AppSec HTTP status as a ban, discards the AppSec response body, and the engine logs a broken pipe. With `crowdsecurity/appsec-bot-*` loaded, every AppSec-enabled route becomes a permanent 403 even when no WAF rule matched. Upstream: [issue 389](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389), implementation shape in [PR 343](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343).

## Current (code)

- `pkg/crowdsecconnection/connection.go` `AppsecQuery`: forwards the request to AppSec; on HTTP 500 honors `FailureBlock`; on any other non-200 returns `appsecQuery statusCode:N` and never parses the JSON body. The deferred drain copies leftover bytes to discard, which is what closes the AppSec write (issue 389 broken pipe) before a challenge can be relayed.
- `pkg/bouncer/bouncer.go` `handleNextServeHTTP`: if `appsecEnabled` and `AppsecQuery` returns an error, always `handleBanServeHTTP` with `ReasonAPPSEC` (operator ban template / 403). There is no path that writes AppSec-supplied status, headers, cookies, or body to the client.
- No plugin config key exists for bot-detection. PR 343 states none is needed: AppSec on, challenge paths through the same middleware.
- `pkg/crowdsecconnection/appsec_test.go` covers streaming body, unreadable HTTP/3 GET, and connection reuse. It does not cover structured `action` JSON.
- Real e2e `tests/e2e/real/appsec.Tests.ps1` only asserts CRS inband allow (200) vs SQLi (403) on `/appsec`. Compose CrowdSec image is `crowdsecurity/crowdsec:v1.7.8` with `crowdsecurity/appsec-crs-inband` (`tests/e2e/real/docker-compose.test.yml`, `tests/e2e/real/acquis.yaml`). No `/crowdsec-internal/challenge` route. Bot-detection collections are not loaded.
- Mock AppSec (`tests/e2e/mock/mocklapi/main.go`) answers 200 / 403 / 500 / 502 from URI substrings with an empty body.
- Specs: no `core_*appsec*` leaf under `openspec/specs/`. Usage: `knowledge/devdocs/build_e2e_real.md` documents CRS AppSec only. Research: `knowledge/research/index_ext_crowdsec.md` has docker env, cscli decisions, and decision scopes — not the AppSec challenge JSON.

## Desired

- Parse a structured AppSec JSON body (`action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers`) when present.
- `action` empty or `allow` → pass the request to `next` (same as today's 200).
- `action` `ban` → keep today's ban template path (`handleBanServeHTTP`), not AppSec HTML. Matches PR 343 review intent after rebase (structured ban must not silently drop `banTemplate`).
- Any other non-allow action (including `challenge`) → write AppSec status, headers, cookies, and body to the client. Clamp `http_status` to 100–999; fall back to `remediationStatusCode` when missing or out of range. Fall back `Content-Type` to `banTemplateContentType` when AppSec omits it.
- Legacy empty/non-JSON non-200 remains a ban (today's behavior).
- Bound AppSec response body reads (PR 343 used 1 MiB). Keep draining so the AppSec connection stays reusable (`appsec_test.go` reuse case).
- Unit tests for parse + relay + legacy 403 + structured ban-keeps-template. Mock e2e for structured challenge. Real e2e against a live CrowdSec that can issue bot-detection (engine ≥ 1.8.0, `appsec-bot-*`, challenge path routed through the same middleware).
- No new plugin option unless research proves one is required.

## Affected

- `pkg/crowdsecconnection` (`AppsecQuery` return value / parse)
- `pkg/bouncer` (`handleNextServeHTTP` and a relay writer)
- `pkg/crowdsecconnection/appsec_test.go` and bouncer tests
- `tests/e2e/mock` AppSec mock + scenario
- `tests/e2e/real` compose, acquis, Pester (`appsec.Tests.ps1` or a sibling)
- OpenSpec change + spec leaf for AppSec structured remediation
- `knowledge/devdocs` AppSec / e2e packets after implement

## Out of scope

- Upstream maxlerebourg merge of PR 343 (we implement on this fork).
- Documented-only graceful fallback instead of relay (issue listed that as an alternative; the caller asked to implement the feature).
- CrowdSec LAPI captcha (`pkg/captcha`) — different remediation.
- New public plugin config keys (PR 343: none for Traefik).
- Changing `isMethodWithBody` / HTTP/3 unreadable-body policy except as needed to keep existing tests green.
- Commenting workflow cards onto maxlerebourg/issue 389 (different owner; dump only).

## Unknowns

- Exact CrowdSec 1.8.0 AppSec JSON field set and HTTP status used for `challenge` vs `ban` vs `allow` (research in flight; PR 343 is the bouncer-side source).
- Whether real e2e can stay on one CrowdSec image (today `v1.7.8`) or must bump to `v1.8.0` for `appsec-bot-*`.
- How operators must wire `/crowdsec-internal/challenge` in Traefik (PR 343 compose vs CrowdSec docs); whether our real stack needs a dedicated router.
- Whether `crowdsecAppsecUnreadableBodyBlock: false` is required for the challenge callback (PR 343 comment by alexstrassheim).

## Tensions

- Issue 389 allowed either relay or a documented fallback; this run takes relay (caller).
- PR 343 first served every non-`allow` action from AppSec HTML, including `ban`; reviewer asked to keep `banTemplate` for `action: ban`. Desired follows the review, not the first patch.
- Real e2e today pins CrowdSec 1.7.8 / CRS-only; bot-detection needs 1.8.0 collections. Image bump is in scope for the test stack if required, not a silent product version change.
