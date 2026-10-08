# Caller spec

Confirm whether upstream pull request https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400 affects this fork.

Upstream report (ffluegel, 2026-10-07), title: forward client HTTP version to AppSec via X-Crowdsec-Appsec-Http-Version.

CrowdSec AppSec expects the original request HTTP version in `X-Crowdsec-Appsec-Http-Version` as a two-digit integer string (`"10"`, `"11"`, `"20"`) to populate `r.Proto` during evaluation.

Previously, this header was not forwarded by the Traefik bouncer plugin. As a result, AppSec defaulted to the HTTP connection version used by the Traefik-to-AppSec client (HTTP/1.1), making it impossible for AppSec rules to inspect or enforce decisions based on the original client's HTTP protocol version (such as blocking HTTP/1.0 requests).

Upstream changes named in the report:

- Added constant `crowdsecAppsecHTTPVersionHeader = "X-Crowdsec-Appsec-Http-Version"`.
- In `appsecQuery()`, set `X-Crowdsec-Appsec-Http-Version` using `httpReq.ProtoMajor` and `httpReq.ProtoMinor`.
- Added unit test `Test_appsecQuery_forwardsHTTPVersion` in `bouncer_test.go`.

Ask:

- Confirm whether that gap exists in this fork.
- Confirm the header contract against the official CrowdSec AppSec documentation.
- If the fork is affected, fix it and add test coverage.
- If the fork is not affected, ensure a test exists that proves it is not affected.
- Mention upstream pull request https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400 on the delivery card.
