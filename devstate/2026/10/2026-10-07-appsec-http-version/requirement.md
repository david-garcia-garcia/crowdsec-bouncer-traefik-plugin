# Requirement
IssueKey: 2026-10-07-appsec-http-version

## Problem
Upstream pull request https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400 reports that the Traefik bouncer never sends the client HTTP version to CrowdSec AppSec. AppSec expects that version on `X-Crowdsec-Appsec-Http-Version` as a two-digit integer string (`"10"`, `"11"`, `"20"`) so it can populate `r.Proto`. Without the header, AppSec uses the Traefik-to-AppSec connection version (HTTP/1.1), and rules cannot see the original client protocol.

## Current (code)
- `pkg/appsec/query.go` declares `X-Crowdsec-Appsec-Ip`, `X-Crowdsec-Appsec-Uri`, `X-Crowdsec-Appsec-Host`, `X-Crowdsec-Appsec-Verb`, `X-Crowdsec-Appsec-Api-Key`, and `X-Crowdsec-Appsec-User-Agent`. No `X-Crowdsec-Appsec-Http-Version` constant.
- `pkg/appsec/query.go` `appsecQuery` sets those headers on the outbound AppSec request (IP, verb, host, URI, client User-Agent, plugin User-Agent) and does not read `ProtoMajor` or `ProtoMinor` for that request.
- `pkg/appsec/zzz_query_test.go` covers AppSec query behavior and does not assert an HTTP-version header.

## Desired
- Confirm whether this fork is missing the header. The current code is missing it.
- Confirm the header name and value encoding against official CrowdSec AppSec documentation.
- If the fork is affected, set `X-Crowdsec-Appsec-Http-Version` from the client request protocol version and add a unit test that the outbound AppSec request carries it.
- If the fork is not affected, add a test that proves the client HTTP version already reaches AppSec.
- The delivery card must mention upstream pull request https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400.

## Affected
- `pkg/appsec/query.go` outbound AppSec request headers
- `pkg/appsec/zzz_query_test.go`

## Out of scope
- Changing the other `X-Crowdsec-Appsec-*` headers
- Rewriting the e2e AppSec mock unless that is the only way to prove the header
- Copying the upstream patch verbatim when this tree's `appsecQuery` shape differs

## Unknowns
- Official CrowdSec AppSec docs: exact header name, and whether the value is `"10"` / `"11"` / `"20"` rather than `HTTP/1.1`
- Whether a missing header makes AppSec default to the bouncer connection version (upstream claim; not measured here)

## Tensions
- None. The in-tree header list matches the upstream claim that the client HTTP version is not forwarded. The encoding and the AppSec default are not confirmed in official docs yet.