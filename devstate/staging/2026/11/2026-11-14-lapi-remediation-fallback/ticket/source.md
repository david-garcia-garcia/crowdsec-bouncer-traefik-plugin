# Add lapiRemediationFallback for unknown LAPI decision types

## Context

Fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198, commit 3388bbca, on master, not released) made every LAPI decision type other than `ban` / `captcha` ingest as `ban`. It followed upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) and upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403).

Upstream PR #433 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433, open) proposes special-casing decisions of type `whitelist` as an allow (skip on stream New, skip on stream Deleted, ignore in live, and an in-memory set that exempts a whitelisted IP from Range bans). Its Range-in-stream part is already covered by this fork and is out of scope here.

## What CrowdSec documents (researched 2026-11-14)

- LAPI swagger (`pkg/models/localapi_swagger.yaml`): Decision `type` is a free string, "might be 'ban', 'captcha' or something custom". No enum.
- `cscli decisions add --type`: "Decision type (ie. ban,captcha,throttle)". Profiles: "for example `ban`, `captcha`".
- `whitelist` and `allow` are NOT CrowdSec decision types. No official component gives them allow semantics.
- The LAPI decision stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW. Allowing traffic in CrowdSec is done with parser whitelists (https://docs.crowdsec.net/u/getting_started/post_installation/whitelists) and LAPI allowlists (`cscli allowlists`, https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists). They act before a decision exists and never reach a bouncer.
- Bouncer spec (https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs): remediation is "ban", "captcha" or "potentially any custom string"; unknown types follow `remediation_fallback`: "Defaults to ignore/ban/captcha"; "If ignored, you don't even need to store the decision".
- Official bouncers: lua-cs-bouncer maps any type other than ban/captcha/challenge to `FALLBACK_REMEDIATION` (default ban). cs-firewall-bouncer only applies `supported_decisions_types` (default ["ban"]) and ignores others on both add and delete ("decisions for ip '%s' will not be deleted because its type is '%s'").

## Desired

1. New config knob `lapiRemediationFallback` (Go field `LapiRemediationFallback`, json `lapiRemediationFallback`) on the LAPI configuration. Values: `ban` | `captcha` | `ignore`. Default `ban` (keeps #198 behavior). Any other value is rejected by config validation.
2. It applies only to LAPI decision types that are neither `ban` nor `captcha`, at LAPI ingest:
   - `ban`: ingested as ban (today).
   - `captcha`: ingested as captcha.
   - `ignore`: the decision is not stored. Stream `new`: Ip, header-mapped scopes and Range are all skipped. Stream `deleted`: an unknown-type row does not delete anything (neither the Ip/header slot nor the Range CIDR), so it cannot clear a ban another decision holds on the same value. Live/none: excluded from the strongest-decision pick; an IP whose only decisions are unknown-type passes.
3. Do not special-case `whitelist`, `allow`, or any other type name in code. The knob is the only policy.
4. The knob is not the LAPI-unreachable behavior; that stays `bouncerLapiFailureAction`. README must say so.
5. Record the decision in usage docs (devdocs) and README: `whitelist` / `allow` are not valid CrowdSec decision types; using decisions to allow traffic is an inadequate way to manage whitelists, because the LAPI stream is designed to say what to block, not what to allow; the supported way is parser whitelists / LAPI allowlists (`cscli allowlists`).
6. Correct `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`: remove the allow-as-veto framing and the recovered "Allow is a whitelist" Pester test (do not restore it); keep the real debt (several decisions on one key: two bans, ban+captcha, a typed delete clearing the whole slot).
7. Tests: unit tests for each knob value on stream (Ip, header scope, Range, deleted) and live; config validation test.

## Out of scope

- Upstream #433 Range-in-stream option and its in-memory AllowSet.
- Storing several decisions per cache key (existing debt).
- Any change to `bouncerLapiFailureAction`.

## Delivery card (must)

The delivery card must reference upstream issue #402 (point 1), upstream PR #403 (point 1), upstream PR #433 (whitelist part) and fork PR #198, and must state clearly that WHITELIST or ALLOW are not valid CrowdSec decisions and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW.
