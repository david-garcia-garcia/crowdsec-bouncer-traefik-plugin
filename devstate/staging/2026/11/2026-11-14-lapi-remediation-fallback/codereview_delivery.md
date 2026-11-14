# Delivery

## Motivation
CrowdSec LAPI decisions carry a free-text `type`. The plugin knows how to remediate two of them, `ban` and `captcha`. Fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198), following upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) and upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403), made every other type (for example `throttle` or `challenge`) ingest as a ban, on stream New (Ip, header-mapped scopes, Range) and in the live/none pick. That fails closed, but the operator has no choice: the CrowdSec bouncer spec defines a `remediation_fallback` (ignore / ban / captcha) for exactly this case, and official bouncers let the operator choose (lua-cs-bouncer `FALLBACK_REMEDIATION`; cs-firewall-bouncer applies only its `supported_decisions_types` and ignores other types on add and delete).

A second gap sits on the delete path. Stream Deleted rows never read the type, so a Deleted row of a type the plugin does not remediate still drops whatever the Ip slot or Range CIDR holds. Reproduced in explore: tick 1 stores a ban for `203.0.113.7` and for `10.0.0.0/8`; tick 2 sends only Deleted rows of type `throttle` for the same Ip and CIDR; both bans are gone. There was no setting that makes such a row a no-op.

Upstream PR #433 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433) proposes the opposite answer for one type name: treat `whitelist` decisions as an allow that lifts bans. This fork's own debt note carried the same allow-as-veto idea. That model is wrong. WHITELIST or ALLOW are not valid CrowdSec decisions, and using decisions to allow traffic is an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW. The LAPI swagger defines `type` as "'ban', 'captcha' or something custom", and no CrowdSec component gives `whitelist` or `allow` allow semantics. Allowing traffic is done upstream by parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source.

Left alone, operators who run custom types must accept every one as a ban, an unknown-type delete can lift a real ban, and the pressure to special-case `whitelist` as an allow (upstream #433) stays open.

Priority: P2 — operators get no choice for unknown decision types and an unknown-type delete can clear a real ban; the default still fails closed, so the blast radius is limited

## Implementation
One public knob, `lapiRemediationFallback` (`ban` | `captcha` | `ignore`, default `ban`, empty treated as `ban`), validated as an enum in `ValidateParams`. It lives on the LAPI connection: `lapi.New` reads it from the middleware that opens the connection and holds the effective value on `lapi.Client`; a subscriber's value is unused, as for `lapiStreamScopes`.

The policy stays at LAPI ingest. `ingestRemediationKind` keeps `ban` / `captcha` unchanged and maps every other type to the fallback letter (`t`, `c`) or to empty under `ignore`, TRACE-logging `handleStreamCache:unknownType` with `type` and `fallback`. Every ingest site reads empty as "not stored": `streamPutItem` (Ip and header scopes), the Range New branch, and the live/none strongest pick, so an IP whose only decisions are unknown-type passes under `ignore`. One `Client` predicate, `deletedTypeClearsStore`, guards both Deleted shapes (Ip/header and Range): under `ignore` an unknown-type Deleted row deletes nothing; under `ban` / `captcha` it keeps the whole-slot delete (the existing multi-decision-per-key debt). Skipped rows do not count in the poll counters. No type name is special-cased; `whitelist` and `allow` follow the knob like `throttle`.

The effective value enters the Client ownership key and, only when it is not `ban`, the `SessionHex` store identity (`omitempty`). A change of value opens a new Client and a new DecisionStore that refills from LAPI; default deployments keep their `SessionHex` and Redis keys on upgrade. README (Decisions paragraph and Variables entry), usage devdocs and the debt note carry the whitelist / allow position; the debt note loses its allow-as-veto framing and keeps the real multi-decision debt.

Process note: this run used the OpenDev CLI (`opd-mcp/scripts/cli.mjs`) instead of the OpenDev MCP, the GitHub MCP for PR operations, and Claude Code subagents without the configured grok model slug.

## What this changes
**Operators.** New optional key `lapiRemediationFallback` (`ban` default, `captcha`, or `ignore`) on the middleware that connects to LAPI decides what happens to decision types other than `ban` and `captcha`; changing it from `ban` forks the decision store, which refills from LAPI, and it is separate from `bouncerLapiFailureAction`.
**Admin users.** None.
**Developers.** `whitelist` / `allow` decisions are not an allow anywhere in the plugin and no type name may be special-cased; unknown types go only through `lapiRemediationFallback`.
**End users.** None.
