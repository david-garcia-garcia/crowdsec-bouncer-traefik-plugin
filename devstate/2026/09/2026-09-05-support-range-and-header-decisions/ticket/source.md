# Repurpose upstream PR 383 onto MASTER

Caller: run sbs-dev-workflow for slug `support-range-and-header-decisions`. DestBranch is this fork's `master` (not upstream `main`). Dedicated worktree. Finished work is a PR with CI passing and an updated delivery card. Mention this upstream PR and related upstream issues on that card. Now that MASTER has real-stack e2e, add real e2e coverage for the new remediation types.

## Upstream PR (source of the product change)

https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383

Title: ✨ feat(bouncer): honor header-mapped CrowdSec decision scopes + IP-Range

Open. Head `david-garcia-garcia:newdecisions` @ `4872e4383997dde409e0cf053f9303f0bbd31eb0`. Base `maxlerebourg:main`.

Product ask from that PR:

This plugin only remediates by exact client IP. CrowdSec already issues Range, Country, AS, and other scoped decisions; the bouncer stored `decision.Value` and looked up only the remote address, so those decisions never matched.

Desired:

- Range matching is on without new config. CrowdSec `Range` decisions this plugin used to ignore now remediate by CIDR containment (stream and alone).
- Country, AS, and other scopes stay off until mapped.
- New public key `decisionScopeHeaders` (CrowdSec scope name → request header). Empty (the default) disables header scopes. `Ip` and `Range` are rejected as keys.
- Country (any case): ISO 3166-1 alpha-2; skip `XX` / `T1`.
- AS (any case): decimal ASN; a leading `AS` / `as` is stripped.
- Any other key: trimmed exact match. The key must match the scope LAPI stored.
- This plugin does not look up GeoIP.
- Stream asks LAPI for every mapped scope. Live/none still expand Range via `?ip=` and add `scope`+`value` when a mapped header is present.
- When several scopes hit, ban wins over captcha.

## Related upstream issues and PRs

- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271 — [FEATURE] Support Decision Scope (open). CrowdSec sends Ip / Range / Country / AS; current implementation treats everything as Ip. Range: radix tree (follow-up). Country/AS: rely on an existing header, do not geolocate in this plugin. PR 383 and PR 368 both claim to close it.
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368 — 🐛 Support range decision on stream mode (open, maxlerebourg). Stream-only Range cache. PR 383 says it should be closed as superseded; it does not close #271.
- https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/3 — same `newdecisions` head against this fork's `main` (not `master`). Do not reuse; open a new PR against `master`.

## Additional caller requirement

Real-stack e2e (`tests/e2e/real/`) must cover the new remediation types (Range and header-mapped scopes), not only mock LAPI.
