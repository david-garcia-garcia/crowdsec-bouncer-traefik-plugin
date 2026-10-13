## Context

See proposal.md Why. Dest ingest maps LAPI `type` in two switches in `bouncer.go`. `default` logs Info `handleStreamCache:unknownType` and leaves `value` empty. `pkg/cache` treats empty as `CacheMiss`. Stream ServeHTTP then allows. Live ServeHTTP remediates the empty return as a ban on the first query, then caches a miss.

Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 1 assigns `cache.BannedValue` in those same defaults. This change is that ingest fail-closed on this tree; it is not a copy of that patch.

## Goals / Non-Goals

**Goals:**

- Unknown LAPI types (`challenge`, `allow`, any other non-`ban`/`captcha`) store and apply as ban in stream, live, and none.
- Keep the existing unknown-type log site and level (Info).
- Empty list / `null` stay allowed.

**Non-Goals:**

- Changing `cache.Get` empty-as-miss.
- Adding `RemediationValue` (not on dest).
- AppSec challenge relay, metrics, captcha provider.
- Other points of upstream PR 403.
- Bootstrapping `openspec/specs/`.

## Decisions

- Fail-closed at the two ingest switches, not at cache Get. Empty remains miss for every other caller.
- Same assignment in both switches (`value = cache.BannedValue` in `default`) so stream and live stay symmetrical.
- Tests call `handleStreamCache` / `handleNoStreamCache` with a mock LAPI and assert `cache.BannedValue`; an empty list asserts `cache.NoBannedValue`.

## Risks / Trade-offs

- [Unknown custom types now ban] → intended fail-closed; same as lua-cs-bouncer `FALLBACK_REMEDIATION=ban`.
- [Live already banned empty returns] → storing `BannedValue` makes the live cache a hit instead of a re-query; behavior stays ban.
