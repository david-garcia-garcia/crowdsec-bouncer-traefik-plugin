## Why

A LAPI decision whose type is neither `ban` nor `captcha` (for example `challenge`) is stored as an empty cache payload. Stream Get treats empty as a miss and allows the IP. CrowdSec's challenge protocol and lua-cs-bouncer fail closed to ban for that case.

## What Changes

- Stream ingest (`handleStreamCache`) stores unknown LAPI types as `cache.BannedValue` after the existing `handleStreamCache:unknownType` log.
- Live and none ingest (`handleNoStreamCache`) return and cache unknown LAPI types as `cache.BannedValue` after the same log.
- `allow` is treated as unknown on that ingest path only.
- Empty decision lists and JSON `null` stay `cache.NoBannedValue`.
- Regression tests fail on dest if an unknown type is skipped or allowed.

## Capabilities

### New Capabilities

- None. Dest has no OpenSpec catalog; this change does not bootstrap one.

### Modified Capabilities

- None.

## Impact

- `bouncer.go` `handleStreamCache` and `handleNoStreamCache` type switches.
- Tests in `bouncer_test.go`.
- Operators: a `challenge` (or other unknown) LAPI/blocklist decision now bans the IP in stream, live, and none.
- AppSec `action: challenge` relay, metrics, and captcha provider are unchanged.
