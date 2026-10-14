## Why

Bot-detection posts the proof to `/crowdsec-internal/challenge/submit`. A truncated body fails AppSec validation and the visitor is challenged again. This fork already forwards the full readable body when `appsecBodyLimit` is `0`, and the default 10MB cap is meant to be enough, but the README never says the challenge proof depends on that body.

## What Changes

- README AppSec / bot-detection section states that `/crowdsec-internal/challenge/submit` must reach AppSec with the full form, the default 10MB is enough, a smaller positive limit cuts the proof short, and `0` means no limit (the whole body is sent).
- README **AppsecBodyLimit** key repeats that same operator warning. It does not say `0` sends nothing.
- Re-run `Test_appsecQuery_zeroBodyLimitForwardsPost`. Do not change query behavior. Do not add a duplicate test.

## Capabilities

### New Capabilities

None. Operator README only. Runtime behavior is unchanged.

### Modified Capabilities

None. `core_plugin_appsec_client` already requires `appsecBodyLimit` `0` = unlimited. This change does not alter that SHALL.

## Impact

- `README.md` only (AppSec / bot-detection paragraph; **AppsecBodyLimit** key).
- Existing test `pkg/appsec/zzz_query_test.go` `Test_appsecQuery_zeroBodyLimitForwardsPost` is re-run, not rewritten.
- No query, metrics, or challenge-path 404 change.
- Dest is `master` (this fork). Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 6 documents the same submit-body need but says limit `0` sends no body; that is false here.
