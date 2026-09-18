## Why

In live mode, `handleNoStreamCache` writes the PreferRemediation merge of the IP query and every header-scope query onto the client-address cache key. A header-only ban therefore becomes an IP ban for `defaultDecisionSeconds`, so a later request from the same address with a different header identity inherits that ban without another LAPI call.

## What Changes

- After the live scope loop, write only the **IP query result** to the client-address key. Header remediations stay on `HeaderScopeKey` via `cacheLiveScope`.
- A clean IP query plus a remediating header writes `NoBannedValue` on the IP key. The request that just merged still returns the header remediation.
- An IP ban plus a header ban still writes the IP ban on the IP key.
- Keep the fail-closed rule: a header-scope query error with no active merge MUST NOT write a negative IP-key entry.
- Add `TestLiveLookup_IPSlotKeepsIPQueryResult` next to `TestLiveLookup_ScopeBanWins`: assert the IP slot is the IP query result, and `LookupCachedRemediation` for the same IP plus a different header does not inherit the first identity's ban.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: the live IP cache slot stores the IP query result, not the merged header-plus-IP verdict. Header remediations stay on `HeaderScopeKey`.

## Impact

- `pkg/lapi/client_live.go` (`handleNoStreamCache` IP-slot write)
- `pkg/lapi/zzz_failure_action_test.go` (regression next to `TestLiveLookup_ScopeBanWins`)
- `openspec/specs/core_plugin_decisions_scopes/spec.md` (one added requirement)
- No public JSON/YAML key changes
- Out of scope: stream/alone apply order, `HeaderScopeKey`, `LookupCachedRemediation` merge order, live TTL math, `none` mode (TTL 0 already skips live cache writes), CAPI login, captcha, AppSec, reclaim, `pkg/cache` key format
