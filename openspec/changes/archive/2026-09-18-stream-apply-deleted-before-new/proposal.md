## Why

On DestBranch, one CrowdSec stream window can carry a replacement: a new ban for an IP or CIDR plus a delete of the prior decision for that same value. The poller writes `new` first, then applies `deleted`, so the replacement disappears and the client is allowed. Official CrowdSec bouncers apply deleted first.

## What Changes

- In `fetchAndApplyStreamDecisions`, loop `stream.Deleted` (IP/header `deleteStreamDecision`, Range removals, `forgetActiveDecision`) before `stream.New` (IP/header `storeStreamDecision`, Range upserts, `rememberActiveDecision`).
- In `ApplyRangeBatch`, apply removals before upserts so a CIDR in both maps remains the replacement. Keep one cache read and one write. Do not split the batch.
- Add IP and Range same-window replacement regressions (`TestHunt_StreamAppliesDeletedBeforeNew`, `TestHunt_StreamRangeAppliesDeletedBeforeNew`) that fail on dest order and pass after the swap.

## Capabilities

### New Capabilities

- `core_plugin_lapi_stream-apply`: write one CrowdSec stream payload into the DecisionStore with deleted before new, including Range removals before upserts in one `ApplyRangeBatch`.

### Modified Capabilities

None.

## Impact

- `pkg/lapi/client_stream.go` (`fetchAndApplyStreamDecisions`)
- `pkg/decisionscope/range.go` (`ApplyRangeBatch` removal-then-upsert order)
- `pkg/lapi/zzz_client_stream_test.go` (two hunt regressions)
- Usage already points at this invariant (`knowledge/devdocs/core_plugin_lapi_stream-apply.md`)
- Official apply order: `knowledge/research/ext_crowdsec_bouncers_stream-apply/`
- No **BREAKING** public JSON/YAML keys
- Out of scope: stream lease, single-flight, live/none, AppSec, captcha, reclaim, metrics reporter, LAPI JSON field order, header-only hunt test, official bouncer repos
