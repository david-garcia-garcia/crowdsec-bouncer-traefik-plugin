## Why

When a client disconnects mid-body on a readable POST (HTTP/2 CANCEL, `context.Canceled`, etc.), `newAppsecBodyRequest` returns `appsecQuery:GetBody` without honoring `crowdsecAppsecFailureAction`, so `applyAppsecServeHTTP` always bans with `ReasonAPPSEC` even when the operator chose `passthrough`. AppSec never runs; the 403 is a false AppSec ban. Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

## What Changes

- Classify **client-gone** errors during buffered body read (`context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF`) and route them through `resultForFailureActionErr` in `newAppsecBodyRequest`, same family as unreachable and unreadable-body fallbacks.
- **`passthrough`:** allow without calling AppSec (no false 403).
- **`ban` / `captcha`:** keep drop/challenge semantics via existing failure-action mapping; no new public config knob.
- **Out of scope:** extending `isBodyUnreadable` for mid-stream errors; skipping `handleBanServeHTTP` when the client is already gone; metrics/LAPI changes; silent pass-through that ignores `FailureAction`.
- Add an automated regression in `pkg/appsec/zzz_query_test.go` that proves #395 on this tree (fails before fix, passes after).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_failure-action`: extend the unified failure-action requirement so client-side body read cancellation/disconnect during AppSec buffering honors `crowdsecAppsecFailureAction` (ADD scenarios for passthrough and ban).

## Impact

- `pkg/appsec/query.go` (`newAppsecBodyRequest`, client-gone classification helper).
- `pkg/appsec/zzz_query_test.go` (#395 proof).
- `openspec/specs/core_plugin_appsec_failure-action` (delta fold).
- `knowledge/devdocs/core_plugin_appsec.md` after implement (devdocsimpact) — document the client-body-dropped path beside existing FailureAction cases.
- No change to `pkg/bouncer/bouncer.go` ban wiring unless implement finds a gap; explore assumes fixing `Query` is sufficient.
