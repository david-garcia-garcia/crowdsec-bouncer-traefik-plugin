## Why

Live/none LAPI lookups and AppSec queries wait `HTTPTimeoutSeconds` on every request when CrowdSec is down or slow. Fail-open and fail-close already name the fallback, but they run only after that wait, so an outage still sits on the request path.

## What Changes

- Add a tumbling-window health Tracker (`pkg/health`) copied from traefik-modsecurity: count failures in a window, trip unhealthy at threshold, auto-recover after a backoff timeout. Next request after recover is the probe. Not a leaky bucket.
- Skip outbound LAPI live/none calls and AppSec `Query` HTTP while that backend’s Tracker is unhealthy. Apply existing `crowdsecLapiFailureAction` / `crowdsecAppsecFailureAction` without waiting on HTTP timeout.
- Public knobs (ticket names): `lapiFailureBackoffTimeout`, `lapiFailureBackoffBucketWindow`, `lapiFailureBackoffBucketThreshold`, and AppSec equivalents. Defaults 30s / 30s / 5. Disable with threshold `-1` or timeout `0`.
- Trackers live on the reclaimed `lapi.Client` and `appsec.Client`. Knobs join those reclaim identities. Stream/alone poll `updateMaxFailure` is unchanged. Unreadable AppSec bodies and live “banned” decisions do not increment.

## Capabilities

### New Capabilities

- `core_plugin_health_tracker`: Tumbling-window failure Tracker (timeout, window, threshold, trip, auto-recover, opt-out).
- `core_plugin_lapi_failure-backoff`: Live/none LAPI skip while unhealthy; record live query errors; LAPI knobs on live reclaim identity; not stream polls.
- `core_plugin_appsec_failure-backoff`: AppSec `Query` skip while unhealthy; record unreachable/500; AppSec knobs on AppSec reclaim identity.

### Modified Capabilities

- `core_plugin_appsec_client`: AppSec reclaim key also includes the three AppSec backoff knobs.

## Impact

- `pkg/health` — new Tracker + tests
- `pkg/configuration` — six knobs, defaults, validation, README
- `pkg/lapi` — Tracker on Client; LiveLookup skip; RecordFailure on live query errors; identity fields
- `pkg/appsec` — Tracker on Client; Query skip; RecordFailure on unreachable/500; identity fields
- Stream/alone request path, captcha providers, Redis, and failure-action enum values are unchanged
