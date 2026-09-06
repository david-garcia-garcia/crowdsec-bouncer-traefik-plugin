# traefik-modsecurity health Tracker

Tumbling-window failure counter with timed backoff for a WAF sidecar. Named reference for CrowdSec bouncer client backoff.

Fetched: 2026-09-06. Source pin: `github.com/david-garcia-garcia/traefik-modsecurity@645f4a25d5023fc42e615e02240cab29799b39c5`.

## Algorithm

`pkg/health/Tracker` ([tracker.go](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/main/pkg/health/tracker.go), extract `.sources/tracker.go.md`):

- **RecordFailure** increments a counter. When `failureWindow > 0`, the counter resets if the window elapsed since `lastFailureReset` (tumbling window, not leaky bucket).
- When `failureCount >= failureThreshold`, sets `isShutdown` and `shutdownUntil = now + backoffTimeout`.
- **IsUnhealthy** fast-path reads `isShutdown` without lock; when shutdown and `now > shutdownUntil`, auto-recovers (clears shutdown and counter).
- `failureThreshold < 0` disables tripping (opt-out).

## Integration in traefik-modsecurity

`pkg/modsecurity/plugin.go` creates the tracker when `UnhealthyWafBackOffPeriodSecs > 0`, passing backoff, window, and threshold from config.

`pkg/modsecurity/serve.go`:

- Before calling the sidecar: if `IsUnhealthy()`, skip the HTTP call and `serveFailClosedOrNext` (fail-open or fail-close per plugin fail mode).
- On transport/HTTP failure from the sidecar: `RecordFailure()`.

Shared tracker across middleware instances reusing the same plugin slot (`plugin_reuse_test.go`).

## Config shape (reference repo)

- `UnhealthyWafBackOffPeriodSecs` → backoff timeout
- `UnhealthyWafFailureWindowSecs` → tumbling window
- `UnhealthyWafFailureThreshold` → trip count

Ticket proposes analogous LAPI/AppSec knobs with `*FailureBackoff*` naming.

## Relation to CrowdSec bouncer today

This plugin already has per-request LAPI/AppSec failure actions (`crowdsecLapiFailureAction`, `crowdsecAppsecFailureAction`) and stream poll health (`updateMaxFailure` / `StreamHealthy`). It does **not** yet skip outbound calls during a backoff window after repeated failures on the request path.

## References

- Source: `github.com/david-garcia-garcia/traefik-modsecurity@645f4a25`
- Extracts: `.sources/`
