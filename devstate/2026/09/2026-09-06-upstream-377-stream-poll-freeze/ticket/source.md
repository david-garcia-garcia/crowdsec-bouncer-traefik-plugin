# upstream#377

- title: Plugin periodically stops calling GET /v1/decisions/stream for exactly ~20 minutes, while POST /v1/usage-metrics keeps working
- state: OPEN
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377
- created: 2026-08-20T09:45:24Z
- updated: 2026-09-06T14:22:54Z
- labels: (none)

## Body

## Description

In `stream` mode, the plugin intermittently stops calling `GET /v1/decisions/stream`
for a duration that has been consistently ~20 minutes across multiple occurrences,
before resuming spontaneously. During the freeze, the independent metrics reporting
call (`POST /v1/usage-metrics`) continues to fire normally on its own cycle — proving
the plugin process itself is not hung, only the decisions-stream update routine.

## Environment

- crowdsec-bouncer-traefik-plugin: v1.7.1 (latest)
- Traefik: v3.7.10
- CrowdSec: v1.7.8 (Docker), SQLite with WAL mode enabled
- Deployment: Traefik in Docker, `network_mode: service:gerbil`, ARM64 (Oracle Cloud Free Tier) - OS: Ubuntu 24.04.4 LTS
- Plugin config: default `updateIntervalSeconds` (60), default `httpTimeoutSeconds` (10)

## Observed pattern (3 occurrences over 2 days)

| Incident | Duration | Notes |
|---|---|---|
| 1 | ~21 min | No blocklist insert in window |
| 2 | 20 min exactly | No blocklist insert in window |
| 3 | 20 min exactly | No blocklist insert in window |

No correlation found with community-blocklist insertion, and no CrowdSec-side
heartbeat degradation — the LAPI itself responds normally throughout (300-500µs).

## Evidence from debug logs (logLevel: DEBUG, LogFilePath enabled)

Normal cycle, repeating every ~60s:

    cache:Get key:updated
    cache:Set key:updated value:f duration:59s
    handleStreamCache:updated

Last normal cycle before freeze:

    time=2026-08-20T04:26:35.528Z level=DEBUG msg=handleStreamCache:updated

--- 20 minutes of total silence on this routine (no errors logged) ---

Resumption, with a duplicate log line at the exact same timestamp:

    time=2026-08-20T04:46:35.529Z level=DEBUG msg=handleStreamCache:updated
    time=2026-08-20T04:46:35.530Z level=DEBUG msg=handleStreamCache:updated

Subsequent cycles return to normal (single line per tick) immediately after.

During the same freeze window, POST /v1/usage-metrics (separate ~10min cycle)
fired successfully at 04:36:36, confirming the plugin process, network path, and
LAPI connectivity were all fine — only the decisions-stream ticker was stuck.

## What I've ruled out

- SQLite/CrowdSec-side contention (heartbeat stayed at 300-500µs throughout, WAL mode active)
- Network/Docker connectivity issues (usage-metrics POST succeeded mid-freeze)
- Plugin crash (no crash trace file, no container restart, RestartCount stayed 0)
- Already on latest plugin version (v1.7.1)

## Hypothesis

The exact, repeating ~20-minute duration and the duplicated log line at resumption
suggest an internal ticker/goroutine that blocks on the stream call without
respecting httpTimeoutSeconds, then releases with a buffered tick firing alongside
the new one. Not confirmed — no error is logged during the freeze itself.

## Impact

Traefik continues serving traffic normally throughout (no downtime). The only effect
is that newly-banned IPs aren't propagated to the Traefik-level bouncer cache during
the freeze window.

---

# Assessment: upstream#377

- relevant: yes
- kind: bug
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-377-stream-poll-freeze
- rationale: Our fork still runs the same stream-mode path (`handleStreamCache` / `handleStreamTicker` on `GET /v1/decisions/stream` with a cache lease on key `updated`) in `pkg/lapi/client_stream.go`, with independent stream and metrics tickers in `pkg/lapi/client.go`. The reported ~20-minute gap with metrics still posting matches a stream-ticker stall while the metrics goroutine keeps running. We mitigated one upstream hypothesis—synchronous ticker work—via `go work()` in `startTicker` (lines 294–307) and `http.Client.Timeout` from `HTTPTimeoutSeconds`, but there is no test that stream polls cannot stall for extended periods or that timeout always bounds `crowdsecQuery`. Overlapping stream polls remain possible (`go work()` on every tick, plus an extra `go handleStreamTicker()` on `Wake()`), which violates the one-poller intent documented in `openspec/changes/archive/2026-09-06-one-stream-per-lapi-session/` and `devstate/bug-hunt/2026-09-06/lapi/stream-poll-concurrency.md`; the duplicate `handleStreamCache:updated` at resumption in the issue aligns with that Wake+ticker pattern. Reclaim/session tests cover warn-and-wire and grace, not sustained poll gaps.

## Evidence
- current: pkg/lapi/client_stream.go, pkg/lapi/client.go, pkg/lapi/client_http.go, pkg/lapi/session.go
- tests: pkg/lapi/session_test.go, pkg/lapi/client_range_test.go
