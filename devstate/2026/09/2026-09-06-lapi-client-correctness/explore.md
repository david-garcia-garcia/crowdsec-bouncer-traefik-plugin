# Explore
IssueKey: 2026-09-06-lapi-client-correctness

## Concepts

**LAPI Client (`pkg/lapi.Client`):** Reclaim value for one CrowdSec LAPI/CAPI backend — stream/metrics tickers, `crowdsecQuery` HTTP helper, isolated cache, in-process Range membership. Stream/alone modes poll `GET …/decisions/stream`; live/none call `GET …/decisions?ip=` and `?scope=&value=` per mapped header scope. Owner: `knowledge/devdocs/core_plugin_middleware.md`.

**Stream poll loop:** `startStream` → optional initial `handleStreamTicker` (sync or `go`) → `startTicker` fires `go handleStreamTicker()` every `updateInterval`. `handleStreamTicker` → `handleStreamCache` (lease on cache key `updated`, stream GET, JSON apply). Health fields `isCrowdsecStreamHealthy`, `isCrowdsecStreamStartup`, `updateFailure` drive `StreamHealthy()` and `streamQuery()` `startup=` flag. `UpdateMaxFailure` default **0** (`configuration.go:180`) — first failed poll marks unhealthy when threshold reached.

**Live lookup:** `LiveLookup` → `handleNoStreamCache` — IP query first; scope map merged via `mergeLiveScope`. IP LAPI errors return `("", err)` → bouncer `applyLapiFailureAction`. Scope LAPI errors are logged and ignored (fail-open). Bouncer only applies failure action when `err != nil && !IsActiveRemediation(kind)` (`bouncer.go:216-221`); IP-ban path still remediates when kind is active even with err.

**HTTP helper:** `crowdsecQuery` — GET when `data` empty, POST otherwise. Alone-mode 401 renews token then **recurses with `nil` data** (drops body). Metrics POST in alone mode uses this path (`client_metrics.go:215`).

```
  Stream/alone (today — overlapping polls possible)
  ┌──────────── ticker.C ────────┐
  │  go handleStreamTicker()     │  Wake() also: go handleStreamTicker()
  │    handleStreamCache         │  startStream: sync or go initial poll
  │      lease hit → return nil  │  ← may hide in-flight failure
  │      else GET stream         │
  │    mutate health fields      │  ← no mutex
  └──────────────────────────────┘
```

## Decisions

- **One change in `pkg/lapi`** (+ tests): shared `crowdsecQuery` fix benefits stream GET, live GET, metrics POST, alone login — do not split PRs.
- **Serialize stream polling per `Client`:** add a dedicated poll gate (e.g. `streamPollMu` + in-flight flag, or `sync.Mutex` around `handleStreamTicker` body). Do not rely on ticker spacing; `Wake`, `startStream`, and `startTicker` all spawn concurrent work today (`client.go:294-302`, `271-272`, `client_stream.go:37-43`).
- **Lease short-circuit:** return early on `updated` lease hit only when no stream poll is in flight; if a poll is running, wait for it or treat lease hit as “skip GET” without resetting failure accounting for the in-flight outcome.
- **Health fields:** protect `isCrowdsecStreamHealthy`, `isCrowdsecStreamStartup`, `updateFailure` under the same poll serialization (or a mutex) so `streamQuery()` and `handleStreamTicker` cannot race.
- **`crowdsecQuery` transport errors:** split `err != nil` from status check; never read `res` when `err != nil || res == nil`. Return unreachable error (no panic). Reorder condition explicitly — today Go `||` short-circuits so panic was **not reproduced**, but the combined condition is fragile.
- **Alone-mode 401 retry:** preserve original method and replay POST body (buffer bytes before first `Do`, pass same `data` on retry). Stream-mode 401 stays out of scope (not retried today).
- **Live scope errors:** `mergeLiveScope` returns error when scope `queryLiveDecisions` fails; `handleNoStreamCache` propagates as `("", err)` so bouncer can `applyLapiFailureAction`. Matches IP unreachable semantics. No bouncer code change in scope — surfacing error is sufficient (`requirement.md` Out of scope).
- **Tests:** httptest, call `handleStreamTicker` / `handleStreamCache` / `LiveLookup` **directly** (no ticker) so concurrency fix does not mask assertions. Cover: health threshold/recovery/`updateMaxFailure:-1`, stream JSON apply (IP/header/range/delete), nil-transport unreachable, alone 401 POST retry (metrics route), live scope 500.
- **Reclaim / plugin lifetime:** per-Client serialization only; no package globals or `sync.Once`. Traefik `New` ctx holds reclaim slot (`knowledge/devdocs/std_go_reclaim.md`); overlapping polls are within one `*lapi.Client`, not cross-middleware.

## Reproduction

Ran `go test ./pkg/lapi/ -count=1 -v` — **18 tests passed** (0.98s). Existing coverage: IP live LAPI 500 error path (`failure_action_test.go`), stream lease-hit hydrate only (`client_range_test.go:54-64`). **No tests** for overlapping polls, health transitions, stream body apply, nil transport, 401 POST retry, or scope failure.

Throwaway `TestRepro_crowdsecQueryNilResponsePanic` (deleted, not committed): custom `RoundTrip` returning `(nil, err)` — **no panic**; Go evaluates `err != nil` first on `||`, so `res.StatusCode` is not read. Defect confirmed as **unsafe pattern / missing guard**, not a reproduced runtime panic on current Go.

Code reading confirms remaining defects:

| Defect | Location | Status |
|--------|----------|--------|
| Overlapping stream polls | `startTicker` `go work()`, `Wake` `go handleStreamTicker`, `startStream` initial poll | **Confirmed** |
| Health fields unsynchronized | `client_stream.go:48-63`, `streamQuery` reads flags | **Confirmed** |
| Lease masks in-flight failure | `handleStreamCache` lease hit returns nil unconditionally | **Confirmed** |
| 401 retry drops POST body | `client_http.go:97-101` | **Confirmed** |
| Scope query fail-open | `mergeLiveScope` `134-136` | **Confirmed** |
| Stream health / apply untested | test inventory | **Confirmed gap** |

## Open questions

- Q: Default `updateMaxFailure` at runtime?
  Decision: resolved — `configuration.NewDefaultConfig()` sets `UpdateMaxFailure: 0`; `Client` copies via `New`; spec `core_plugin_lapi_failure-action` documents first-failure unhealthy unless `-1`.
  By: explore

- Q: Scope-error propagation when IP already banned vs IP allowed?
  Decision: assumed — propagate scope LAPI errors from `mergeLiveScope` whenever the scope query fails (same as IP unreachable). When IP already yields active remediation, bouncer still remediates from `kind` even if `err != nil`; when IP allowed and scope fails, `LiveLookup` returns error so `lapiFailureAction` applies. Do not silently omit scopes.
  By: explore

- Q: Serialize stream polls with `Client.mu` vs dedicated mutex?
  Decision: assumed — dedicated stream poll mutex (or in-flight gate) to avoid deadlocking with `Close`/`Sleep`/`Wake` which already take `Client.mu`.
  By: explore

- Q: Is nil-`res` panic a P1 production crash today?
  Decision: assumed — not reproduced (Go `||` short-circuit); still fix in `crowdsecQuery` with explicit guards and split checks. Priority stays P1 for alone-mode POST retry and scope fail-open; transport guard is correctness hardening.
  By: explore

- Q: Stream health tests — use ticker or direct calls?
  Decision: assumed — direct synchronous calls to `handleStreamTicker` / `handleStreamCache` in httptest; no reliance on ticker timing.
  By: explore
