# Unhealthy WAF admission gate

How [david-garcia-garcia/traefik-modsecurity](https://github.com/david-garcia-garcia/traefik-modsecurity) (`e860d2494f41d49172f2d8aae916615c8ee356e1`) skips the CRS sidecar after repeated inspect failures, via `backendbackoff.Gate`. This worktree’s `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/` has no `backendbackoff` package; the plugin’s `go.mod` requires utilities `v1.0.3` (`950b08de86b6fd9ea68ac1d205e17a379ec60522`).

Fetched: 2026-10-12.

## When the gate exists

`newWafGate` returns `nil, nil` when `unhealthyWafBackOffPeriodSecs <= 0`. `CreateConfig` defaults that field to `0`, so omitted YAML builds no gate: every sidecar failure still follows `failMode`, with no later skip. Owner: `github.com/david-garcia-garcia/traefik-modsecurity@e860d249:pkg/modsecurity/plugin.go` (`newWafGate`), `…@e860d249:pkg/modsecurity/config.go` (`CreateConfig`). Extracts: `.sources/plugin.go.md`, `.sources/config.go.md`. Official README Configuration agrees: default `0` (gate unused). Owner: [README Configuration](https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md). Extract: `.sources/README-configuration.md`.

When backoff seconds are `> 0`, `newWafGate` builds one in-process `backendbackoff.Gate` and ServeHTTP uses the single key `"waf"`. Owner: `…@e860d249:pkg/modsecurity/plugin.go` (`wafGateKey`, `newWafGate`). Extract: `.sources/plugin.go.md`.

## Plugin knobs and what reaches the Gate

| Plugin field | `CreateConfig` / `Prepare` | Passed to `backendbackoff.Config` |
| --- | --- | --- |
| `unhealthyWafBackOffPeriodSecs` | default `0`; `> 0` enables the gate; negatives fail Prepare | `BaseCooldown` = that many seconds |
| `unhealthyWafMaxBackOffPeriodSecs` | default `0`; if `> 0` must be `>=` base | `MaxCooldown`; when `0`, plugin sets `MaxCooldown = BaseCooldown` (fixed cooldown) |
| `unhealthyWafFailureThreshold` | omitted `0` → Prepare fills `5` | `TripFailures` |
| `unhealthyWafFailureRatio` | default `0`; Prepare rejects `< 0` or `>= 1` when set | copied only if `> 0`; else Gate packaged `0.30` |
| `unhealthyWafFailureWindowSecs` | omitted `0` → Prepare fills `10` | **not passed**; unused by the gate |

Owners: `…@e860d249:pkg/modsecurity/config.go` (`Config`, `CreateConfig`, `Prepare`); `…@e860d249:pkg/modsecurity/plugin.go` (`newWafGate`). Official README Configuration states the same omitted-threshold / omitted-window / omitted-ratio / omitted-max mapping. Extract: `.sources/README-configuration.md`.

`Jitter` and `TTL` are never set by the plugin. Owner: `…@e860d249:pkg/modsecurity/plugin.go` (`newWafGate` literal). Extract: `.sources/plugin.go.md`.

## Gate Allow / Report (utilities v1.0.3)

Owner: `github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de:backendbackoff/gate.go` and `…@950b08de:backendbackoff/allow.go`. Extracts: `.sources/gate.go.md`, `.sources/allow.go.md`.

Packaged defaults when a field is zero: `FailureRatio=0.30`, `TripFailures=5`, `BaseCooldown=1s`, `MaxCooldown=10s`, `TTL=60s`. A **fully zero** `Config` also sets `Jitter=0.10`. A **partial** `Config` with `Jitter==0` leaves jitter at `0` (disabled). The plugin always sends a partial `Config` (at least `TripFailures` + cooldowns), so this pin runs **without** cooldown jitter. Owner: `…@950b08de:backendbackoff/gate.go` (`resolveConfig` comment and `allZero` branch).

Per-key states: CLOSED (admit), OPEN (deny until `openUntil`), HALF-OPEN (one probe). `Allow`:

- CLOSED → `true` (and may reset backoff exponent `n` after one `MaxCooldown` of continuous CLOSED).
- OPEN before `openUntil` → `false` plus remaining wait. Other in-flight requests stay skipped.
- OPEN after cooldown → HALF-OPEN, `probeOutstanding=true`, one admit.
- HALF-OPEN with probe still outstanding before `probeUntil` → `false`.
- `ctx.Err()` non-nil → `false, 0, err` (no state change). Closed gate → `errClosed`.

`Report` records only an attempt the gate already admitted. Denied `Allow` is not reported. Success in CLOSED adds credit `p/(1-p)` up to budget `TripFailures`. Failure in CLOSED decrements credit; at `<= 0` the key goes OPEN for `cooldownDuration(n)`. HALF-OPEN success closes the gate (credit = budget); HALF-OPEN failure increments `n` and re-opens. Report while OPEN is a no-op.

## ServeHTTP: skip vs failMode

Owner: `…@e860d249:pkg/modsecurity/serve.go`. Extract: `.sources/serve.go.md`. Official How it works + Configuration: `.sources/README-how-it-works.md`, `.sources/README-configuration.md`.

When the gate is non-nil, ServeHTTP calls `Allow(req.Context(), "waf")` **after** `bypassRules` and `denyVerbsWithBody`, **before** the sidecar hop.

- `!allowed` (OPEN / probe busy): status token `unhealthy`, log `skipping sidecar; waf backoff open`, then `serveFailClosedOrNext`. No `Report`. Skip still follows `failMode` (`open` → `next`; `close` → empty HTTP 502).
- Sidecar transport error or sidecar `>= 500`: `Report("waf", false)`, status token `error`, then the same `serveFailClosedOrNext`.
- Sidecar `2xx` or `3xx`/`4xx` block: `Report("waf", true)` (a copied block is a successful inspect).

`failMode` after Prepare is `open` or `close` (case-insensitive; empty → `open`). Other values fail construction. Official README: applies to sidecar transport errors (**not** inbound cancel), sidecar 5xx, **and** the already-unhealthy skip. Owner: `…@e860d249:pkg/modsecurity/config.go` (`FailModeOpen`/`FailModeClose`, `parseFailMode`); README Configuration.

`denyVerbsWithBody` runs before `Allow`, so a listed method with a body is HTTP 400 even after the gate has tripped. Owner: `…@e860d249:pkg/modsecurity/serve.go` order; README Configuration (`denyVerbsWithBody`).

## Inbound cancel does not trip

Two ServeHTTP paths treat client/Traefik cancel as not a WAF health event:

1. `Allow` returns an error that is `context.Canceled` (or `req.Context()` is canceled): log `inbound request canceled; WAF call aborted`, empty HTTP 502, **return**. No `Report`, no `serveFailClosedOrNext`.
2. `httpClient.Do` fails and `req.Context().Err()` is `context.Canceled`: same log and empty 502, **return**. No `reportWafOutcome`.

Owner: `…@e860d249:pkg/modsecurity/serve.go`. README Configuration: failMode applies to sidecar transport errors **not inbound cancel**. Extract: `.sources/README-configuration.md`.

`Allow` itself returns `ctx.Err()` without mutating credit when the inbound context is already done. Owner: `…@950b08de:backendbackoff/allow.go`.
