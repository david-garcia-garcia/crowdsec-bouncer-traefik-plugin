---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/plugin.go
title: plugin.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/plugin.go
---

`wafGateKey` is the constant `"waf"` — the single admission key on the Plugin's Gate.

Plugin holds `wafGate *backendbackoff.Gate` and `failMode string`.

HTTP client `CheckRedirect` returns `http.ErrUseLastResponse` so ServeHTTP can copy sidecar 3xx.

`newWafGate(cfg)`: if `cfg.UnhealthyWafBackOffPeriodSecs <= 0` return `nil, nil`. Else `base = UnhealthyWafBackOffPeriodSecs` seconds; `maxCooldown = base` unless `UnhealthyWafMaxBackOffPeriodSecs > 0` then that many seconds. `backendbackoff.Config{TripFailures: UnhealthyWafFailureThreshold, BaseCooldown: base, MaxCooldown: maxCooldown}`. If `UnhealthyWafFailureRatio > 0`, set `FailureRatio`. `Jitter` and `TTL` are not set. `backendbackoff.New(gateCfg)`; wrap error as `waf admission gate: %w`.

`Close` calls `wafGate.Close()` when non-nil.
