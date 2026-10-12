---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/config.go
title: config.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/config.go
---

`FailModeOpen = "open"`, `FailModeClose = "close"`.

Config JSON fields used by the gate: `unhealthyWafBackOffPeriodSecs`, `unhealthyWafFailureThreshold`, `unhealthyWafFailureWindowSecs`, `unhealthyWafFailureRatio`, `unhealthyWafMaxBackOffPeriodSecs`, `failMode`.

CreateConfig defaults: BackOffPeriodSecs `0`, FailureThreshold `5`, FailureWindowSecs `10`, FailureRatio `0`, MaxBackOffPeriodSecs `0`, FailMode `open`.

Prepare: omitted FailureThreshold `0` → 5; omitted FailureWindowSecs `0` → 10. Rejects negative backoff/threshold/window/max and FailureRatio `< 0` or (when set) `>= 1`. If MaxBackOffPeriodSecs `> 0` it must be `>=` BackOffPeriodSecs. Empty failMode → `open`; `parseFailMode` accepts only `open`/`close`.
