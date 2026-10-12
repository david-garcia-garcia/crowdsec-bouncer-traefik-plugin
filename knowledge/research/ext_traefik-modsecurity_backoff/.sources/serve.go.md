---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/serve.go
title: serve.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/serve.go
---

Order: clear status header; `compiledBypass.match` → token `bypassrule`, `next`, return; denyVerbsWithBody body peek → HTTP 400 return (no gate); then if `wafGate != nil`, `Allow(req.Context(), wafGateKey)`.

Allow error: if `context.Canceled` (or inbound ctx canceled) → log `inbound request canceled; WAF call aborted`, empty HTTP 502, return (no Report, no failMode helper). Other Allow errors → token `error`, `serveFailClosedOrNext`. `!allowed` → token `unhealthy`, log `skipping sidecar; waf backoff open`, `serveFailClosedOrNext`.

`httpClient.Do` error: if inbound `context.Canceled` → same cancel log + empty 502, return (no `reportWafOutcome`). Else `reportWafOutcome(false)`, `recordWafFailure`, `serveFailClosedOrNext`.

Sidecar 3xx/4xx: `reportWafOutcome(true)`, token `blocked`, `forwardResponse`. Sidecar >=500: `reportWafOutcome(false)`, `recordWafFailure`, `serveFailClosedOrNext`. Else 2xx: `reportWafOutcome(true)`, token `ok`, `next`.

`serveFailClosedOrNext`: `failMode == FailModeClose` → empty HTTP 502; else `next`.

`reportWafOutcome`: no-op if `wafGate == nil`; else `wafGate.Report(wafGateKey, success)`. Comment: Denied Allow is not reported.
