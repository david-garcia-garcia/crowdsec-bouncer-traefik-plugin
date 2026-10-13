# Issues

- [x] take large  `pkg/lapi/client_metrics.go` Client window/ticker → `MetricsReporter`
  Why: this ticket lands the parked reporter split so usage-metrics stop riding the LAPI client identity.
  Taken: MetricsReporter owns the window in client_metrics.go; Client holds one pointer and the existing ticker; deleted knowledge/debt/2026-09-17-metrics-reporter-split.md.
