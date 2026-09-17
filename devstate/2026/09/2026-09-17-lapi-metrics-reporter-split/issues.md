# Issues

- [ ] take large  `pkg/lapi/client_metrics.go` Client window/ticker → `MetricsReporter`
  Why: this ticket lands the parked reporter split so usage-metrics stop riding the LAPI client identity.
