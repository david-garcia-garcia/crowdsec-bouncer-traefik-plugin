# Deviations

- [x] taken  skip only the request dropped counter dest already posts
  Asked: a relay under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes).
  Instead: skip `blockedRequests` only; do not add a bytes series.
  Owner: `bouncer.go` `reportMetrics`
  Why: dest's metrics POST has a single `dropped` request item and no bytes series; adding bytes would change the POST shape, which the ask forbids.
  By: explore
  Requester: not asked
