# Deviations

- [x] taken  client disconnect is stop+TRACE+optional header, not FailureAction
  Asked: do not treat client-side body cancel as an AppSec ban; distinguish cancel from genuine faults; reporter offered pass-through or a fail-open option.
  Instead: detect client-gone, TRACE-only log, optional `remediationHeadersCustomName` `error:client-disconnected`, do not call AppSec, origin, or `handleBanServeHTTP`. `crowdsecAppsecFailureAction` does not apply.
  Owner: `pkg/bouncer/bouncer.go` `handleClientDisconnectedServeHTTP`
  Why: a cancelled stream has no client to protect or to serve 403 to; FailureAction would still 403 (default ban) or call origin (passthrough). Access-log header is the metric.
  By: implement
  Requester: confirmed
