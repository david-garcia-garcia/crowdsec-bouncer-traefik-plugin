# Ban unknown LAPI decision types

CrowdSec's challenge protocol: a LAPI or blocklist decision whose type is challenge carries nothing to render and must fail closed to ban. lua-cs-bouncer falls back to ban for unsupported types.

On master (this fork), decisionscope.RemediationValue maps only ban and captcha; any other type is empty. pkg/lapi/client_decisions.go streamPutItem then skips the decision (ok=false), so stream allows the IP. Live strongestLiveDecision ignores it and queryLiveDecisions returns NoBannedValue, so live allows it too.

Desired: stream, live, and none store and apply a decision whose type is neither ban nor captcha (challenge, allow, anything else) as a ban. Empty decision lists stay no-remediation.

Log the unknown type at TRACE, not Info and not Debug. An unknown type on every stream item will flood Info. Use logger.Trace (slog has no Trace method). Keep the existing message stem handleStreamCache:unknownType.

Do NOT change RemediationValue's default empty return. Origin remap and other callers use empty to mean "not a remediation code". Fail closed only at LAPI ingest (streamPutItem and the live query path).

Out of scope: AppSec challenge relay, metrics, captcha, workflow files, the closed PR 193.

Regression test must fail on master if an unknown type is skipped or allowed. Run tests on this machine.

Upstream (must appear on the delivery card): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 1. Do not copy that patch; it edits the old root bouncer.go which master does not have.
