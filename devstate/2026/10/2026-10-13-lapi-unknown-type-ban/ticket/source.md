# Ban unknown LAPI decision types

CrowdSec's challenge protocol says a LAPI or blocklist decision whose type is `challenge` carries nothing to render and must fail closed to ban. lua-cs-bouncer falls back to ban for any decision type it does not support.

This fork's `decisionscope.RemediationValue` maps only `ban` and `captcha`. Any other type, including `challenge`, is empty. Stream `streamPutItem` then skips the decision (`ok=false`), so the IP is allowed. Live `strongestLiveDecision` ignores it and `queryLiveDecisions` returns no remediation, so the IP is allowed. A throwaway test on this tree failed both: stream `ok=false kind=""`, live challenge not picked.

Desired: a stream or live LAPI decision whose type is neither `ban` nor `captcha` (for example `challenge`) is stored and applied as a ban, in stream and live (and none, if it shares the live query path). Log the unknown type at the existing log site (today Debug `handleStreamCache:unknownType`).

Constraint: do NOT change `RemediationValue`'s default return of empty string if that empty result is also how origin-remap and other callers mean "not a remediation code". Put fail-closed at the LAPI decision ingest that stores stream/live decisions. `allow` as a decision type is not a supported remediation; treat it like any other unknown type (ban) only on that ingest path. Do not ban an empty decision list.

Out of scope: AppSec `action: challenge` relay (already implemented). Metrics. Captcha provider.

A regression test must fail on dest if an unknown type is skipped or allowed. Run the tests on this machine. Report pass/fail.

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 1).
