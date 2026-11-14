## Why

A LAPI or blocklist decision whose type is neither ban nor captcha (including challenge, which has nothing to render) is skipped at ingest, so stream, live, and none allow the IP. CrowdSec challenge protocol and lua-cs-bouncer fail closed to ban for unsupported types. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 1 is the same job; this fork cannot copy that patch because master has no root bouncer.go.

## What Changes

- Stream Ip/header, stream Range, live, and none store and apply an unknown LAPI decision type (challenge, allow, anything else) as a ban.
- Empty decision lists stay no-remediation.
- Unknown types log at TRACE with stem handleStreamCache:unknownType via logger.Trace.
- RemediationValue keeps its empty default. Origin remap still uses empty as not a remediation code.
- Fail closed only at LAPI ingest. AppSec challenge relay, metrics, captcha, and workflow files stay out.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- core_plugin_lapi_origin-based-decision-remap: stream Put, Range upsert, and live/none query store an unknown LAPI type as ban instead of skipping; live strongest pick treats unknown as ban.
- core_plugin_decisions_scopes: unknown LAPI types are no longer ignored at ingest; they fail closed to ban. RemediationValue still maps only ban and captcha.

## Impact

- pkg/lapi/client_decisions.go (streamPutItem, queryLiveDecisions, strongestLiveDecision)
- pkg/lapi/client_stream.go (Range kind mapping)
- pkg/lapi tests that must fail on master if an unknown type is skipped or allowed
- pkg/decisionscope.RemediationValue is not changed
- Usage packets knowledge/devdocs/core_plugin_lapi_stream-apply.md and knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md
