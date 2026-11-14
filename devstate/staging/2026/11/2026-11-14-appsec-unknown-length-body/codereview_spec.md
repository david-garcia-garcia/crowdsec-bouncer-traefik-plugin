# Spec

1. [judgement] Body-timeout escape list over-claims — `openspec/changes/appsec-inspect-unknown-length-body/specs/core_plugin_appsec_body-read-timeout/spec.md:67` — "Only `bypass` or `bypassAppsec` SHALL avoid it" is not true of the code: a client in `bouncerClientTrustedIPs` also never reaches the AppSec body read (`pkg/bouncer/bouncer.go:200-205` calls `next` before LAPI and AppSec), so it avoids the body-timeout ban without either action rule. Existing behaviour, unchanged by this diff; the new SHALL is just worded wider than the code.
   Fix: Reword the sentence to "Within the AppSec check, only a matching `bypass` or `bypassAppsec` action rule SHALL avoid it; trusted clients (`bouncerClientTrustedIPs`) skip AppSec entirely", or scope it to `applyAppsecServeHTTP`
   Status: skipped
   Argument: judgement; trusted clients skip every bouncer check before AppSec (unchanged behaviour); spec wording refinement left for the requester, not applied unattended.
