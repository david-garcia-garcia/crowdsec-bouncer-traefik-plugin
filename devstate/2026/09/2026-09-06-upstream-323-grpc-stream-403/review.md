## prepare (2026-09-06)
phase: prepare
findings: qualified-with-gaps (default ban vs ticket passthrough; upstream #332 default unverified)
fixed: dump, requirement, stub PR #51
skipped: none

## explore (2026-09-06)
phase: explore
findings: hang already fixed; default ban still drops unreadable gRPC POST as 403; lua APPSEC_DROP_UNREADABLE_BODY defaults false
fixed: explore.md decisions; research ext_crowdsec_appsec_unreadable-body
skipped: did not flip CrowdsecAppsecFailureAction default; did not re-add UnreadableBodyBlock

## propose (2026-09-06)
phase: propose
findings: fold core_plugin_appsec_failure-action; unreadable body is headers-only GET
fixed: OpenSpec change appsec-unreadable-body-headers-only (proposal, spec, design, tasks)
skipped: none

## implement (2026-09-06)
phase: implement
findings: none
fixed: headers-only GET for isBodyUnreadable; tests and README
skipped: Windows root-package logging TempDir cleanup flake (unrelated)
