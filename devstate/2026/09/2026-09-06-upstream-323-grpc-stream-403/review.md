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

## codereview (2026-09-06)
phase: codereview
findings: P3 1 (Standards test GET symmetry)
fixed: fa9d177 streaming passthrough GET assert
skipped: none

## devdocsimpact (2026-09-06)
phase: devdocsimpact
findings: stale-usage already produced in implement
fixed: none (packet already current)
skipped: none

## archive (2026-09-06)
phase: archive
findings: none
fixed: live spec synced; change moved to archive/2026-09-06-appsec-unreadable-body-headers-only
skipped: none

## pullrequest (2026-09-06)
phase: pullrequest
findings: e2e mock still expected 403 on unreadable HTTP/2; fixed then CI green
fixed: PR title ready; CI Main Process + both e2e succeeded
skipped: none

## explore (2026-09-06 rethink)
phase: explore
findings: human asked for CrowdsecAppsecUnreadableBodyBlock on this PR; current HEAD still always headers-only GET
fixed: explore.md decisions (default false, independent of failure action, GET exemption); issues.md take small
skipped: none

## propose (2026-09-06 rethink)
phase: propose
findings: fold core_plugin_appsec_failure-action; restore UnreadableBodyBlock default false
fixed: OpenSpec change appsec-unreadable-body-block
skipped: none

## implement (2026-09-06 rethink)
phase: implement
findings: dest merge left cache.NoBannedValue in stream log test
fixed: CrowdsecAppsecUnreadableBodyBlock default false; drop when true; GET exemption; merge typecheck
skipped: none
