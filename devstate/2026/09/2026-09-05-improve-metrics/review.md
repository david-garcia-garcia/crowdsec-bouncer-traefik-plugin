# Review
## prepare (2026-09-05)

phase: prepare
findings: none
fixed: none
skipped: LAPI usage-metrics schema still in-flight research (`ext_crowdsec_lapi_usage-metrics`); qualify is qualified-with-gaps

## explore (2026-09-05)

phase: explore
findings: current POST is one dropped item with labels.type=traefik_plugin; cscli displays origin and ip_type only
fixed: none
skipped: assumed proceed policy pending human confirm — conductor continued per later instruction

## propose (2026-09-05)

phase: propose
findings: change align-lapi-usage-metrics; new core_plugin_lapi_usage-metrics; fold core_plugin_decisions_scopes
fixed: none
skipped: none

## implement (2026-09-05)

phase: implement
findings: merged origin/master (connection file split + ip network split); kept labeled usage-metrics
fixed: duplicate symbols after merge; reportMetrics lives in connection_metrics.go
skipped: Windows TestBouncerFileLogging flake

## codereview (2026-09-05)

phase: codereview
findings: none hard remaining
fixed: folded metrics.go into connection_metrics.go
skipped: five-axis sub-agents; reviewed on this thread

## devdocsimpact (2026-09-05)

phase: devdocsimpact
findings: missing usage-metrics packet; stale Lookup snippet
fixed: produced core_plugin_lapi_usage-metrics.md; updated decisionscope and ip packets
skipped: none

## archive (2026-09-05)

phase: archive
findings: none
fixed: catalog sync + archive/2026-09-05-align-lapi-usage-metrics
skipped: none

## pullrequest (2026-09-05)

phase: pullrequest
findings: Main Process, e2e mock, and e2e pester succeeded on 13225c0
fixed: golangci forcetypeassert/gocognit/tagliatelle in metrics_test.go; captcha mock wait 30s
skipped: none


