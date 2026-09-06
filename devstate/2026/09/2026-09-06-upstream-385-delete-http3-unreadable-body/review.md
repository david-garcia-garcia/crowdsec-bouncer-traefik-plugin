## prepare (2026-09-06)
phase: prepare
findings: upstream #385 DELETE HTTP/3 false positive confirmed in pkg/appsec/query.go
fixed: n/a
skipped: product change deferred to explore/implement

## explore (2026-09-06)
phase: explore
findings: DELETE HTTP/3 under ban drops with appsecQuery:unreadableBody dropped
fixed: n/a
skipped: product change deferred to propose/implement

## propose (2026-09-06)
phase: propose
findings: fold core_plugin_appsec_failure-action; change appsec-delete-unreadable-body
fixed: n/a
skipped: product apply deferred to implement

## implement (2026-09-06)
phase: implement
findings: none
fixed: DELETE removed from isMethodWithBody; DELETE HTTP/3 test added
skipped: none

## codereview (2026-09-06)
phase: codereview
findings: none
fixed: n/a
skipped: none

## devdocsimpact (2026-09-06)
phase: devdocsimpact
findings: none
fixed: n/a
skipped: none
