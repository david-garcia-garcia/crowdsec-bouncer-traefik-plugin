## prepare (2026-09-17)
phase: prepare
findings: qualified; five query.go defects grounded on dest a57c848; #64 transport already in place; no new knobs
fixed: stub PR #70; requirement.md; dest master
skipped: Task research subagent (in-tree AppSec protocol packet already answers the outside system)

## explore (2026-09-17)
phase: explore
findings: five dest defects reproduced in query.go; go test ./pkg/appsec/ passed (untested so green); 0 means skip LimitReader; read errors keep appsecQuery:readBody; set ContentLength field and header; DELETE only out of isMethodWithBody
fixed: explore.md with Decision on every Q; research packets for LimitReader, keep-alive drain, ContentLength; PR #70 summary
skipped: hop-by-hop filter; oversized-body FA; #51; product apply

## propose (2026-09-17)
phase: propose
findings: fold core_plugin_appsec_client (drain, zero limit, Content-Length) and core_plugin_appsec_failure-action (read-body FA; DELETE out of unreadable set); OpenSpec valid 4/4
fixed: change appsec-query-hardening; specs.md; PR #70 summary
skipped: no Open question Decision changed; no new spec leaf; no product apply

## implement (2026-09-17)
phase: implement
findings: five Query defects applied; localTests passed; Main Process lint failed dest nestif configuration.go:336; e2e both success
fixed: drain 502/503/504; limit 0 unlimited; read-body FA; rebuild Content-Length; DELETE out of isMethodWithBody; PR #70 summary
skipped: dest nestif (note large); hop-by-hop filter; oversized FA; #51; no Open question Decision changed

## codereview (2026-09-17)
phase: codereview
findings: Standards 1 done (sentinel errAppsecReadBody); Performance 1 skipped (limit 0 unlimited); Spec/Security/Dead/Coverage none
fixed: Query matches errAppsecReadBody with errors.Is
skipped: Performance bound (specified unlimited); dest nestif

## devdocsimpact (2026-09-17)
phase: devdocsimpact
findings: stale-usage AppSec Client produced; FailureAction none; no Language term for the internal sentinel
fixed: usage packet Key files + Gotchas for errors.Is classification; PR #70 summary
skipped: Language for errAppsecReadBody (internal sentinel)

## archive (2026-09-17)
phase: archive
findings: FindSpecHost fold core_plugin_appsec_client and core_plugin_appsec_failure-action; catalog validate 0; change moved
fixed: baseline AppSec spec leaves synced; archive folder 2026-09-17-appsec-query-hardening; PR #70 summary
skipped: Task FindSpecHost subagent (no Task tool); validate-output commit (map.md hash unchanged); pullrequest

## pullrequest (2026-09-17)
phase: pullrequest
findings: reused PR #70; ready title 🐛; comments none; Main Process failed dest nestif CaptchaProvider; both e2e success
fixed: title drop 🚧; card cites #35 and #43; PR #70 summary
skipped: dest nestif (note large); second PR

## amendment fold-35 (2026-09-18)
phase: implement + codereview + devdocsimpact + archive (in-place on the open PR, owner direction)
findings: owner closes #35 as superseded, so its two held-back items land here; #70's CI base a57c848 is stale, merged origin/master 0e7dbf0 clean (no conflict in pkg/appsec/query.go); both new tests reproduced red against the pre-fix query.go
fixed: isHopByHopHeader (RFC 7230 6.1, errata 4522) replaces the literal Transfer-Encoding skip; isMethodWithForwardableBody (POST/PUT/PATCH/DELETE) gates the readable copy and skips http.NoBody; Content-Length stays POST-only; spec leaf + archived delta + design/tasks/proposal + usage packet + README updated
skipped: dynamic Connection-token stripping (lets a client hide Cookie from the WAF); any change to isMethodWithBody, the unreadable-body drop policy, or #51's crowdsecAppsecUnreadableBodyBlock
gates: build, vet, go test ./pkg/... -count=1, go test . -count=1, golangci-lint run ./..., docker golang:1.22.12 go test -race -count=1 ./pkg/... — all green on the merged tree
