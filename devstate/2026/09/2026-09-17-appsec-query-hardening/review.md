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
