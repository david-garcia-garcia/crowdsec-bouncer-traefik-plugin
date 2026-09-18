## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: official CrowdSec deleted-first apply order not cloned; hunt tests named by the ticket are not on dest

## explore (2026-09-18)
phase: explore
findings: dest New-then-Deleted plus ApplyRangeBatch upsert-then-remove drops same-window IP and Range replacements; hunt tests not on dest
fixed: usage packet core_plugin_lapi_stream-apply.md; four assumed open questions
skipped: product apply; official bouncer clone still in flight

## propose (2026-09-18)
phase: propose
findings: FindSpecHost new core_plugin_lapi_stream-apply; official deleted-first resolved from research
fixed: OpenSpec change stream-apply-deleted-before-new (proposal, spec, design, tasks)
skipped: product apply

## implement (2026-09-18)
phase: implement
findings: dest New-then-Deleted dropped same-window replacements
fixed: fetchAndApplyStreamDecisions deleted first; ApplyRangeBatch removals then upserts; two hunt tests; go test -cover ./... passed
skipped: remote CI still queued

## codereview (2026-09-18)
phase: codereview
findings: none
fixed: none
skipped: none; all six axes clean

## devdocsimpact (2026-09-18)
phase: devdocsimpact
findings: none
fixed: none
skipped: usage packet already matched the apply

## archive (2026-09-18)
phase: archive
findings: none
fixed: synced core_plugin_lapi_stream-apply into catalog; moved change to archive/2026-09-18-stream-apply-deleted-before-new
skipped: none
