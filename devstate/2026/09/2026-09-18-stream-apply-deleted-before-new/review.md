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
