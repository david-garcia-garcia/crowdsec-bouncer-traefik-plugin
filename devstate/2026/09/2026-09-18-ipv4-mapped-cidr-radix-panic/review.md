## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: none

## explore (2026-09-18)
phase: explore
findings: panic reproduced on AddCIDR, NewChecker, MembershipFromIndex; Contains treats ::ffff:0:0/96 as IPv4 /0
fixed: none
skipped: none

## propose (2026-09-18)
phase: propose
findings: fold core_plugin_ip_radix-lookup; remap To4 plus 128-bit mask to IPv4 ones-96
fixed: none
skipped: none

## implement (2026-09-18)
phase: implement
findings: remapped To4 plus 128-bit mask to IPv4 ones-96; hunt tests pass; CI succeeded
fixed: insert remap on v4 root; three hunt regressions; radix-lookup spec and usage gotcha
skipped: none

## codereview (2026-09-18)
phase: codereview
findings: six axes none
fixed: none
skipped: none
