# Review

## prepare (2026-09-06)

phase: prepare
findings: none
fixed: none
skipped: none

## explore (2026-09-06)

phase: explore
findings: none
fixed: none
skipped: none
- assumed: GetRemoteIP returns (string, net.IP, error)
- assumed: nil parsed after GetRemoteIP → trustipfail
- assumed: Remediation takes net.IP
- assumed: ipType string threaded to recordDropped

