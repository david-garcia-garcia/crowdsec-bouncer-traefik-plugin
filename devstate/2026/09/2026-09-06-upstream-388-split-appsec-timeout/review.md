## prepare (2026-09-06)
phase: prepare
findings: single HTTPTimeoutSeconds shared by LAPI and AppSec; no AppsecTimeoutSeconds or ms granularity
fixed: n/a
skipped: n/a

## implement (2026-09-06)
phase: implement
findings: CrowdsecAppsecTimeoutMilliseconds landed; local tests passed; CI queued
fixed: AppSec HTTP timeout split from LAPI
skipped: n/a

## codereview (2026-09-06)
phase: codereview
findings: all five axes none
fixed: n/a
skipped: n/a

## devdocsimpact (2026-09-06)
phase: devdocsimpact
findings: none — AppSec Client and middleware packets already current
fixed: n/a
skipped: n/a
