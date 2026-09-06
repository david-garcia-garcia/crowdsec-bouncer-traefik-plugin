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
