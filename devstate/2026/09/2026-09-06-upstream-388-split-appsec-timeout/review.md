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

## archive (2026-09-06)
phase: archive
findings: catalog synced; change moved to archive/2026-09-06-split-appsec-timeout
fixed: n/a
skipped: n/a

## pullrequest (2026-09-06)
phase: pullrequest
findings: CI succeeded on d256d34; title ready
fixed: n/a
skipped: n/a

## codereview (2026-09-06T19:06:37Z)
phase: codereview
findings: Standards/Spec/Security/Performance/Dead none; Coverage 2 hard (LAPI client Timeout wiring, captcha siteverify Timeout wiring)
fixed: none
skipped: attended — waiting on which coverage items to apply
