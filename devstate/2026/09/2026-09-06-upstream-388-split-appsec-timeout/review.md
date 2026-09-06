## prepare (2026-09-06)
phase: prepare
findings: single HTTPTimeoutSeconds shared by LAPI and AppSec; no AppsecTimeoutSeconds or ms granularity
fixed: n/a
skipped: n/a

## explore (2026-09-06)
phase: explore
findings: one CrowdsecAppsecTimeoutMilliseconds knob; 0 inherits HTTPTimeoutSeconds; identity hashes effective duration
fixed: n/a
skipped: captcha timeout split; LAPI millisecond config; e2e hanging AppSec; default 200ms
