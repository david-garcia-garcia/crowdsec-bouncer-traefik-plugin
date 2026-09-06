## explore (2026-09-06)
phase: explore
findings: IP-only grace reproduced; bind to IP+cookie; skip UA/proto in v1
fixed: n/a
skipped: UA+protocol session bind (issues.md)

## propose (2026-09-06)
phase: propose
findings: new spec core_plugin_captcha_session-cookie
fixed: n/a
skipped: UA+protocol session bind

## implement (2026-09-06)
phase: implement
findings: captcha grace bound to IP+cookie; CI green
fixed: govet shadow, revive unused-parameter
skipped: UA+protocol session bind
