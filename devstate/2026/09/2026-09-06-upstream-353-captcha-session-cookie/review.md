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

## codereview (2026-09-06)
phase: codereview
findings: Standards 3 (2 hard Leave a trail, 1 judgement name); Spec/Security/Performance/Dead none
fixed: block intros on Check and sessionTokenFromRequest
skipped: test local session rename (judgement)

## devdocsimpact (2026-09-06)
phase: devdocsimpact
findings: missing captcha packet; stale cache logical keys
fixed: core_plugin_captcha.md; core_cache_client.md How-to/Gotchas
skipped: n/a
