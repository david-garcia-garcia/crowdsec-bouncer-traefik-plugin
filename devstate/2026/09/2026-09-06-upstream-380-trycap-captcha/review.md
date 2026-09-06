## prepare (2026-09-06)
phase: prepare
findings: qualified-with-gaps (TryCap template/config unknowns, #318 overlap tension)
fixed: run root, ticket dump, requirement.md, stub PR #40
skipped: PR comments (none open)

## explore (2026-09-06)
phase: explore
findings: first-class trycap; JSON siteverify; dedicated instance URL; one default template; no custom JSON (#318 noted)
fixed: explore.md decisions, ext_cap_standalone research, core_plugin_captcha usage
skipped: none

## propose (2026-09-06)
phase: propose
findings: new spec core_plugin_captcha_trycap-provider; change trycap-captcha-provider
fixed: proposal, design, tasks, spec delta
skipped: none

## implement (2026-09-06)
phase: implement
findings: trycap provider + JSON siteverify landed; CI green (Main + e2e)
fixed: pkg/captcha, configuration, captcha.html, tests, README, examples/trycap-captcha
skipped: none


