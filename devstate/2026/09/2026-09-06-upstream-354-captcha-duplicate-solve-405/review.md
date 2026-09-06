## prepare (2026-09-06)
phase: prepare
findings: grounded upstream#354 duplicate captcha POST → origin 405
fixed: n/a
skipped: product fix deferred to explore/implement

## explore (2026-09-06)
phase: explore
findings: reproduced grace Check true + captcha POST relays POST to next (no Location); proposed intercept+302 matching first solve, Body restore when not intercepting
fixed: n/a
skipped: product apply deferred to propose/implement

## propose (2026-09-06)
phase: propose
findings: new spec core_plugin_captcha_solved-form-post; change redirect-solved-captcha-form-post apply-ready
fixed: n/a
skipped: runtime apply deferred to implement
