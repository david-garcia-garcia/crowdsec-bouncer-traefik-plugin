## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: no Task subagent used; prepare wrote the bus in-process

## explore (2026-09-18)
phase: explore
findings: dest README and captcha examples still name HTML-cased old keys; Traefik v3.7.11 drops unused keys after field delete
fixed: none
skipped: no Task subagent available; research written in-process

## propose (2026-09-18)
phase: propose
findings: FindSpecHost fold build_e2e_pester_crowdsec-stack; no Config-surface alias SHALL
fixed: none
skipped: no Task subagent used; propose written in-process

## implement (2026-09-18)
phase: implement
findings: leftover custom-ban `banhtmlfilepath` label broke e2e (docker + pester) after field delete
fixed: retargeted that label to `banFilePath`; fields and New copies deleted; live leftovers retargeted
skipped: no Task subagent used; apply written in-process

## codereview (2026-09-18)
phase: codereview
findings: none
fixed: none
skipped: Task tool unavailable in nested session; six axes written in-process; all clean

## devdocsimpact (2026-09-18)
phase: devdocsimpact
findings: stale-usage 3
fixed: Middleware New, Real-stack e2e, Mock LAPI e2e usage
skipped: no Language write (no invented umbrella term)

## archive (2026-09-18)
phase: archive
findings: none
fixed: folded custom-ban WHEN into build_e2e_pester_crowdsec-stack; moved change to openspec/changes/archive/2026-09-18-remove-html-filepath-deprecations
skipped: FindSpecHost Task (tool unavailable in worker; ran on this thread)
