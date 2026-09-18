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
