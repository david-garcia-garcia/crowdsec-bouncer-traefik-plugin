# Review

## prepare (2026-09-05)
phase: prepare
findings: none
fixed: none
skipped: issue status comment on maxlerebourg#389 (different owner; dump only). Product apply not started.

## explore (2026-09-05)
phase: explore
findings: none
fixed: none
skipped: live CrowdSec 1.8 reproduce (no lab). Research packet still in flight.

## propose (2026-09-05)
phase: propose
findings: none
fixed: none
skipped: none. Change appsec-bot-detection validated.

## implement (2026-09-05)
phase: implement
findings: none
fixed: AppsecQuery parse + Bouncer challenge relay; golangci split of AppsecQuery; mock /challenge; real e2e CrowdSec v1.8.0
skipped: issue status comment on maxlerebourg#389 (different owner)

## codereview (2026-09-05)
phase: codereview
findings: P3 5 (3 standards, 4 spec; security none; performance none)
fixed: test helper, captcha relay, empty 200 test, spec allow-return and port 7423
skipped: judgement rename of `decision`; judgement extra log fields

## destocsimpact (2026-09-05)
phase: destocsimpact
findings: stale-usage 1
fixed: core_plugin_appsec.md How-to (non-allow non-ban relays)
skipped: none

## archive (2026-09-05)
phase: archive
findings: none
fixed: catalog core_plugin_appsec_bot-detection; fold build_e2e_pester_crowdsec-stack; moved openspec/changes/archive/2026-09-05-appsec-bot-detection
skipped: none

## pullrequest (2026-09-05)
phase: pullrequest
findings: none
fixed: WIP title dropped; CI green on b92c882 (Main + mock + Pester)
skipped: none
