## prepare (2026-09-18)
phase: prepare
findings: none
fixed: none
skipped: none

## explore (2026-09-18)
phase: explore
findings: none
fixed: none
skipped: none
decisions: canonicalize on clientRequest after parse; delete IPLookupCacheKey; e2e none+stream in decision_scopes; memo-hit stays unit; cscli inject via Add-TestDecision

## propose (2026-09-18)
phase: propose
findings: none
fixed: none
skipped: none
change: canonicalize-client-remoteip
fold: core_plugin_decisions_scopes

## implement (2026-09-18)
phase: implement
findings: none
fixed: canonicalize remoteIP after parse; deleted IPLookupCacheKey; live memo Set(remoteIP); real e2e Ip spelling
skipped: local e2e_pester (no crowdsec-test)
localTests: passed

## codereview (2026-09-18)
phase: codereview
findings: coverage 1 hard
fixed: TestServeHTTP_NonCanonicalHeaderHitsCanonicalIpBan (92275b5)
skipped: none

## devdocsimpact (2026-09-18)
phase: devdocsimpact
findings: none
fixed: none
skipped: none

## archive (2026-09-18)
phase: archive
findings: none
fixed: fold core_plugin_decisions_scopes; moved to archive/2026-09-18-canonicalize-client-remoteip
skipped: none
