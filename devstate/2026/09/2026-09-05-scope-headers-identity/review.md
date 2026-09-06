# Reviews

## prepare (2026-09-05)
phase: prepare
findings: none
fixed: none
skipped: none

## explore (2026-09-05)
phase: explore
findings: none
fixed: none
skipped: none
assumed: hash normalized full map; empty==omitted; getter DecisionScopeHeaders(); do not mint a second LAPI key

## propose (2026-09-05)
phase: propose
findings: none
fixed: none
skipped: none
change: put-decision-scope-headers-on-identity

## implement (2026-09-05)
phase: implement
findings: none
fixed: identity map + getter + drop Bouncer copy; tests; usage packets
skipped: none
localTests: passed

## codereview (2026-09-05)
phase: codereview
findings: none
fixed: none
skipped: none
pin: origin/master...HEAD

## devdocsimpact (2026-09-05)
phase: devdocsimpact
findings: stale-usage already produced in implement
fixed: none
skipped: none

## archive (2026-09-05)
phase: archive
findings: none
fixed: catalog synced; change moved to archive/2026-09-05-put-decision-scope-headers-on-identity
skipped: none

## pullrequest (2026-09-05)
phase: pullrequest
findings: none
fixed: title 🐛 fix(crowdsecconnection): put decisionScopeHeaders on reclaim identity
skipped: none
ci: success 33978659998 / 33978659993

## merge (2026-09-05)
phase: merge
findings: none
fixed: merge origin/master; keep identity map + DecisionScopeHeaders() on connection.go
skipped: none
ci: success 33991231123 / 33991231104

## merge (2026-09-06)
phase: merge
findings: none
fixed: merge origin/master; DecisionScopeHeaders on lapi identity; getter on Client; no Bouncer copy
skipped: none
ci: success 34040563219 / 34040563286

