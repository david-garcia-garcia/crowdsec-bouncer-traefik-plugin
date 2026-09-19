# Code review
change: align-lapi-usage-metrics
pin: origin/master...HEAD
axes: Standards, Spec, Security, Performance, Dead
unattended: applied hard findings on this thread (no five sub-agents)

## Standards
- Applied: keep labeled usage-metrics in `connection_metrics.go` (master file-split SHALL), not a second `metrics.go`.
- Recorded: Lookup snippet in `core_plugin_decisionscope.md` now returns kind+origin.

## Spec
- Asked: official labels, processed, active_decisions, origin suffix, GetRemoteIP family — implemented.
- Extra: none material vs DestBranch besides master merge of connection file split and ip checker/network.
- Wrong: none remaining after folding reportMetrics into `connection_metrics.go`.

## Security
none.

Origin labels come from LAPI/AppSec, not client-set headers. Cache suffix is not a matching key.

## Performance
none hard.

Window maps key by origin × ip_type × remediation (CrowdSec origin cardinality). `activeDecisionSlots` is one entry per stored decision record, not per host in a CIDR.

## Dead
none.

`IncBlocked` / `blockedRequests` removed; no remaining callers. `metrics.go` deleted after fold into `connection_metrics.go`.

## Applied
- Merge `origin/master` with labeled metrics kept.
- Fold `metrics.go` into `connection_metrics.go` to match `core_plugin_connection_source-files`.

## Recorded-and-skipped
- Root `TestBouncerFileLogging*` Windows TempDir lock flake (assertions pass; Linux CI expected green).
