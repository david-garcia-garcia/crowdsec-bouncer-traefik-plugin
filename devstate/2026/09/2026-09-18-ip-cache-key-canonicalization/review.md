## implement (2026-09-18)
phase: implement
findings: two defects, both reproduced failing-first before the fix
fixed: Ip cache key canonicalized on the store side, the delete side, the live memo, and the request
  path in one commit; `readRangeIndex`/`ApplyRangeBatch` separate a miss from a failed read and the
  stream poll reports a failed apply
skipped: deleting the test-only `AddRange`/`RemoveRange` wrappers (noted as debt); rewriting the LAPI
  `?ip=` query to the canonical spelling (LAPI matches numerically, so it would change the wire for
  nothing); any cache migration (Ip entries expire by TTL)

## codereview (2026-09-18)
phase: codereview
findings: Standards 0, Spec 2 (both resolved in the apply), Security 1 accepted + 3 resolved,
  Performance 1 accepted + 2 resolved, Dead 1 noted + 2 resolved, Coverage 1 noted + 5 resolved
fixed: the live spec leaf's "lookup keys MUST NOT change" sentence amended instead of silently
  contradicted; `testLeaseRedis` taught `DEL` so the lease assertion is falsifiable
skipped: nothing; the one accepted finding (a failed range apply can mark the stream unhealthy and
  so reach `crowdsecLapiFailureAction`) is on the card as a decision for the owner

## devdocsimpact (2026-09-18)
phase: devdocsimpact
findings: one Language gap (no term existed for the Ip cache key), one stale usage line
  (`ApplyRangeBatch` described as infallible), two missing gotchas
fixed: `knowledge/devdocs/core_plugin_decisionscope.md` updated for all four
skipped: none
