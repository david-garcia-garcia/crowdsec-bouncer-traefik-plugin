# Code review
Pin: origin/master...HEAD (exclude devstate/, .cursor/)
Change: honor-range-and-header-decisions

## Standards
1. [hard] Leave a trail — `pkg/crowdsecconnection/connection_decisions.go:23` — new file adds methods with no job comment
   → Add one-line comments stating each unit's job
2. [hard] Leave a trail — `pkg/decisionscope/range.go:58` — unexported helpers had no comments
   → Add succinct func comments
3. [hard] Leave a trail — `pkg/bouncer/bouncer.go:151` — `// TODO This should be simplified`
   → Replaced with a comment naming the header-scope read
4. [hard] Leave a trail — `pkg/bouncer/bouncer.go:171` — cache-hit log labeled `isBanned` while value may be captcha
   → Log `remediation:`
5. [hard] Name for the scope — `pickDecision` was a vague verb
   → Renamed to `strongestLiveDecision`
6. [judgement] Smallest durable delta — `pkg/configuration/configuration.go:46` — Config struct field realign
   → Add only the new field
7. [judgement] Duplicated Code — `decisionScopeHeaders` held on bouncer and connection
   → Keep one owner
8. [judgement] Duplicated Code — ban-over-captcha in `strongestLiveDecision` vs `PreferRemediation`
   → Map types then call PreferRemediation once

## Spec
1. [wrong] Ban wins across scopes — `LookupCachedRemediation` returned Ip/Range captcha before header-scope ban
2. [missing] Range ban contains the test IP — stream e2e did not assert an IP outside the Range stays allowed

## Security
none

## Performance
1. [hard] Hot-path full scan — `MatchRangeFromIndex` walks every `range-index` line per request
   → Index at load (radix tree) or bound the walk
2. [hard] Unbounded payload — `range-index` blob fetched in GetMany with no byte cap
   → Cap index size or shard ranges
3. [hard] I/O in a loop — each Range stream item GET+SET the full index
   → Batch Range updates per stream tick
4. [judgement] I/O in a loop — one LAPI HTTP call per present header scope on none/live
   → Batch if LAPI supports it, or document a config cap

Standards: 8 findings, worst: Leave a trail on connection_decisions.go
Spec: 2 findings, worst: Ban wins across scopes
Security: 0 findings, worst: none
Performance: 4 findings, worst: per-request linear scan of unbounded range-index

## Applied
- Standards 1: job comments on connection_decisions.go
- Standards 2: comments on range.go helpers
- Standards 3: TODO replaced
- Standards 4: cache-hit log uses remediation
- Standards 5: pickDecision → strongestLiveDecision
- Spec 1: LookupCachedRemediation merges Ip + Range + headers with PreferRemediation; TestLookupCachedRemediationBanWinsAcrossScopes
- Spec 2: stream Range e2e asserts StreamOutside stays 200 while the ban is active
- Performance 3: handleStreamCache batches Range upserts/removals into ApplyRangeBatch (one read, one write)

## Recorded and skipped
- Standards 6: Config field alignment is judgement; not needed to land the SHALL
- Standards 7: two maps (HTTP vs LAPI) match explore; cause-fix would be a larger contract change
- Standards 8: LAPI items are Decision structs, not cache remediations; mapping then PreferRemediation is a later tidy
- Performance 1: explore/design chose one `range-index` blob and no radix tree on this PR; radix tree is a cause fix outside the chosen shape
- Performance 2: same design; a byte cap would be new product behavior not in the spec
- Performance 4: header-scope count is operator config, not a live growing table; judgement
