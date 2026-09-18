# Code review — Test coverage
Pin: origin/master...HEAD

## Findings

- [resolved] **Failing-first, deliverable 1.** `TestStoreStreamDecision_SpellingsShareOneCacheSlot`
  fails 5 of 6 pairs on DestBranch (only `/128` stored → bare requested passed, because `IPCacheKey`
  already handled host prefixes) and 3 of 6 under PR #34's read-side-only shape.
  `TestLiveLookup_MemoHitsAcrossSpellings` needs 4 LAPI queries for 4 requests on DestBranch.

- [resolved] **Regression guard, deliverable 1.** `TestLiveLookup_MemoHitsOnRepeatedRequests` is the
  measurement the ticket demands. It passes on DestBranch (1 query for every spelling) and fails
  under read-side-only canonicalization with 5 queries for 5 requests on `2001:DB8::1`,
  `2001:0db8:…:0001`, and `::ffff:192.0.2.4`. Note that `MemoHitsAcrossSpellings` alone would *not*
  have caught #34 — mixed spellings read through one canonical key and so hit the memo written by the
  first request. The repeated-same-spelling case is the one that matters.

- [resolved] **Failing-first, deliverable 2.** `TestApplyRangeBatch_UnreachableReadKeepsSharedIndex`
  and `…DoesNotDeleteIndex` fail on DestBranch with the damage visible in the assertion output: the
  stored blob goes from `10.0.0.0/8=t` to `192.168.0.0/16=t` on the upsert path, and is deleted
  outright on the removal path. `TestHandleStreamCache_RangeApplyFailureReleasesLease` fails too.

- [noted] `TestDeleteStreamDecision_ClearsTheSlotAnySpelling` passes on DestBranch, vacuously: the
  ban it stores was never findable there in the first place. It is a guard against a future
  asymmetric delete, not evidence of the defect. Kept and labelled as such.

- [resolved] **Invariant under test.** `TestIPLookupCacheKeyAgreesWithStore` asserts the two entry
  points agree for every spelling in play, so "one rule, two entry points" is machine-checked rather
  than a comment.

- [resolved] **Test harness gap closed.** `testLeaseRedis` answered `DEL` from its `default: +OK`
  branch without removing the key, so any assertion about a released lease on Redis was previously
  unfalsifiable. It now implements `DEL`.
