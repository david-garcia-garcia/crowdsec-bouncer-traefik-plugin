# Explore
IssueKey: 2026-09-06-directed-refactor

## Concepts

**Range membership**: in-process ban/captcha CIDR sets on the reclaimed LAPI Client. Stream/alone hydrate from `range-index`. Live/none never call `hydrateRangeMembership`; `RangeMembership()` is nil until that hydrate.

**Cache miss vs live lookup**: after the cache block, stream/alone treat a miss as allow-if-healthy; live/none call `LiveLookup`. That split is Crowdsec mode, not “whether membership exists.”

## Decisions

- Remove `useRangeMembership` from `LookupCachedRemediation` and from `ServeHTTP`. Always call `membership.Remediation`. Nil or empty membership is a Range miss (`rangemembership.go` returns `""`). Live/none never hydrate, so they do not pick up a sibling’s `range-index` blob on the request path.
- After the cache block, branch on `StreamMode` / `AloneMode` vs live/none. Do not name that split after Range membership.
- Fold live spec `core_plugin_decisions_scopes` “False skips Range membership” into empty/nil membership is a miss. Keep “MUST NOT import `pkg/configuration`.”

## Open questions

- Q: Does always consulting membership change live/none when Redis already has `range-index`?
  Decision: resolved — no. `OpenLive` never hydrates; `RangeMembership()` is nil; `Remediation` on nil is empty. Request path still does not read the blob (`LookupCacheKeys` omits `RangeIndexKey`).
  By: explore

- Q: Keep a Crowdsec-mode flag on `LookupCachedRemediation`?
  Decision: resolved — no. The flag duplicated “is the tree populated?” and made ServeHTTP name a cache-miss policy after Range.
  By: explore
