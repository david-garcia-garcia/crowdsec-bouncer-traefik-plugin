# Devdocs impact
IssueKey: 2026-09-18-ip-cache-key-canonicalization

## Units

- `pkg/decisionscope` — Ip cache key derivation, range-index apply contract
- `pkg/lapi` — stream store/delete slot, live-mode memo slot, stream poll failure on a failed apply

## Findings

- updated `knowledge/devdocs/core_plugin_decisionscope.md`
  - Language gap: the packet had no term for the Ip cache key at all, so nothing said the store side
    and the request side are one contract. Added **Ip cache key** with its Avoid list.
  - Stale usage: "How to use" told the reader to pass `req.ipAddr` for Range membership only, and
    described `ApplyRangeBatch` as a call that cannot fail. Both corrected.
  - Missing gotchas: that CrowdSec does not canonicalize decision values (measured), and that cache
    reads use a round-robin replica while `Acquire`/`Set` use the writer. The second is what makes
    the range-index defect reachable and is not obvious from either package.

## Open findings

None.
