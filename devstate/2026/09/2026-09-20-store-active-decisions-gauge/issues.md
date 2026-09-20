# Issues

- [ ] note large  `knowledge/debt/2026-09-20-range-active-decisions-forget.md`
  Why: Range is a blob + LPM trees, not a slot Peek; omit Range from the store-owned gauge until ApplyRangeBatch displacements.
- [ ] note medium  `knowledge/debt/2026-09-20-active-decisions-ttl-forget.md`
  Why: Peek-then-adjust lives on Store PutMany/DeleteMany only; memory PublishTick expiry and Redis TTL do not decrement.
