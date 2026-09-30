# Delivery

## Motivation

Stream and live already receive LAPI `decision.Scenario` on each ban or captcha. `MetricsOrigin` keeps that string only for lists, folding it into origin as `lists:<name>`. For `crowdsec`, `CAPI`, and `cscli`, the raw scenario is discarded before Put. Store `Decision` has no scenario field. The in-memory slot is an 8-byte `LiveSlot` whose packed word holds ASCII kind, origin intern id, and family — one origin intern table, no place for the raw name.

When a stream or live ban arrives with origin `crowdsec` and scenario `ssh-bf`, the store records origin `crowdsec` and the scenario string is gone after pack. Lists keep `lists:firehol_level1` as the origin label but still do not intern `firehol_level1` on its own. Lookup, dropped items, and `active_decisions` still work on kind plus origin; they do not need scenario today. Per-scenario usage metrics later will need that raw name on the live slot, without sending a `scenario` label yet.

Leaving the drop in place does not break current remediations or the origin×family gauge. It leaves nowhere on the existing 8-byte word to recover a scenario id, so a later metrics series would have to reshape the slot or re-learn names pack already threw away.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm

## Implementation

Stream and live copy LAPI `Scenario` onto `decisionstore.Decision` (`streamPutItem`, `liveResult` / `memoLive`). DecisionStore owns a second intern table for that raw name; origins stay folded `MetricsOrigin`, so lists intern twice (`lists:firehol_level1` and `firehol_level1`). Memory re-lays the existing `uint32` to 2-bit kind (0 empty / 1 `t` / 2 `c` / 3 `f`), 12-bit origin, 2-bit family, and 16-bit scenario id; unpack still returns ASCII `t`/`c`/`f`. Origin ids above 4095 pack as 0 with Warn `decisionstore:intern overflow`; scenario table overflow Warns `decisionstore:scenario intern overflow` and packs scenario id 0; kind, family, and TTL stay. Redis and the range blob remain `KindOriginString`. Lookup, `IncDropped`, and `ActiveCounts` stay origin×family; usage-metrics still must not send a `scenario` label.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Put carries `Decision.Scenario` into Scenario intern; `LookupRemediation` still returns kind, origin name, and origin id; usage-metrics still MUST NOT send a `scenario` item label.
**End users.** None.
