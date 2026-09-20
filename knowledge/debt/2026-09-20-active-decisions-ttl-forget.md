# Memory PublishTick and Redis TTL leave active_decisions high

IssueKey: 2026-09-20-store-active-decisions-gauge
Size: medium
Action: note

## Why this follow-up

Store-owned `active_decisions` adjusts only on PutMany/DeleteMany (one peek-then-adjust path). Memory PublishTick expiry and Redis key TTL drop the slot without DeleteMany, so the compact map stays high until a later overwrite or delete peeks the missing key.

## Why it was not taken

Counting on expiry would walk the swept keys (memory) or invent a TTL callback (Redis). That duplicated gauge logic inside the engines, which this change pulled out on purpose.

## Risks

`cscli metrics show bouncers` `active_decisions` can stay high after a slot expired in memory or Redis until stream Deleted or a later Put overwrites that key. Accepted.

## Context

Memory PublishTick still drops `ExpiresAt <= now` from tick. Redis MSetEX still uses CrowdSec duration as TTL. Gauge adjust is `pkg/decisionstore/activecount.go` only.
