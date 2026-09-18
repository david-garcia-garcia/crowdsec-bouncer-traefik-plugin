## 1. Origin dictionary

- [x] 1.1 Add an append-only origin table on `DecisionStore` (forward + reverse, `uint16` ids, empty origin skipped, overflow does not intern or wrap, log once)
- [x] 1.2 Publish the name slice so resolve is lock-free after the write; intern write takes the table mutex
- [x] 1.3 Do not use a package `var`; two Clients that reclaim the same store share this table

## 2. Packed memory values

- [x] 2.1 Pack kind letter + origin id into a `uint32` stored in memory ttl_map `Data.Value`
- [x] 2.2 Keep string `Get`/`Set` for Redis, the stream lease, and the `range-index` blob; Redis still writes `RemediationWithOrigin`
- [x] 2.3 Add a memory type-switch accessor that shift/masks kind (or `stored[:1]` on a leftover string) without formatting a U+001F string and without taking intern `mu`
- [x] 2.4 Stream/alone write (`client_decisions.go`, `client_stream.go`) interns then packs; overflow and live/none stay on the string codec

## 3. Range and lookup

- [x] 3.1 Intern + pack Range upserts on the memory path before `ApplyRangeBatch`; membership holds packed or leftover-string values
- [x] 3.2 Lookup returns kind without resolving origin on the allow path; resolve `table[id]` or the leftover suffix only on drop
- [x] 3.3 Keep letter-only and Redis U+001F suffix matching

## 4. Compact slots

- [x] 4.1 Change `activeDecisionSlots` values to origin id + family byte; keep the per-slot map
- [x] 4.2 Reporter resolves names through the DecisionStore table at POST; overflow/empty origin still send today's labels
- [x] 4.3 `rememberActiveDecision` / `forgetActiveDecision` stay `Client` forwards; POST `origin` / `ip_type` stay `MetricsOrigin` and `ipv4`/`ipv6`

## 5. Tests

- [x] 5.1 Cover intern reuse, shared-store ids, isolated stores, overflow string fallback + one log
- [x] 5.2 Cover packed memory Ip ban, Redis still `\x1f`, allow path does not format origin, drop still sends `origin`
- [x] 5.3 Cover packed Range membership remediates; letter-only Range still remediates
- [x] 5.4 Cover `active_decisions` labels after compact slots and forget still clears the slot

## 6. Verify

- [x] 6.1 `go test` for `pkg/cache`, `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`
- [x] 6.2 Grep live product paths for a package-level origin table and for `atomic.Pointer`
