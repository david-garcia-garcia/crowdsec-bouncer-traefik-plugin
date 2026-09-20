## MODIFIED Requirements

### Requirement: Memory engine is copy-on-write maps
A memory-backed Store SHALL hold `map[string]LiveSlot` (packed word and expiresAt), always non-nil. Each `LiveSlot.expiresAt` SHALL be int32 elapsed whole seconds on the package elapsed clock (not wall Unix). BeginTick SHALL clone published into tick. PutMany and DeleteMany during a stream apply SHALL mutate tick only. PublishTick SHALL accept `now` as int32 elapsed seconds on that same clock. When `now` is `0`, memory PublishTick SHALL skip dropping slots by expiry and SHALL still publish tick once (sentinel). When `now` is not `0`, PublishTick SHALL drop tick slots where `expiresAt > 0 && expiresAt <= now`, then publish once. Memory lookup and live PutMany copy-on-write sweeps SHALL use the same elapsed `now` and predicate. Memory MUST NOT Set stream or live Ip or header keys on a TTL heap. When no tick is open, PutMany SHALL copy-on-write onto the published map (live/none memo). Redis BeginTick and PublishTick SHALL be no-ops and SHALL ignore the elapsed `now` argument. Redis PutMany SHALL group by DurationSec and MSetEX in `PutManyChunk` (1024) batches. Redis DeleteMany SHALL DEL each key (SimpleRedis has no multi-DEL).

#### Scenario: Memory stream IP is not on a TTL heap
- **WHEN** stream/alone memory stores an Ip ban for a client address
- **THEN** lookup reads the published LiveSlot map for that Ip key after PublishTick

#### Scenario: Single publish after full payload
- **WHEN** one stream payload adds two Ip bans and deletes one header scope
- **THEN** observers see at most one new map generation for that apply
- **AND** all three mutations appear together after PublishTick

#### Scenario: PublishTick zero skips expiry sweep
- **WHEN** memory PublishTick is called with elapsed `now` `0` while tick holds slots that would expire for a non-zero `now`
- **THEN** those slots remain in the published map after PublishTick
- **AND** a later lookup using elapsed `now` still applies the expiry predicate

## ADDED Requirements

### Requirement: Memory slot expiry uses elapsed seconds
The decisionstore package SHALL fix a process-wide origin once at package init as wall Unix minus two seconds. Elapsed `now()` SHALL be wall Unix minus that origin, clamped so it never decreases when wall clock steps backward. Packing a memory slot from CrowdSec `durationSec` SHALL set `expiresAt` to a saturated int32 in `[1, MaxInt32]` derived from elapsed `now()` plus `durationSec` (`1` is already expired and still `> 0`), so duration `0` and `-1` yield values that miss under the predicate `expiresAt > 0 && expiresAt <= now()` on the next comparison. The Store `PublishTick` method and the memory engine PublishTick callback SHALL take `now` as int32 elapsed seconds. Callers that drive memory expiry (including stream apply after a payload) SHALL pass elapsed `now()`, not wall Unix seconds.

#### Scenario: Stream apply passes elapsed now
- **WHEN** the stream poller finishes applying one payload on a memory-backed Store
- **THEN** it calls PublishTick with elapsed seconds from the decisionstore clock
- **AND** it does not pass wall Unix seconds as `now`

#### Scenario: Wall Unix now would drop every slot
- **WHEN** published memory slots hold elapsed `expiresAt` values
- **AND** a caller mistakenly passes wall Unix magnitude as PublishTick `now`
- **THEN** the implementation contract treats that as incorrect usage; correct callers use elapsed `now()` only

#### Scenario: Duration zero does not linger past publish sweep
- **WHEN** memory PutMany stores a slot with duration `0` during a tick
- **AND** PublishTick runs with non-zero elapsed `now`
- **THEN** that slot is absent from the published map after PublishTick
