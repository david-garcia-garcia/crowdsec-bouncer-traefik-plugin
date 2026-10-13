# Standards

1. [hard] Leave a trail — `pkg/decisionstore/liveslot.go:25` — `ElapsedNow` comment limits callers to “PublishTick and tests” but stream apply is production code
   ```go
   // ElapsedNow is whole seconds on the memory slot clock for PublishTick and tests.
   func ElapsedNow() int32 {
   ```
   → Name stream apply and other memory expiry callers, not only tests
   Status: done
   Argument: ElapsedNow comment names stream apply, PublishTick, lookup, and tests.

2. [hard] Leave a trail — `pkg/decisionstore/liveslot.go:30` — new `elapsedNow` has no succinct job comment and the CAS clamp loop is a second logical block without a block intro
   ```go
   func elapsedNow() int32 {
   	wallElapsed := time.Now().Unix() - originUnix
   	for {
   		last := atomic.LoadInt64(&lastElapsed)
   ```
   → Add a function comment and a one-line intro before the monotonic clamp loop
   Status: done
   Argument: Function comment plus one-line intro before the CAS clamp loop.

3. [hard] Leave a trail — `pkg/decisionstore/liveslot.go:47` — new `expiryFromDuration` has no function comment (commandment: every function states its job)
   ```go
   func expiryFromDuration(durationSec int64) int32 {
   	exp := int64(elapsedNow()) + durationSec
   ```
   → Add a one-line comment for saturated elapsed `ExpiresAt` from CrowdSec duration seconds
   Status: done
   Argument: Function comment added.

4. [hard] Leave a trail — `pkg/decisionstore/liveslot.go:20` — package `init` that fixes the elapsed clock origin has no comment
   ```go
   func init() {
   	originUnix = time.Now().Unix() - 2
   	atomic.StoreInt64(&lastElapsed, 2)
   ```
   → Add a one-line comment that origin is write-once and seeds monotonic elapsed at 2
   Status: done
   Argument: init comment: origin write-once, elapsed seed 2.

5. [hard] Leave a trail — `pkg/decisionstore/store.go:124` — public `PublishTick(now int32)` comment still reads like the old wall-Unix API and does not say `now` is elapsed seconds
   ```go
   // PublishTick closes that window. Memory drops expired tick slots and publishes tick.
   // Redis is a no-op: key TTL is the expiry.
   func (s *Store) PublishTick(now int32) {
   ```
   → Document that memory callers pass elapsed seconds on the package clock, not wall Unix
   Status: done
   Argument: PublishTick comment says elapsed seconds / ElapsedNow, not wall Unix.

6. [hard] Name for the scope — `pkg/decisionstore/liveslot.go:48` — `exp` abbreviates the saturated elapsed expiry value this body returns
   ```go
   exp := int64(elapsedNow()) + durationSec
   if exp <= 1 {
   	return 1
   ```
   → Rename to the role in this body, e.g. `elapsedExpiresAt`
   Status: done
   Argument: Renamed to elapsedExpiresAt.

7. [judgement] Mysterious Name — `pkg/decisionstore/liveslot.go:12` — `ExpiresAt` still reads as a wall instant but the diff retargets it to int32 elapsed seconds on the package clock
   ```go
   type LiveSlot struct {
   	Word      uint32
   	ExpiresAt int32
   }
   ```
   → Add a field or type doc line for elapsed encoding so readers are not decoding from the identifier alone
   Status: skipped
   Argument: judgement; ExpiresAt stays the slot role. Encoding is on the type comment (elapsed, not wall Unix).
