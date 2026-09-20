# Compact LiveSlot.ExpiresAt to int32 elapsed seconds since process epoch

Memory DecisionStore slots (`pkg/decisionstore/liveslot.go` LiveSlot) store ExpiresAt as int64 Unix seconds. That makes the struct 16 bytes (uint32 Word + pad + int64). Changing ExpiresAt to int32 makes the struct 8 bytes. At 1M IPv4 keys on Go 1.25 swiss maps that saved ~27 MiB per published map (~54 MiB during BeginTick clone). Naive 8*N understates because of map table/group size-class rounding.

int16 is rejected: 32767s (~9.1h) cannot cover CrowdSec durations (stream TTL is int64 seconds with no clamp) nor Traefik uptime, and uint32+int16 still pads to 8 bytes same as int32.

Do not store Unix in the int32 field (Y2038 and unnecessary). Use a process-wide origin (write-once at package init, not Traefik New — New is per router). Now() is wall Unix minus origin. Name the clock elapsedsec (not customtimestamp, not floatingtimestamp). Extract pkg/elapsedsec only if explore confirms a Unix-shaped API with a second consumer; otherwise keep the origin unexported next to LiveSlot in pkg/decisionstore.

Origin must be wall Unix minus bias 2 so Now() is never 0 or 1. Current expiry predicate is ExpiresAt > 0 && ExpiresAt <= now (memory.go PublishTick, live PutMany COW sweep, LookupRemediation). PublishTick(0) is the test/skip-sweep sentinel. duration 0 and duration -1 (TestMemoryExpiryOnPublish) must still expire correctly. Saturate Expiry(durationSec) into (1, MaxInt32]; do not wrap. Clock step-back: clamp Now() to bias.

PublishTick must not keep taking time.Now().Unix() mixed with elapsed ExpiresAt (that would expire every slot). Change the now parameter to the elapsed clock. Redis PublishTick stays a no-op; Redis PutMany still uses DurationSec as TTL seconds (wall duration, not this timestamp). Captcha cookies, metrics, Redis EXAT stay wall Unix.

Benches that set ExpiresAt: 9_999_999_999 must use MaxInt32.

Out of scope: Redis slot encoding, packing expiry into Word leftover bits, int16, clamping stream TTL on Redis, changing intern Table, switching this caller checkout.
