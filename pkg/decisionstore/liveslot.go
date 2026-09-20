package decisionstore

import (
	"math"
	"sync/atomic"
	"time"
)

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
// ExpiresAt is elapsed whole seconds on the package clock, not wall Unix.
type LiveSlot struct {
	Word      uint32
	ExpiresAt int32
}

var (
	originUnix  int64 //nolint:gochecknoglobals // process-wide memory slot clock origin at init
	lastElapsed int64 //nolint:gochecknoglobals // monotonic elapsed seconds for slot comparisons
)

// init fixes origin at wall Unix minus two so elapsed 0 stays the PublishTick skip sentinel.
//
//nolint:gochecknoinits // process-wide clock seed; explore rejected per-Store origin
func init() {
	originUnix = time.Now().Unix() - 2
	atomic.StoreInt64(&lastElapsed, 2)
}

// ElapsedNow is whole seconds on the memory slot clock for stream apply, PublishTick, lookup, and tests.
func ElapsedNow() int32 {
	return elapsedNow()
}

// elapsedNow is wall Unix minus origin, never decreasing when the wall clock steps back.
func elapsedNow() int32 {
	wallElapsed := time.Now().Unix() - originUnix
	// Keep lastElapsed monotonic across NTP step-back.
	for {
		last := atomic.LoadInt64(&lastElapsed)
		if wallElapsed < last {
			wallElapsed = last
		}
		if atomic.CompareAndSwapInt64(&lastElapsed, last, wallElapsed) {
			break
		}
	}
	if wallElapsed > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(wallElapsed) //nolint:gosec // G115 capped above MaxInt32
}

// expiryFromDuration is saturated elapsed ExpiresAt from CrowdSec duration seconds.
func expiryFromDuration(durationSec int64) int32 {
	elapsedExpiresAt := int64(elapsedNow()) + durationSec
	if elapsedExpiresAt <= 1 {
		return 1
	}
	if elapsedExpiresAt > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(elapsedExpiresAt)
}

// LiveSlotFromPack builds a slot from a packed word and CrowdSec duration seconds.
func LiveSlotFromPack(word uint32, durationSec int64) LiveSlot {
	return LiveSlot{Word: word, ExpiresAt: expiryFromDuration(durationSec)}
}
