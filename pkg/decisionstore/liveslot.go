package decisionstore

import (
	"math"
	"time"
)

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
// ExpiresAt is elapsed whole seconds on the package clock, not wall Unix.
type LiveSlot struct {
	Word      uint32
	ExpiresAt int32
}

// elapsedStart is the process-wide memory slot clock. time.Since uses its monotonic reading.
var elapsedStart = time.Now() //nolint:gochecknoglobals // one slot clock per process

const elapsedBias = 2 // keeps 0 as PublishTick skip-sweep sentinel

// ElapsedNow is whole seconds on the memory slot clock for stream apply, PublishTick, lookup, and tests.
func ElapsedNow() int32 {
	return elapsedNow()
}

// elapsedNow is process uptime in seconds plus bias, from elapsedStart's monotonic clock.
func elapsedNow() int32 {
	elapsed := int64(time.Since(elapsedStart)/time.Second) + elapsedBias
	if elapsed < elapsedBias {
		return elapsedBias
	}
	if elapsed > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(elapsed) //nolint:gosec // G115 capped above MaxInt32
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
