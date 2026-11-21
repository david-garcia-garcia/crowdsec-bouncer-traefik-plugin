package decisionstore

import (
	"math"
	"time"
)

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
// ExpiresAt (store TTL end) and DecisionEnd (decision end, 0 = unknown) are elapsed whole
// seconds on the package clock, not wall Unix. Stream sets both to the same second; a live
// memo keeps ExpiresAt at the capped cache end and DecisionEnd at the decision end.
type LiveSlot struct {
	Word        uint32
	ExpiresAt   int32
	DecisionEnd int32
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
	return int32(elapsed)
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

// decisionEndFromDuration is the elapsed DecisionEnd for a decision's remaining seconds, or 0 when unknown.
// A known end is at least elapsedBias, so it never collides with the 0 sentinel.
func decisionEndFromDuration(decisionDurationSec int64) int32 {
	if decisionDurationSec <= 0 {
		return 0
	}
	return expiryFromDuration(decisionDurationSec)
}

// LiveSlotFromPack builds a slot from a packed word, the store TTL seconds, and the decision's remaining seconds.
func LiveSlotFromPack(word uint32, durationSec, decisionDurationSec int64) LiveSlot {
	return LiveSlot{
		Word:        word,
		ExpiresAt:   expiryFromDuration(durationSec),
		DecisionEnd: decisionEndFromDuration(decisionDurationSec),
	}
}

// decisionLeft is the time left on this slot's decision at elapsed now. Zero when the end is unknown or past.
func (slot LiveSlot) decisionLeft(now int32) time.Duration {
	if slot.DecisionEnd == 0 || slot.DecisionEnd <= now {
		return 0
	}
	return time.Duration(slot.DecisionEnd-now) * time.Second
}
