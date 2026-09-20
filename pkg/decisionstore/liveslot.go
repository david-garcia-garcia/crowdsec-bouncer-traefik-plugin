package decisionstore

import (
	"math"
	"sync/atomic"
	"time"
)

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
type LiveSlot struct {
	Word      uint32
	ExpiresAt int32
}

var (
	originUnix  int64
	lastElapsed int64 // wall elapsed seconds; monotonic for slot comparisons
)

func init() {
	originUnix = time.Now().Unix() - 2
	atomic.StoreInt64(&lastElapsed, 2)
}

// ElapsedNow is whole seconds on the memory slot clock for PublishTick and tests.
func ElapsedNow() int32 {
	return elapsedNow()
}

func elapsedNow() int32 {
	wallElapsed := time.Now().Unix() - originUnix
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
	return int32(wallElapsed)
}

func expiryFromDuration(durationSec int64) int32 {
	exp := int64(elapsedNow()) + durationSec
	if exp <= 1 {
		return 1
	}
	if exp > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(exp)
}

// LiveSlotFromPack builds a slot from a packed word and CrowdSec duration seconds.
func LiveSlotFromPack(word uint32, durationSec int64) LiveSlot {
	return LiveSlot{Word: word, ExpiresAt: expiryFromDuration(durationSec)}
}
