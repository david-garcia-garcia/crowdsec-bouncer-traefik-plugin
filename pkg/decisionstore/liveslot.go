package decisionstore

import (
	"time"
)

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
type LiveSlot struct {
	Word      uint32
	ExpiresAt int64
}

// LiveSlotFromPack builds a slot from a packed word and CrowdSec duration seconds.
func LiveSlotFromPack(word uint32, durationSec int64) LiveSlot {
	return LiveSlot{Word: word, ExpiresAt: time.Now().Unix() + durationSec}
}
