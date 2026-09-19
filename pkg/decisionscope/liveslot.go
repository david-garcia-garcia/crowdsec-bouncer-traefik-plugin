package decisionscope

import "time"

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
type LiveSlot struct {
	Word      uint32
	ExpiresAt int64
}

// LiveSlotFromPack builds a slot from a Pack payload and CrowdSec duration seconds.
func LiveSlotFromPack(payload any, durationSec int64) LiveSlot {
	expiresAt := time.Now().Unix() + durationSec
	switch stored := payload.(type) {
	case uint32:
		return LiveSlot{Word: stored, ExpiresAt: expiresAt}
	case string:
		return LiveSlot{Word: packWord(RemediationKind(stored), 0), ExpiresAt: expiresAt}
	default:
		return LiveSlot{ExpiresAt: expiresAt}
	}
}
