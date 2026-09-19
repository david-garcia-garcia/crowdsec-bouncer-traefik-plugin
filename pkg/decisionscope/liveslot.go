package decisionscope

import "time"

// LiveSlot is one in-memory stream/alone decision keyed by Ip or header-scope string.
type LiveSlot struct {
	Word      uint32
	ExpiresAt int64
	Leftover  string
}

// HitFromLiveSlot unpacks a live snapshot slot into lookup merge input.
func HitFromLiveSlot(slot LiveSlot) lookupHit {
	if slot.Leftover != "" {
		return hitFromPayload(slot.Leftover)
	}
	return hitFromPayload(slot.Word)
}

// LiveSlotFromPack builds a slot from a Pack payload and CrowdSec duration seconds.
func LiveSlotFromPack(payload any, durationSec int64) LiveSlot {
	expiresAt := time.Now().Unix() + durationSec
	switch stored := payload.(type) {
	case uint32:
		return LiveSlot{Word: stored, ExpiresAt: expiresAt}
	case string:
		return LiveSlot{Leftover: stored, ExpiresAt: expiresAt}
	default:
		return LiveSlot{ExpiresAt: expiresAt}
	}
}
