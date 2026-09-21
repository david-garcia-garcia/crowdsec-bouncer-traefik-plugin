package decisionstore

// ActiveCountKey is one compact stream/alone gauge group: intern origin id and address family.
type ActiveCountKey struct {
	OriginID uint16
	Family   string
}

// ActiveCounts is a copy of the engine's origin×family snapshot. Memory recounts after
// PublishTick builds the published map. Redis always returns empty (no slot inventory).
func (s *Store) ActiveCounts() map[ActiveCountKey]int64 {
	return s.engine.activeCounts()
}

// countPublishedSlots walks the published Ip/header snapshot into origin×family totals.
// Family and origin id come from the packed word (parsed at Put), not ParseIP on the key.
func countPublishedSlots(slots map[string]LiveSlot) map[ActiveCountKey]int64 {
	out := make(map[ActiveCountKey]int64)
	for _, slot := range slots {
		word := slot.Word
		out[ActiveCountKey{OriginID: packedOriginID(word), Family: packedFamily(word)}]++
	}
	return out
}
