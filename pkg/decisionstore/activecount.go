package decisionstore

import "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"

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
// Incremental Put/Delete/TTL is possible, but overwrite still needs a previous-origin peek
// and expiry still walks the same keys. One pass after the snapshot is published is simpler
// and lower impact, and it matches what lookups currently see. Range is not in this map.
func countPublishedSlots(slots map[string]LiveSlot) map[ActiveCountKey]int64 {
	out := make(map[ActiveCountKey]int64)
	for key, slot := range slots {
		_, _, originID := unpackWord(slot.Word)
		family := ip.FamilyOfHostOrCIDR(key)
		out[ActiveCountKey{OriginID: originID, Family: family}]++
	}
	return out
}
