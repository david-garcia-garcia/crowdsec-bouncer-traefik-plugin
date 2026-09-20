package decisionstore

import (
	"sync"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// ActiveCountKey is one compact stream/alone gauge group: intern origin id and address family.
type ActiveCountKey struct {
	OriginID uint16
	Family   string
}

// peekedSlot is what one engine key held before PutMany/DeleteMany. Memory fills OriginID;
// Redis fills Leftover from KindOriginString. Present is false when the key is missing.
type peekedSlot struct {
	OriginID uint16
	Leftover string
	Present  bool
}

// activeCountState is the in-process origin×family gauge. Store PutMany/DeleteMany adjust it.
type activeCountState struct {
	mu    sync.Mutex
	byKey map[ActiveCountKey]int64
}

// newActiveCountState allocates an empty compact map.
func newActiveCountState() *activeCountState {
	return &activeCountState{byKey: map[ActiveCountKey]int64{}}
}

// add increments or decrements one group. A non-positive total drops the key.
func (c *activeCountState) add(key ActiveCountKey, delta int64) {
	if c == nil || delta == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byKey == nil {
		c.byKey = map[ActiveCountKey]int64{}
	}
	next := c.byKey[key] + delta
	if next <= 0 {
		delete(c.byKey, key)
		return
	}
	c.byKey[key] = next
}

// snapshot copies groups with a positive count.
func (c *activeCountState) snapshot() map[ActiveCountKey]int64 {
	if c == nil {
		return map[ActiveCountKey]int64{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[ActiveCountKey]int64, len(c.byKey))
	for key, value := range c.byKey {
		if value > 0 {
			out[key] = value
		}
	}
	return out
}

// ActiveCounts is a snapshot copy of origin×family counts. Empty when countActive is false.
func (s *Store) ActiveCounts() map[ActiveCountKey]int64 {
	if s == nil || !s.countActive {
		return map[ActiveCountKey]int64{}
	}
	return s.active.snapshot()
}

// adjustPuts decrements a peeked previous origin×family group then increments the new.
// Same-batch overwrite updates prev so a second Put of one key is a swap. Engines do not call this.
func (s *Store) adjustPuts(items []Decision) {
	if !s.countActive || len(items) == 0 {
		return
	}
	prev := s.engine.peekMany(canonicalKeys(items))
	if prev == nil {
		prev = map[string]peekedSlot{}
	}
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		family := ip.FamilyOfHostOrCIDR(item.Value)
		if previous, ok := prev[key]; ok && previous.Present {
			s.active.add(ActiveCountKey{OriginID: s.originIDFromPeek(previous), Family: family}, -1)
		}
		originID := s.internOrigin(item.Origin)
		s.active.add(ActiveCountKey{OriginID: originID, Family: family}, 1)
		prev[key] = peekedSlot{OriginID: originID, Present: true}
	}
}

// adjustDeletes decrements the peeked canonical group once. Missing delete is a no-op.
func (s *Store) adjustDeletes(items []Decision) {
	if !s.countActive || len(items) == 0 {
		return
	}
	prev := s.engine.peekMany(canonicalKeys(items))
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		previous, ok := prev[key]
		if !ok || !previous.Present {
			continue
		}
		family := ip.FamilyOfHostOrCIDR(item.Value)
		s.active.add(ActiveCountKey{OriginID: s.originIDFromPeek(previous), Family: family}, -1)
		delete(prev, key)
	}
}

func canonicalKeys(items []Decision) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		key, _ := slotKeys(item.Scope, item.Value)
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func (s *Store) originIDFromPeek(slot peekedSlot) uint16 {
	if slot.Leftover != "" {
		return s.internOrigin(slot.Leftover)
	}
	return slot.OriginID
}

func (s *Store) internOrigin(name string) uint16 {
	if s == nil || s.origins == nil {
		return 0
	}
	originID, ok := s.origins.ID(name)
	if ok {
		return originID
	}
	return 0
}
