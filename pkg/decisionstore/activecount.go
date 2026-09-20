package decisionstore

import "sync"

// ActiveCountKey is one compact stream/alone gauge group: intern origin id and address family.
type ActiveCountKey struct {
	OriginID uint16
	Family   string
}

// activeCountState is the in-process origin×family gauge. Memory and Redis hold the same pointer.
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
