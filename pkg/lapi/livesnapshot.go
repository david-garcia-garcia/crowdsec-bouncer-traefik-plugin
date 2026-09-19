package lapi

import (
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// cloneLiveSnapshot copies the prior tick map for in-tick mutation.
func (s *DecisionStore) cloneLiveSnapshot() map[string]decisionscope.LiveSlot {
	if s == nil {
		return make(map[string]decisionscope.LiveSlot)
	}
	prev, _ := s.liveSnapshot.Load().(map[string]decisionscope.LiveSlot)
	if len(prev) == 0 {
		return make(map[string]decisionscope.LiveSlot)
	}
	next := make(map[string]decisionscope.LiveSlot, len(prev))
	for key, slot := range prev {
		next[key] = slot
	}
	return next
}

// publishLiveSnapshot drops expired slots and stores the clone for readers.
func (s *DecisionStore) publishLiveSnapshot(next map[string]decisionscope.LiveSlot, now int64) {
	if s == nil || next == nil {
		return
	}
	for key, slot := range next {
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			delete(next, key)
		}
	}
	s.liveSnapshot.Store(next)
}

// LiveSnapshot is the published stream/alone memory map. Nil when empty or Redis-backed.
func (s *DecisionStore) LiveSnapshot() map[string]decisionscope.LiveSlot {
	if s == nil {
		return nil
	}
	snap, _ := s.liveSnapshot.Load().(map[string]decisionscope.LiveSlot)
	return snap
}

// UsesLiveSnapshot is true for in-memory DecisionStore stream/alone lookup.
func (c *Client) UsesLiveSnapshot() bool {
	return c != nil && c.decisionStore != nil && c.decisionStore.PacksMemory()
}

// LiveSnapshot forwards the store snapshot for request lookup.
func (c *Client) LiveSnapshot() map[string]decisionscope.LiveSlot {
	if c == nil || c.decisionStore == nil {
		return nil
	}
	return c.decisionStore.LiveSnapshot()
}

// publishLiveTick ends a stream apply tick on memory stores.
func (c *Client) publishLiveTick() {
	if c == nil || c.decisionStore == nil || !c.decisionStore.PacksMemory() || c.liveTick == nil {
		return
	}
	c.decisionStore.publishLiveSnapshot(c.liveTick, time.Now().Unix())
	c.liveTick = nil
}
