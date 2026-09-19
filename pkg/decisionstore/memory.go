package decisionstore

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

type memory struct {
	log        *slog.Logger
	origins    *intern.Table
	mu         sync.Mutex
	tick       map[string]LiveSlot
	published  atomic.Value // map[string]LiveSlot
	rangeIndex string
}

func newMemory(log *slog.Logger, origins *intern.Table) *memory {
	return &memory{log: log, origins: origins}
}

// BeginTick clones the published map into tick. Lookups keep reading published.
func (m *memory) BeginTick() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, _ := m.published.Load().(map[string]LiveSlot)
	if len(prev) == 0 {
		m.tick = make(map[string]LiveSlot)
		return
	}
	next := make(map[string]LiveSlot, len(prev))
	for key, slot := range prev {
		next[key] = slot
	}
	m.tick = next
}

// PublishTick drops expired tick slots, publishes tick, and clears it.
func (m *memory) PublishTick(now int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tick == nil {
		return
	}
	for key, slot := range m.tick {
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			delete(m.tick, key)
		}
	}
	m.published.Store(m.tick)
	m.tick = nil
}

// Put writes one decision into tick when a stream window is open, else onto the published map (live).
func (m *memory) Put(item Decision) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tick != nil {
		m.putTick(item)
		return
	}
	m.putPublishedLocked(item)
}

// putTick writes one decision into tick. Intern overflow logs Warn and packs origin id 0.
func (m *memory) putTick(item Decision) {
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	m.tick[key] = LiveSlotFromPack(m.pack(item.Kind, item.Origin), item.DurationSec)
}

// putPublishedLocked copy-on-write one live slot onto the published map. Caller holds mu.
func (m *memory) putPublishedLocked(item Decision) {
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	prev, _ := m.published.Load().(map[string]LiveSlot)
	next := make(map[string]LiveSlot, len(prev)+1)
	for slotKey, slot := range prev {
		next[slotKey] = slot
	}
	next[key] = LiveSlotFromPack(m.pack(item.Kind, item.Origin), item.DurationSec)
	m.published.Store(next)
}

// pack encodes a uint32 word. Intern overflow Warns and uses origin id 0.
func (m *memory) pack(kind, origin string) uint32 {
	if m == nil {
		return packWord(kind, 0)
	}
	if m.origins != nil {
		if originID, ok := m.origins.ID(origin); ok {
			return packWord(kind, originID)
		}
		if m.log != nil {
			m.log.Warn("decisionstore:intern overflow", "kind", kind)
		}
	}
	return packWord(kind, 0)
}

// Delete drops the canonical slot and a prior Ip spelling from tick or the published map.
func (m *memory) Delete(scope, value string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key, legacy := slotKeys(scope, value)
	if key == "" {
		return
	}
	if m.tick != nil {
		delete(m.tick, key)
		if legacy != "" && legacy != key {
			delete(m.tick, legacy)
		}
		return
	}
	prev, _ := m.published.Load().(map[string]LiveSlot)
	if len(prev) == 0 {
		return
	}
	next := make(map[string]LiveSlot, len(prev))
	for slotKey, slot := range prev {
		if slotKey == key || (legacy != "" && slotKey == legacy) {
			continue
		}
		next[slotKey] = slot
	}
	m.published.Store(next)
}

// LookupRemediation reads the published map (Ip, header scopes, Range). Expired slots miss.
func (m *memory) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, uint16, error) {
	if m == nil {
		return "", "", 0, ErrMiss
	}
	snap, _ := m.published.Load().(map[string]LiveSlot)
	now := time.Now().Unix()
	kind, origin, originID := lookupHits(func(key string) any {
		slot, ok := snap[key]
		if !ok {
			return nil
		}
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			return nil
		}
		return slot.Word
	}, remoteIP, ipAddr, scopes, membership)
	if kind == "" {
		return "", "", 0, ErrMiss
	}
	return kind, origin, originID, nil
}

// ApplyRangeBatch mutates the in-process range-index blob.
func (m *memory) ApplyRangeBatch(upserts map[string]Decision, removals []string) error {
	if m == nil {
		return nil
	}
	if len(upserts) == 0 && len(removals) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rangeIndex = ApplyRangeIndex(m.rangeIndex, upserts, removals)
	return nil
}

// RangeIndex is the in-process range-index blob.
func (m *memory) RangeIndex() (string, error) {
	if m == nil {
		return "", nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rangeIndex, nil
}

func (m *memory) close() {}

// publishedMap is the lookup snapshot. Nil before the first publish or live Put.
func (m *memory) publishedMap() map[string]LiveSlot {
	if m == nil {
		return nil
	}
	snap, _ := m.published.Load().(map[string]LiveSlot)
	return snap
}

// seedPublished writes one decision onto the published map without a tick.
func (m *memory) seedPublished(item Decision) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.putPublishedLocked(item)
}
