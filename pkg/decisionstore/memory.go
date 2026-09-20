package decisionstore

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

// memory is in-process COW tick/published LiveSlot maps plus the Range blob.
type memory struct {
	log        *slog.Logger
	origins    *intern.Table       // origin name → id packed into LiveSlot.Word
	mu         sync.RWMutex        // maps, ticking, rangeIndex
	ticking    bool                // stream window: Put/Delete write tick; Lookup reads published
	tick       map[string]LiveSlot // unpublished clone; SlotKey → packed word + Unix expiry
	published  map[string]LiveSlot // request-path snapshot
	rangeIndex string              // Range CIDR=kind blob; membership is rebuilt from this
}

// newMemory allocates non-nil tick/published maps.
func newMemory(log *slog.Logger, origins *intern.Table) *memory {
	return &memory{
		log:       log,
		origins:   origins,
		tick:      map[string]LiveSlot{},
		published: map[string]LiveSlot{},
	}
}

// BeginTick clones the published map into tick. Lookups keep reading published.
func (m *memory) BeginTick() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tick = cloneLiveSlotMap(m.published)
	m.ticking = true
}

// PublishTick drops expired tick slots, publishes tick, and closes the window.
func (m *memory) PublishTick(now int64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ticking {
		return
	}
	var expired []string
	for key, slot := range m.tick {
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		delete(m.tick, key)
	}
	m.published = m.tick
	m.tick = map[string]LiveSlot{}
	m.ticking = false
}

// Put writes one decision into tick when a stream window is open, else onto the published map (live).
func (m *memory) Put(item Decision) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ticking {
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

// putPublishedLocked writes one live slot onto the published map and sweeps expired keys. Caller holds mu.
func (m *memory) putPublishedLocked(item Decision) {
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	now := time.Now().Unix()
	for existing, slot := range m.published {
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			delete(m.published, existing)
		}
	}
	m.published[key] = LiveSlotFromPack(m.pack(item.Kind, item.Origin), item.DurationSec)
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
			m.log.Warn("decisionstore:intern overflow", "kind", kind, "origin", origin)
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
	key, priorSpelling := slotKeys(scope, value)
	if key == "" {
		return
	}
	if m.ticking {
		delete(m.tick, key)
		if priorSpelling != "" && priorSpelling != key {
			delete(m.tick, priorSpelling)
		}
		return
	}
	next := cloneLiveSlotMap(m.published)
	delete(next, key)
	if priorSpelling != "" && priorSpelling != key {
		delete(next, priorSpelling)
	}
	m.published = next
}

// LookupRemediation reads the published map (Ip, header scopes, Range). Expired slots miss.
func (m *memory) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, uint16, error) {
	if m == nil {
		return "", "", 0, ErrMiss
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now().Unix()
	kind, origin, originID := lookupHits(func(key string) any {
		slot, ok := m.published[key]
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
func (m *memory) ApplyRangeBatch(upserts map[string]string, removals []string) error {
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rangeIndex, nil
}

// publishedMap is the lookup snapshot. Nil before the first publish or live Put.
func (m *memory) publishedMap() map[string]LiveSlot {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.published) == 0 {
		return nil
	}
	return cloneLiveSlotMap(m.published)
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

func cloneLiveSlotMap(src map[string]LiveSlot) map[string]LiveSlot {
	next := make(map[string]LiveSlot, len(src))
	for key, slot := range src {
		next[key] = slot
	}
	return next
}
