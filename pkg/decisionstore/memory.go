package decisionstore

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

// publishedSlots is one immutable lookup map. atomic.Value stores *publishedSlots, not the map (Yaegi).
type publishedSlots struct {
	byKey map[string]LiveSlot
}

// memory is in-process COW tick/published LiveSlot maps plus the Range blob.
type memory struct {
	log        *slog.Logger
	origins    *intern.Table            // origin name → id packed into LiveSlot.Word
	mu         sync.RWMutex             // tick, ticking, rangeIndex, active; not lookup
	ticking    bool                     // stream window: PutMany/DeleteMany write tick; Lookup reads published
	tick       map[string]LiveSlot      // unpublished clone; SlotKey → packed word + elapsed expiry
	published  atomic.Value             // *publishedSlots; request-path snapshot, not atomic.Pointer (Yaegi v0.16)
	active     map[ActiveCountKey]int64 // last PublishTick walk of published; not adjusted on Put/Delete
	rangeIndex string                   // Range CIDR=kind blob; membership is rebuilt from this
}

// newMemory allocates non-nil tick and an empty published snapshot.
func newMemory(log *slog.Logger, origins *intern.Table) *memory {
	mem := &memory{
		log:     log,
		origins: origins,
		tick:    map[string]LiveSlot{},
		active:  map[ActiveCountKey]int64{},
	}
	mem.storePublished(map[string]LiveSlot{})
	return mem
}

// publishedMapValue is the current lookup map. Never nil. Callers must not mutate it.
func (m *memory) publishedMapValue() map[string]LiveSlot {
	loaded, _ := m.published.Load().(*publishedSlots)
	if loaded == nil || loaded.byKey == nil {
		return map[string]LiveSlot{}
	}
	return loaded.byKey
}

// storePublished publishes slots as the lookup snapshot. Caller holds mu except construct.
func (m *memory) storePublished(slots map[string]LiveSlot) {
	if slots == nil {
		slots = map[string]LiveSlot{}
	}
	m.published.Store(&publishedSlots{byKey: slots})
}

// BeginTick clones the published map into tick. Lookups keep reading published.
func (m *memory) BeginTick() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tick = cloneLiveSlotMap(m.publishedMapValue())
	m.ticking = true
}

// PublishTick drops expired tick slots, publishes tick, recounts ActiveCounts, and closes the window.
// The walk runs after the published snapshot exists so the gauge matches lookup, including TTL drops.
func (m *memory) PublishTick(now int32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ticking {
		return
	}
	if now != 0 {
		var expired []string
		for key, slot := range m.tick {
			if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
				expired = append(expired, key)
			}
		}
		for _, key := range expired {
			delete(m.tick, key)
		}
	}
	m.storePublished(m.tick)
	m.active = countPublishedSlots(m.publishedMapValue())
	m.tick = map[string]LiveSlot{}
	m.ticking = false
}

// PutMany writes decisions into tick when a stream window is open, else copy-on-write onto published (live).
func (m *memory) PutMany(items []Decision) {
	if len(items) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ticking {
		for _, item := range items {
			m.putSlot(m.tick, item)
		}
		return
	}
	next := cloneLiveSlotMap(m.publishedMapValue())
	now := elapsedNow()
	for existing, slot := range next {
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			delete(next, existing)
		}
	}
	for _, item := range items {
		m.putSlot(next, item)
	}
	m.storePublished(next)
}

// putSlot writes one decision into slots. Intern overflow logs Warn and packs origin id 0.
func (m *memory) putSlot(slots map[string]LiveSlot, item Decision) {
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	slots[key] = LiveSlotFromPack(m.pack(item.Kind, item.Origin), item.DurationSec)
}

// pack encodes a uint32 word. Intern overflow Warns and uses origin id 0.
func (m *memory) pack(kind, origin string) uint32 {
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

// DeleteMany drops canonical slots and prior Ip spellings from tick or the published map.
func (m *memory) DeleteMany(items []Decision) {
	if len(items) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ticking {
		for _, item := range items {
			m.deleteTickLocked(item.Scope, item.Value)
		}
		return
	}
	next := cloneLiveSlotMap(m.publishedMapValue())
	for _, item := range items {
		key, priorSpelling := slotKeys(item.Scope, item.Value)
		if key == "" {
			continue
		}
		delete(next, key)
		if priorSpelling != "" && priorSpelling != key {
			delete(next, priorSpelling)
		}
	}
	m.storePublished(next)
}

// deleteTickLocked drops one slot from tick. Caller holds mu.
func (m *memory) deleteTickLocked(scope, value string) {
	key, priorSpelling := slotKeys(scope, value)
	if key == "" {
		return
	}
	delete(m.tick, key)
	if priorSpelling != "" && priorSpelling != key {
		delete(m.tick, priorSpelling)
	}
}

// activeCounts copies the last PublishTick origin×family walk. Live Put does not PublishTick.
func (m *memory) activeCounts() map[ActiveCountKey]int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[ActiveCountKey]int64, len(m.active))
	for key, value := range m.active {
		out[key] = value
	}
	return out
}

// LookupRemediation reads the published snapshot (Ip, header scopes, Range). Expired slots miss.
func (m *memory) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (kind string, origin string, originID uint16, err error) {
	slots := m.publishedMapValue()
	now := elapsedNow()
	kind, origin, originID = lookupHits(func(key string) any {
		slot, ok := slots[key]
		if !ok {
			return nil
		}
		if slot.ExpiresAt > 0 && slot.ExpiresAt <= now {
			return nil
		}
		return slot.Word
	}, remoteIP, ipAddr, scopes, membership)
	return kind, origin, originID, nil
}

// ApplyRangeBatch mutates the in-process range-index blob.
func (m *memory) ApplyRangeBatch(upserts map[string]string, removals []string) error {
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rangeIndex, nil
}

// publishedMap is the lookup snapshot. Nil before the first publish or live Put.
func (m *memory) publishedMap() map[string]LiveSlot {
	slots := m.publishedMapValue()
	if len(slots) == 0 {
		return nil
	}
	return cloneLiveSlotMap(slots)
}

// seedPublished writes one decision onto the published map without a tick.
func (m *memory) seedPublished(item Decision) {
	m.PutMany([]Decision{item})
}

func cloneLiveSlotMap(src map[string]LiveSlot) map[string]LiveSlot {
	next := make(map[string]LiveSlot, len(src))
	for key, slot := range src {
		next[key] = slot
	}
	return next
}
