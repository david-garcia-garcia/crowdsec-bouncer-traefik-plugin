package decisionstore

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

type memory struct {
	log        *slog.Logger
	origins    *intern.Table
	mu         sync.RWMutex
	ticking    bool
	tickWord   map[string]uint32
	tickExp    map[string]int64
	pubWord    map[string]uint32
	pubExp     map[string]int64
	rangeIndex string
}

func newMemory(log *slog.Logger, origins *intern.Table) *memory {
	return &memory{
		log:      log,
		origins:  origins,
		tickWord: map[string]uint32{},
		tickExp:  map[string]int64{},
		pubWord:  map[string]uint32{},
		pubExp:   map[string]int64{},
	}
}

// BeginTick clones the published maps into tick. Lookups keep reading published.
func (m *memory) BeginTick() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickWord = cloneUint32Map(m.pubWord)
	m.tickExp = cloneInt64Map(m.pubExp)
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
	for key, expiresAt := range m.tickExp {
		if expiresAt > 0 && expiresAt <= now {
			expired = append(expired, key)
		}
	}
	for _, key := range expired {
		delete(m.tickWord, key)
		delete(m.tickExp, key)
	}
	m.pubWord = m.tickWord
	m.pubExp = m.tickExp
	m.tickWord = map[string]uint32{}
	m.tickExp = map[string]int64{}
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
	slot := LiveSlotFromPack(m.pack(item.Kind, item.Origin), item.DurationSec)
	m.tickWord[key] = slot.Word
	m.tickExp[key] = slot.ExpiresAt
}

// putPublishedLocked copy-on-write one live slot onto the published maps. Caller holds mu.
func (m *memory) putPublishedLocked(item Decision) {
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	word := cloneUint32Map(m.pubWord)
	exp := cloneInt64Map(m.pubExp)
	slot := LiveSlotFromPack(m.pack(item.Kind, item.Origin), item.DurationSec)
	word[key] = slot.Word
	exp[key] = slot.ExpiresAt
	m.pubWord = word
	m.pubExp = exp
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
	if m.ticking {
		delete(m.tickWord, key)
		delete(m.tickExp, key)
		if legacy != "" && legacy != key {
			delete(m.tickWord, legacy)
			delete(m.tickExp, legacy)
		}
		return
	}
	word := cloneUint32Map(m.pubWord)
	exp := cloneInt64Map(m.pubExp)
	delete(word, key)
	delete(exp, key)
	if legacy != "" && legacy != key {
		delete(word, legacy)
		delete(exp, legacy)
	}
	m.pubWord = word
	m.pubExp = exp
}

// LookupRemediation reads the published map (Ip, header scopes, Range). Expired slots miss.
func (m *memory) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, uint16, error) {
	if m == nil {
		return "", "", 0, ErrMiss
	}
	m.mu.RLock()
	words := m.pubWord
	exps := m.pubExp
	m.mu.RUnlock()
	now := time.Now().Unix()
	kind, origin, originID := lookupHits(func(key string) any {
		word, ok := words[key]
		if !ok {
			return nil
		}
		if expiresAt := exps[key]; expiresAt > 0 && expiresAt <= now {
			return nil
		}
		return word
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
	if len(m.pubWord) == 0 {
		return nil
	}
	out := make(map[string]LiveSlot, len(m.pubWord))
	for key, word := range m.pubWord {
		out[key] = LiveSlot{Word: word, ExpiresAt: m.pubExp[key]}
	}
	return out
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

func cloneUint32Map(src map[string]uint32) map[string]uint32 {
	next := make(map[string]uint32, len(src))
	for key, packed := range src {
		next[key] = packed
	}
	return next
}

func cloneInt64Map(src map[string]int64) map[string]int64 {
	next := make(map[string]int64, len(src))
	for key, expiresAt := range src {
		next[key] = expiresAt
	}
	return next
}
