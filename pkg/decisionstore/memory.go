package decisionstore

import (
	"log/slog"
	"net"
	"sync/atomic"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

type memory struct {
	log       *slog.Logger
	origins   *intern.Table
	tick      map[string]decisionscope.LiveSlot
	published atomic.Value // map[string]decisionscope.LiveSlot
}

func newMemory(log *slog.Logger, origins *intern.Table) *memory {
	return &memory{log: log, origins: origins}
}

// BeginTick clones the published map into tick. Lookups keep reading published.
func (m *memory) BeginTick() {
	if m == nil {
		return
	}
	prev, _ := m.published.Load().(map[string]decisionscope.LiveSlot)
	if len(prev) == 0 {
		m.tick = make(map[string]decisionscope.LiveSlot)
		return
	}
	next := make(map[string]decisionscope.LiveSlot, len(prev))
	for key, slot := range prev {
		next[key] = slot
	}
	m.tick = next
}

// PublishTick drops expired tick slots, publishes tick, and clears it.
func (m *memory) PublishTick(now int64) {
	if m == nil || m.tick == nil {
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

// Put writes one decision into tick. Intern overflow logs Warn and stores kind only.
func (m *memory) Put(item Decision) {
	if m == nil || m.tick == nil {
		return
	}
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	payload := m.pack(item.Kind, item.Origin)
	if stored, isString := payload.(string); isString && m.log != nil {
		m.log.Warn("decisionstore:intern overflow", "kind", decisionscope.RemediationKind(stored))
	}
	m.tick[key] = decisionscope.LiveSlotFromPack(payload, item.DurationSec)
}

// pack encodes a uint32 word when intern succeeds, else a leftover kind+origin string.
func (m *memory) pack(kind, origin string) any {
	if m == nil {
		return decisionscope.RemediationWithOrigin(kind, origin)
	}
	return decisionscope.Pack(kind, origin, originIntern{table: m.origins, packsMemory: true})
}

// Delete drops the canonical slot and a prior Ip spelling from tick.
func (m *memory) Delete(scope, value string) {
	if m == nil || m.tick == nil {
		return
	}
	key, legacy := slotKeys(scope, value)
	if key == "" {
		return
	}
	delete(m.tick, key)
	if legacy != "" && legacy != key {
		delete(m.tick, legacy)
	}
}

// LookupRemediation reads the published map (Ip, header scopes, Range).
func (m *memory) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error) {
	if m == nil {
		return "", "", 0, cache.ErrMiss
	}
	snap, _ := m.published.Load().(map[string]decisionscope.LiveSlot)
	return decisionscope.LookupStreamMapRemediation(snap, remoteIP, ipAddr, scopes, membership)
}

// publishedMap is the lookup snapshot. Nil before the first PublishTick.
func (m *memory) publishedMap() map[string]decisionscope.LiveSlot {
	if m == nil {
		return nil
	}
	snap, _ := m.published.Load().(map[string]decisionscope.LiveSlot)
	return snap
}

// seedPublished writes one decision onto the published map without a tick.
func (m *memory) seedPublished(item Decision) {
	if m == nil {
		return
	}
	key, _ := slotKeys(item.Scope, item.Value)
	if key == "" {
		return
	}
	payload := m.pack(item.Kind, item.Origin)
	prev := m.publishedMap()
	next := make(map[string]decisionscope.LiveSlot, len(prev)+1)
	for slotKey, slot := range prev {
		next[slotKey] = slot
	}
	next[key] = decisionscope.LiveSlotFromPack(payload, item.DurationSec)
	m.published.Store(next)
}
