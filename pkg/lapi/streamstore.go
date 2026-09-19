package lapi

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// streamStore holds stream/alone Ip and header-scope slots (Redis cache or memory COW map).
type streamStore interface {
	BeginTick()
	PublishTick(now int64)
	Put(key string, payload any, durationSec int64)
	Delete(key, legacyKey string)
	LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error)
}

func (s *DecisionStore) initStreamStore(log *slog.Logger) {
	if s == nil {
		return
	}
	if s.redisBacked {
		s.stream = &redisStreamStore{cache: s.cache}
		return
	}
	s.stream = &memoryStreamStore{owner: s, log: log}
}

func (s *DecisionStore) beginStreamTick() {
	if s == nil || s.stream == nil {
		return
	}
	s.stream.BeginTick()
}

func (s *DecisionStore) publishStreamTick() {
	if s == nil || s.stream == nil {
		return
	}
	s.stream.PublishTick(time.Now().Unix())
}

func (s *DecisionStore) putStreamSlot(key string, payload any, durationSec int64) {
	if s == nil || s.stream == nil {
		return
	}
	s.stream.Put(key, payload, durationSec)
}

func (s *DecisionStore) deleteStreamSlot(key, legacyKey string) {
	if s == nil || s.stream == nil {
		return
	}
	s.stream.Delete(key, legacyKey)
}

func (s *DecisionStore) lookupStreamRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error) {
	if s == nil || s.stream == nil {
		return "", "", 0, cache.ErrMiss
	}
	return s.stream.LookupRemediation(remoteIP, ipAddr, scopes, membership)
}

type redisStreamStore struct {
	cache *cache.Client
}

func (r *redisStreamStore) BeginTick() {}
func (r *redisStreamStore) PublishTick(int64) {}

func (r *redisStreamStore) Put(key string, payload any, durationSec int64) {
	if r == nil || r.cache == nil {
		return
	}
	r.cache.Set(key, payload, durationSec)
}

func (r *redisStreamStore) Delete(key, legacyKey string) {
	if r == nil || r.cache == nil {
		return
	}
	r.cache.Delete(key)
	if legacyKey != "" && legacyKey != key {
		r.cache.Delete(legacyKey)
	}
}

func (r *redisStreamStore) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error) {
	if r == nil || r.cache == nil {
		return "", "", 0, cache.ErrMiss
	}
	return decisionscope.LookupCachedRemediation(r.cache, remoteIP, ipAddr, scopes, membership)
}

type memoryStreamStore struct {
	owner *DecisionStore
	log   *slog.Logger
	tick  map[string]decisionscope.LiveSlot
	published atomic.Value // map[string]decisionscope.LiveSlot
}

func (m *memoryStreamStore) BeginTick() {
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

func (m *memoryStreamStore) PublishTick(now int64) {
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

func (m *memoryStreamStore) Put(key string, payload any, durationSec int64) {
	if m == nil || m.tick == nil || key == "" {
		return
	}
	m.tick[key] = memoryLiveSlot(m.log, payload, durationSec)
}

func (m *memoryStreamStore) Delete(key, legacyKey string) {
	if m == nil || m.tick == nil {
		return
	}
	delete(m.tick, key)
	if legacyKey != "" && legacyKey != key {
		delete(m.tick, legacyKey)
	}
}

func (m *memoryStreamStore) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error) {
	if m == nil {
		return "", "", 0, cache.ErrMiss
	}
	snap, _ := m.published.Load().(map[string]decisionscope.LiveSlot)
	return decisionscope.LookupStreamMapRemediation(snap, remoteIP, ipAddr, scopes, membership)
}

func memoryLiveSlot(log *slog.Logger, payload any, durationSec int64) decisionscope.LiveSlot {
	expiresAt := time.Now().Unix() + durationSec
	switch stored := payload.(type) {
	case uint32:
		return decisionscope.LiveSlot{Word: stored, ExpiresAt: expiresAt}
	case string:
		if log != nil {
			log.Warn("streamStore:intern overflow", "kind", decisionscope.RemediationKind(stored))
		}
		kind := decisionscope.RemediationKind(stored)
		return decisionscope.LiveSlot{Word: packKindOnlyWord(kind), ExpiresAt: expiresAt}
	default:
		return decisionscope.LiveSlot{ExpiresAt: expiresAt}
	}
}

func packKindOnlyWord(kind string) uint32 {
	if kind == "" {
		return 0
	}
	return uint32(kind[0])
}

// seedStreamSlotForTest publishes one memory stream slot without a tick (tests only).
func (s *DecisionStore) seedStreamSlotForTest(key string, payload any, durationSec int64) {
	if s == nil || s.stream == nil {
		return
	}
	mem, ok := s.stream.(*memoryStreamStore)
	if !ok {
		s.stream.Put(key, payload, durationSec)
		return
	}
	prev, _ := mem.published.Load().(map[string]decisionscope.LiveSlot)
	next := make(map[string]decisionscope.LiveSlot, len(prev)+1)
	for k, slot := range prev {
		next[k] = slot
	}
	next[key] = memoryLiveSlot(nil, payload, durationSec)
	mem.published.Store(next)
}

// streamMapForTest returns the published memory map (tests only).
func (s *DecisionStore) streamMapForTest() map[string]decisionscope.LiveSlot {
	if s == nil || s.stream == nil {
		return nil
	}
	mem, ok := s.stream.(*memoryStreamStore)
	if !ok {
		return nil
	}
	snap, _ := mem.published.Load().(map[string]decisionscope.LiveSlot)
	return snap
}
