// Package decisionstore holds CrowdSec decisions for one LAPI Client.
// Stream/alone and live/none Ip and header-scope slots are a memory copy-on-write map
// or Redis via SimpleRedis. Range is ApplyRangeBatch on the same engine.
package decisionstore

import (
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

// engine is the slot and Range ops bound at NewMemory or NewRedis.
// Funcs, not an interface: Yaegi v0.16 panics putting a map-holding *memory in an interface.
type engine struct {
	beginTick   func()
	publishTick func(int64)
	put         func(Decision)
	deleteSlot  func(string, string)
	lookup      func(string, net.IP, map[string]string, *RangeMembership) (string, string, uint16, error)
	applyRange  func(map[string]string, []string) error
	rangeIndex  func() (string, error)
	close       func()
}

// memoryEngine binds *memory methods into engine funcs.
func memoryEngine(mem *memory) engine {
	return engine{
		beginTick:   mem.BeginTick,
		publishTick: mem.PublishTick,
		put:         mem.Put,
		deleteSlot:  mem.Delete,
		lookup:      mem.LookupRemediation,
		applyRange:  mem.ApplyRangeBatch,
		rangeIndex:  mem.RangeIndex,
		close:       func() {},
	}
}

// redisEngine binds *redis methods into engine funcs.
func redisEngine(red *redis) engine {
	return engine{
		beginTick:   red.BeginTick,
		publishTick: red.PublishTick,
		put:         red.Put,
		deleteSlot:  red.Delete,
		lookup:      red.LookupRemediation,
		applyRange:  red.ApplyRangeBatch,
		rangeIndex:  red.RangeIndex,
		close:       red.close,
	}
}

// Store is intern table, Range membership, and the decision engine for one Client.
type Store struct {
	engine          engine
	mem             *memory
	red             *redis
	origins         *intern.Table
	rangeMembership atomic.Value // *RangeMembership
	lastRangeIndex  atomic.Value // string of the blob last used to build membership
}

// NewMemory is in-process COW slots and an in-process Range blob.
func NewMemory(log *slog.Logger) *Store {
	origins := intern.New()
	mem := newMemory(log, origins)
	return &Store{
		engine:  memoryEngine(mem),
		mem:     mem,
		origins: origins,
	}
}

// NewRedis stores Ip, header-scope, and Range on Redis (keyPrefix namespaces keys).
func NewRedis(log *slog.Logger, writeHost string, readHosts []string, pass, database, keyPrefix string) *Store {
	red := newRedis(log, writeHost, readHosts, pass, database, keyPrefix)
	return &Store{
		engine:  redisEngine(red),
		red:     red,
		origins: intern.New(),
	}
}

// BeginTick opens the write window for one stream poll. Memory clones published into tick.
// Redis is a no-op: each Set/Delete is already visible to other processes.
func (s *Store) BeginTick() {
	s.engine.beginTick()
}

// PublishTick closes that window. Memory drops expired tick slots and publishes tick.
// Redis is a no-op: key TTL is the expiry.
func (s *Store) PublishTick(now int64) {
	s.engine.publishTick(now)
}

// Put stores one Ip or header-scope decision. Range is ignored (use ApplyRangeBatch).
func (s *Store) Put(item Decision) {
	s.engine.put(item)
}

// Delete drops the canonical slot for scope+value, and a prior Ip spelling when it differs.
func (s *Store) Delete(scope, value string) {
	s.engine.deleteSlot(scope, value)
}

// LookupRemediation is the request path for stream/alone and live/none.
func (s *Store) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (string, string, uint16, error) {
	return s.engine.lookup(remoteIP, ipAddr, scopes, s.RangeMembership())
}

// Close drains the Redis pool. Memory is a no-op. Client Close hook.
func (s *Store) Close() {
	s.engine.close()
}

// RangeIndex is the Range blob, or empty when none has been written.
func (s *Store) RangeIndex() (string, error) {
	return s.engine.rangeIndex()
}

// ApplyRangeBatch upserts and removes Range CIDRs, then rebuilds in-process membership.
func (s *Store) ApplyRangeBatch(upserts map[string]string, removals []string) error {
	if err := s.engine.applyRange(upserts, removals); err != nil {
		return err
	}
	s.HydrateRange()
	return nil
}

// RangeMembership is the current in-process Range lookup, or nil before the first hydrate.
func (s *Store) RangeMembership() *RangeMembership {
	membership := s.rangeMembership.Load()
	if membership == nil {
		return nil
	}
	membershipTyped, _ := membership.(*RangeMembership)
	return membershipTyped
}

// HydrateRange rebuilds Range membership from the stored blob. A read that did not answer keeps the last trees.
func (s *Store) HydrateRange() {
	index, err := s.RangeIndex()
	if err != nil {
		return
	}
	previous, _ := s.lastRangeIndex.Load().(string)
	if s.rangeMembership.Load() != nil && previous == index {
		return
	}
	s.rangeMembership.Store(MembershipFromIndex(index))
	s.lastRangeIndex.Store(index)
}

// OriginID appends an origin name for metrics. Empty name is id 0. Overflow does not wrap.
func (s *Store) OriginID(name string) (uint16, bool) {
	return s.origins.ID(name)
}

// OriginName is the interned origin for id. Unknown id is empty.
func (s *Store) OriginName(id uint16) string {
	return s.origins.Name(id)
}

// FillUntilMaxForTest fills the intern table so the next OriginID overflows. Tests only.
func (s *Store) FillUntilMaxForTest() {
	s.origins.FillUntilMaxForTest()
}

// SeedSlotForTest publishes one memory slot without a tick. Redis Put goes to Redis.
func (s *Store) SeedSlotForTest(item Decision) {
	if s.mem != nil {
		s.mem.seedPublished(item)
		return
	}
	s.Put(item)
}

// PublishedMemoryMapForTest is the published memory map. Nil when the store is Redis.
func (s *Store) PublishedMemoryMapForTest() map[string]LiveSlot {
	if s.mem == nil {
		return nil
	}
	return s.mem.publishedMap()
}
