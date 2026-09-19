// Package decisionstore is the reclaimed holder of CrowdSec decisions.
// Stream/alone and live/none Ip and header-scope slots are a memory copy-on-write map
// or Redis via SimpleRedis. Range is ApplyRangeBatch on the same engine.
package decisionstore

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// Store is one reclaim value: intern table, Range membership, and the decision engine.
// Memory and Redis are concrete fields: Yaegi v0.16 panics putting a map-holding struct in an interface.
type Store struct {
	mem             *memory
	red             *redis
	origins         *intern.Table
	rangeMembership atomic.Value // *RangeMembership
	lastRangeIndex  atomic.Value // string of the blob last used to build membership
}

// NewMemory is in-process COW slots and an in-process Range blob.
func NewMemory(log *slog.Logger) *Store {
	origins := intern.New()
	return &Store{
		mem:     newMemory(log, origins),
		origins: origins,
	}
}

// NewRedis stores Ip, header-scope, and Range on Redis (keyPrefix namespaces keys).
func NewRedis(log *slog.Logger, writeHost string, readHosts []string, pass, database, keyPrefix string) *Store {
	return &Store{
		red:     newRedis(log, writeHost, readHosts, pass, database, keyPrefix),
		origins: intern.New(),
	}
}

// Open reclaims one Store per reclaimKey. cachePrefix is the Redis key prefix.
func Open(ctx context.Context, reclaimKey, cachePrefix string, cfg *configuration.Config, log *slog.Logger) (*Store, error) {
	stored, err := reclaim.OpenWithHooks(ctx, reclaimKey, log, func() (any, reclaim.Hooks, error) {
		var store *Store
		if cfg.RedisCacheEnabled {
			store = NewRedis(
				log,
				cfg.RedisCacheHost,
				cfg.RedisCacheReadHosts,
				cfg.RedisCachePassword,
				cfg.RedisCacheDatabase,
				cachePrefix,
			)
		} else {
			store = NewMemory(log)
		}
		return store, reclaim.Hooks{Close: store.Close}, nil
	})
	if err != nil {
		return nil, err
	}
	store, ok := stored.(*Store)
	if !ok {
		return nil, fmt.Errorf("reclaim: want *decisionstore.Store, got %T", stored)
	}
	return store, nil
}

// originIntern packs memory words without exporting intern on Store.
type originIntern struct {
	table *intern.Table
}

// Intern appends an origin name. Empty name is id 0. Overflow does not wrap.
func (o originIntern) Intern(name string) (uint16, bool) {
	if o.table == nil {
		return 0, false
	}
	return o.table.ID(name)
}

// BeginTick opens the write window for one stream poll. Memory clones published into tick.
// Redis is a no-op: each Set/Delete is already visible to other processes.
func (s *Store) BeginTick() {
	if s != nil && s.mem != nil {
		s.mem.BeginTick()
	}
}

// PublishTick closes that window. Memory drops expired tick slots and publishes tick.
// Redis is a no-op: key TTL is the expiry.
func (s *Store) PublishTick(now int64) {
	if s != nil && s.mem != nil {
		s.mem.PublishTick(now)
	}
}

// Put stores one Ip or header-scope decision. Range is ignored (use ApplyRangeBatch).
func (s *Store) Put(item Decision) {
	if s == nil {
		return
	}
	if s.mem != nil {
		s.mem.Put(item)
		return
	}
	if s.red != nil {
		s.red.Put(item)
	}
}

// Delete drops the canonical slot for scope+value, and a prior Ip spelling when it differs.
func (s *Store) Delete(scope, value string) {
	if s == nil {
		return
	}
	if s.mem != nil {
		s.mem.Delete(scope, value)
		return
	}
	if s.red != nil {
		s.red.Delete(scope, value)
	}
}

// LookupRemediation is the request path for stream/alone and live/none.
func (s *Store) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (string, string, uint16, error) {
	if s == nil {
		return "", "", 0, ErrMiss
	}
	membership := s.RangeMembership()
	if s.mem != nil {
		return s.mem.LookupRemediation(remoteIP, ipAddr, scopes, membership)
	}
	if s.red != nil {
		return s.red.LookupRemediation(remoteIP, ipAddr, scopes, membership)
	}
	return "", "", 0, ErrMiss
}

// Close drains the Redis pool. Memory is a no-op. Reclaim last-holder hook.
func (s *Store) Close() {
	if s != nil && s.red != nil {
		s.red.close()
	}
}

// RangeIndex is the Range blob, or empty when none has been written.
func (s *Store) RangeIndex() (string, error) {
	if s == nil {
		return "", ErrMiss
	}
	if s.mem != nil {
		return s.mem.RangeIndex()
	}
	if s.red != nil {
		return s.red.RangeIndex()
	}
	return "", ErrMiss
}

// ApplyRangeBatch upserts and removes Range CIDRs, then rebuilds in-process membership.
func (s *Store) ApplyRangeBatch(upserts map[string]string, removals []string) error {
	if s == nil {
		return ErrMiss
	}
	var err error
	switch {
	case s.mem != nil:
		err = s.mem.ApplyRangeBatch(upserts, removals)
	case s.red != nil:
		err = s.red.ApplyRangeBatch(upserts, removals)
	default:
		return ErrMiss
	}
	if err != nil {
		return err
	}
	s.HydrateRange()
	return nil
}

// RangeMembership is the current in-process Range lookup, or nil before the first hydrate.
func (s *Store) RangeMembership() *RangeMembership {
	if s == nil {
		return nil
	}
	stored := s.rangeMembership.Load()
	if stored == nil {
		return nil
	}
	membership, _ := stored.(*RangeMembership)
	return membership
}

// HydrateRange rebuilds Range membership from the stored blob. A read that did not answer keeps the last trees.
func (s *Store) HydrateRange() {
	if s == nil {
		return
	}
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
	if s == nil {
		return 0, false
	}
	return s.origins.ID(name)
}

// OriginName is the interned origin for id. Unknown id is empty.
func (s *Store) OriginName(id uint16) string {
	if s == nil {
		return ""
	}
	return s.origins.Name(id)
}

// FillUntilMaxForTest fills the intern table so the next OriginID overflows. Tests only.
func (s *Store) FillUntilMaxForTest() {
	if s == nil {
		return
	}
	s.origins.FillUntilMaxForTest()
}

// SeedSlotForTest publishes one memory slot without a tick. Redis Put goes to Redis.
func (s *Store) SeedSlotForTest(item Decision) {
	if s == nil {
		return
	}
	if s.mem != nil {
		s.mem.seedPublished(item)
		return
	}
	s.Put(item)
}

// PublishedMemoryMapForTest is the published memory map. Nil when the store is Redis.
func (s *Store) PublishedMemoryMapForTest() map[string]LiveSlot {
	if s == nil || s.mem == nil {
		return nil
	}
	return s.mem.publishedMap()
}
