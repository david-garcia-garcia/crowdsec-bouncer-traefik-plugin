// Package decisionstore is the reclaimed holder of CrowdSec decisions.
// Stream/alone and live/none Ip and header-scope slots are a memory copy-on-write map
// or Redis via SimpleRedis. Range is ApplyRangeBatch on the same backend.
package decisionstore

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// backend holds Ip, header-scope, and Range decisions. Redis writes those keys through
// SimpleRedis; memory uses a copy-on-write LiveSlot map plus an in-process range blob.
type backend interface {
	// BeginTick opens the write window for one stream poll.
	// Memory clones the published map into tick so Put/Delete mutate a private copy
	// while lookups still read the previous published map.
	// Redis is a no-op: each Set/Delete is already visible to other processes.
	BeginTick()
	// PublishTick closes that window.
	// Memory drops slots whose expiresAt is at or before now, publishes tick as the
	// lookup map, and clears tick.
	// Redis is a no-op: key TTL is the expiry.
	PublishTick(now int64)
	// Put stores one Ip or header-scope decision for DurationSec seconds.
	// Memory writes tick when a stream window is open, else the published map (live).
	// Redis is a leftover kind+origin string SET with that TTL.
	Put(item Decision)
	// Delete drops the canonical slot for scope+value. For Ip, a prior spelling of the same
	// address is deleted too so a lift cannot survive under the old key.
	// Memory deletes from tick or the published map. Redis is DEL.
	Delete(scope, value string)
	// LookupRemediation is the request path: Ip slot, then header scopes, then Range.
	// Memory reads the published map. Redis reads SimpleRedis.
	// Returns kind, leftover origin name, intern origin id, or ErrMiss.
	LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error)
	// ApplyRangeBatch upserts and removes Range CIDRs on this backend's index.
	ApplyRangeBatch(upserts map[string]string, removals []string) error
	// RangeIndex is the Range blob, or empty when none has been written.
	RangeIndex() (string, error)
	close()
}

// Store is one reclaim value: intern table, Range membership, and the decision backend.
type Store struct {
	backend
	origins         *intern.Table
	rangeMembership atomic.Value // *decisionscope.RangeMembership
	lastRangeIndex  atomic.Value // string of the blob last used to build membership
}

// NewMemory is in-process COW slots and an in-process Range blob.
func NewMemory(log *slog.Logger) *Store {
	origins := intern.New()
	return &Store{
		backend: newMemory(log, origins),
		origins: origins,
	}
}

// NewRedis stores Ip, header-scope, and Range on Redis (keyPrefix namespaces keys).
func NewRedis(log *slog.Logger, writeHost string, readHosts []string, pass, database, keyPrefix string) *Store {
	return &Store{
		backend: newRedis(log, writeHost, readHosts, pass, database, keyPrefix),
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
	table       *intern.Table
	packsMemory bool
}

// Intern appends an origin name. Empty name is id 0. Overflow does not wrap.
func (o originIntern) Intern(name string) (uint16, bool) {
	if o.table == nil {
		return 0, false
	}
	return o.table.ID(name)
}

// PacksMemory is true when this backend may pack remediations as uint32 words.
func (o originIntern) PacksMemory() bool {
	return o.packsMemory
}

// Put stores one Ip or header-scope decision. Range is ignored (use ApplyRangeBatch).
func (s *Store) Put(item Decision) {
	if s == nil || s.backend == nil {
		return
	}
	s.backend.Put(item)
}

// Delete drops the canonical slot for scope+value, and a prior Ip spelling when it differs.
func (s *Store) Delete(scope, value string) {
	if s == nil || s.backend == nil {
		return
	}
	s.backend.Delete(scope, value)
}

// LookupRemediation is the request path for stream/alone and live/none.
func (s *Store) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (string, string, uint16, error) {
	if s == nil || s.backend == nil {
		return "", "", 0, ErrMiss
	}
	return s.backend.LookupRemediation(remoteIP, ipAddr, scopes, s.RangeMembership())
}

// Close drains the Redis pool. Memory is a no-op. Reclaim last-holder hook.
func (s *Store) Close() {
	if s == nil || s.backend == nil {
		return
	}
	s.backend.close()
}

// RangeIndex is the Range blob, or empty when none has been written.
func (s *Store) RangeIndex() (string, error) {
	if s == nil || s.backend == nil {
		return "", ErrMiss
	}
	return s.backend.RangeIndex()
}

// ApplyRangeBatch upserts and removes Range CIDRs, then rebuilds in-process membership.
func (s *Store) ApplyRangeBatch(upserts map[string]string, removals []string) error {
	if s == nil || s.backend == nil {
		return ErrMiss
	}
	if err := s.backend.ApplyRangeBatch(upserts, removals); err != nil {
		return err
	}
	s.HydrateRange()
	return nil
}

// RangeMembership is the current in-process Range lookup, or nil before the first hydrate.
func (s *Store) RangeMembership() *decisionscope.RangeMembership {
	if s == nil {
		return nil
	}
	stored := s.rangeMembership.Load()
	if stored == nil {
		return nil
	}
	membership, _ := stored.(*decisionscope.RangeMembership)
	return membership
}

// HydrateRange rebuilds Range membership from the stored blob. A read that did not answer keeps the last trees.
func (s *Store) HydrateRange() {
	if s == nil || s.backend == nil {
		return
	}
	index, err := s.backend.RangeIndex()
	if err != nil {
		return
	}
	previous, _ := s.lastRangeIndex.Load().(string)
	if s.rangeMembership.Load() != nil && previous == index {
		return
	}
	s.rangeMembership.Store(decisionscope.MembershipFromIndex(index))
	s.lastRangeIndex.Store(index)
}

// OriginID appends an origin name for metrics. Empty name is id 0. Overflow does not wrap.
func (s *Store) OriginID(name string) (uint16, bool) {
	if s == nil {
		return 0, false
	}
	return s.origins.ID(name)
}

// OriginName is the interned origin for id. Lock-free. Unknown id is empty.
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
	if s == nil || s.backend == nil {
		return
	}
	mem, ok := s.backend.(*memory)
	if !ok {
		s.backend.Put(item)
		return
	}
	mem.seedPublished(item)
}

// PublishedMemoryMapForTest is the published memory map. Nil when the store is Redis.
func (s *Store) PublishedMemoryMapForTest() map[string]decisionscope.LiveSlot {
	if s == nil {
		return nil
	}
	mem, ok := s.backend.(*memory)
	if !ok {
		return nil
	}
	return mem.publishedMap()
}
