// Package decisionstore is the reclaimed holder of CrowdSec decisions.
// Stream/alone Ip and header-scope slots are a memory copy-on-write map or Redis
// via cache.Client. That same cache.Client is the range-index, stream lease, and
// live/none memo — not a second stream of Ip keys.
package decisionstore

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// backend holds stream/alone Ip and header-scope slots. Redis writes those keys
// through cache.Client; memory uses a copy-on-write LiveSlot map. Range, lease,
// and live memo stay on Store.cache, not on this interface.
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
	// Memory writes tick (BeginTick must have run) and packs a uint32 word when intern succeeds.
	// Redis is cache.Set of a leftover kind+origin string with that TTL.
	Put(item Decision)
	// Delete drops the canonical slot for scope+value. For Ip, a prior spelling of the same
	// address is deleted too so a lift cannot survive under the old key.
	// Memory deletes from tick. Redis is cache.Delete.
	Delete(scope, value string)
	// LookupRemediation is the request path: Ip slot, then header scopes, then Range.
	// Memory reads the published map. Redis reads cache.Client.
	// Returns kind, leftover origin name, intern origin id, or cache.ErrMiss.
	LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error)
}

// Store is one reclaim value: intern table, cache.Client, and the stream/alone slot backend.
type Store struct {
	backend
	cache   *cache.Client
	origins *intern.Table
}

// NewMemory is in-process COW slots. cacheClient is lease, range-index, and live memo.
func NewMemory(cacheClient *cache.Client, log *slog.Logger) *Store {
	origins := intern.New()
	return &Store{
		backend: newMemory(log, origins),
		cache:   cacheClient,
		origins: origins,
	}
}

// NewRedis stores stream/alone slots on cacheClient (Redis-protocol prefix).
func NewRedis(cacheClient *cache.Client) *Store {
	return &Store{
		backend: newRedis(cacheClient),
		cache:   cacheClient,
		origins: intern.New(),
	}
}

// Open reclaims one Store per reclaimKey. cachePrefix is the Redis/memory key prefix.
func Open(ctx context.Context, reclaimKey, cachePrefix string, cfg *configuration.Config, log *slog.Logger) (*Store, error) {
	stored, err := reclaim.OpenWithHooks(ctx, reclaimKey, log, func() (any, reclaim.Hooks, error) {
		cacheClient := &cache.Client{}
		cacheClient.New(
			log,
			cfg.RedisCacheEnabled,
			cfg.RedisCacheHost,
			cfg.RedisCacheReadHosts,
			cfg.RedisCachePassword,
			cfg.RedisCacheDatabase,
			cachePrefix,
		)
		var store *Store
		if cfg.RedisCacheEnabled {
			store = NewRedis(cacheClient)
		} else {
			store = NewMemory(cacheClient, log)
		}
		return store, reclaim.Hooks{Close: store.close}, nil
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

// close drains the cache Redis pool. Memory is a no-op. Reclaim last-holder hook.
func (s *Store) close() {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.Close()
}

// TryLease tries to own the stream-poll key for duration seconds.
func (s *Store) TryLease(ctx context.Context, key, value string, duration int64) (bool, error) {
	if s == nil || s.cache == nil {
		return false, cache.ErrUnreachable
	}
	return s.cache.Acquire(ctx, key, value, duration)
}

// DropLease deletes the stream-poll lease key so the next tick can retry immediately.
func (s *Store) DropLease(key string) {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.Delete(key)
}

// RangeIndex is the shared Range blob, or a miss when no index has been written.
func (s *Store) RangeIndex() (string, error) {
	if s == nil || s.cache == nil {
		return "", cache.ErrMiss
	}
	return s.cache.Get(decisionscope.RangeIndexKey)
}

// ApplyRangeBatch upserts and removes Range CIDRs on the shared index.
func (s *Store) ApplyRangeBatch(upserts map[string]string, removals []string) error {
	if s == nil || s.cache == nil {
		return cache.ErrMiss
	}
	return decisionscope.ApplyRangeBatch(s.cache, upserts, removals)
}

// Memo writes a live/none TTL slot (not a stream/alone COW slot).
func (s *Store) Memo(key string, payload any, durationSec int64) {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.Set(key, payload, durationSec)
}

// LookupCached is the live/none request path: Ip, header scopes, then Range on cache.Client.
func (s *Store) LookupCached(remoteIP string, ipAddr net.IP, scopes map[string]string, membership *decisionscope.RangeMembership) (string, string, uint16, error) {
	if s == nil || s.cache == nil {
		return "", "", 0, cache.ErrMiss
	}
	return decisionscope.LookupCachedRemediation(s.cache, remoteIP, ipAddr, scopes, membership)
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

// CacheForTest is the TTL/Redis pool. Tests only.
func (s *Store) CacheForTest() *cache.Client {
	if s == nil {
		return nil
	}
	return s.cache
}

// FillUntilMaxForTest fills the intern table so the next OriginID overflows. Tests only.
func (s *Store) FillUntilMaxForTest() {
	if s == nil {
		return
	}
	s.origins.FillUntilMaxForTest()
}

// SeedSlotForTest publishes one memory slot without a tick. Redis Put goes to cache.
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
