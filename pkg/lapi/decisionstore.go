package lapi

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

const decisionStoreKeyPrefix = "decisionstore:"

// storeParams is the Redis location hashed into the DecisionStore reclaim key.
type storeParams struct {
	RedisCacheEnabled   bool     `json:"redisCacheEnabled"`
	RedisCacheHost      string   `json:"redisCacheHost"`
	RedisCacheReadHosts []string `json:"redisCacheReadHosts"`
	RedisCachePassword  string   `json:"redisCachePassword"`
	RedisCacheDatabase  string   `json:"redisCacheDatabase"`
}

// storeParamsFrom copies Redis store fields off cfg. Call after Prepare (password is resolved there).
func storeParamsFrom(cfg *configuration.Config) storeParams {
	return storeParams{
		RedisCacheEnabled:   cfg.RedisCacheEnabled,
		RedisCacheHost:      cfg.RedisCacheHost,
		RedisCacheReadHosts: cfg.RedisCacheReadHosts,
		RedisCachePassword:  cfg.RedisCachePassword,
		RedisCacheDatabase:  cfg.RedisCacheDatabase,
	}
}

// StoreKey is the reclaim table key: CrowdSec cursor SessionHex plus Redis store parameters.
func StoreKey(cfg *configuration.Config) string {
	return decisionStoreKeyPrefix + SessionHex(cfg) + ":" + hashJSON(storeParamsFrom(cfg))
}

// DecisionStore is a reclaim value that owns one cache.Client (memory TTL or Redis-protocol prefix).
type DecisionStore struct {
	cache       *cache.Client
	redisBacked bool

	internMu sync.Mutex
	// internNames is []string with index 0 unused. atomic.Value not atomic.Pointer[T] (Yaegi v0.16).
	internNames atomic.Value
}

// Cache is the map or Redis pool this store owns.
func (s *DecisionStore) Cache() *cache.Client {
	if s == nil {
		return nil
	}
	return s.cache
}

// Close drains the cache Redis pool. Memory is a no-op.
// Safe to call more than once: cache.Client.Close is nil-safe and SimpleRedis.Close CAS-gates.
func (s *DecisionStore) Close() {
	if s == nil || s.cache == nil {
		return
	}
	s.cache.Close()
}

// OpenDecisionStore reclaims one store per cursor plus Redis params on the Traefik New context.
func OpenDecisionStore(ctx context.Context, cfg *configuration.Config, log *slog.Logger) (*DecisionStore, error) {
	stored, err := reclaim.OpenWithHooks(ctx, StoreKey(cfg), log, func() (any, reclaim.Hooks, error) {
		cacheClient := &cache.Client{}
		// Prefix is SessionHex for every mode so live interval splits share remediations.
		cacheClient.New(
			log,
			cfg.RedisCacheEnabled,
			cfg.RedisCacheHost,
			cfg.RedisCacheReadHosts,
			cfg.RedisCachePassword,
			cfg.RedisCacheDatabase,
			SessionHex(cfg),
		)
		store := &DecisionStore{cache: cacheClient, redisBacked: cfg.RedisCacheEnabled}
		store.internNames.Store([]string{""})
		return store, reclaim.Hooks{Close: store.Close}, nil
	})
	if err != nil {
		return nil, err
	}
	store, ok := stored.(*DecisionStore)
	if !ok {
		return nil, fmt.Errorf("reclaim: want *lapi.DecisionStore, got %T", stored)
	}
	return store, nil
}

// internNamesSnapshot is the lock-free name table. Index 0 is unused.
func (s *DecisionStore) internNamesSnapshot() []string {
	if s == nil {
		return nil
	}
	names, _ := s.internNames.Load().([]string)
	return names
}

// lookupIntern finds an already interned origin on the snapshot.
func (s *DecisionStore) lookupIntern(name string) (uint16, bool) {
	for id, existing := range s.internNamesSnapshot() {
		if id == 0 || existing != name {
			continue
		}
		return uint16(id), true //nolint:gosec // G115 intern snapshot index is capped at 65535
	}
	return 0, false
}

// PacksMemory is true when this store may pack remediations as uint32 words.
func (s *DecisionStore) PacksMemory() bool {
	return s != nil && !s.redisBacked
}

// Intern appends an origin name. Empty name is id 0. Overflow does not wrap.
func (s *DecisionStore) Intern(name string) (uint16, bool) {
	if s == nil {
		return 0, false
	}
	if name == "" {
		return 0, true
	}
	if id, ok := s.lookupIntern(name); ok {
		return id, true
	}
	s.internMu.Lock()
	defer s.internMu.Unlock()
	if id, ok := s.lookupIntern(name); ok {
		return id, true
	}
	names := s.internNamesSnapshot()
	if names == nil {
		names = []string{""}
	}
	if len(names) > 65535 {
		return 0, false
	}
	next := make([]string, len(names)+1)
	copy(next, names)
	next[len(names)] = name
	id := uint16(len(names)) //nolint:gosec // G115 overflow returns before append past 65535
	s.internNames.Store(next)
	return id, true
}

// OriginName is the interned origin for id. Lock-free. Unknown id is empty.
func (s *DecisionStore) OriginName(id uint16) string {
	if id == 0 {
		return ""
	}
	names := s.internNamesSnapshot()
	if int(id) >= len(names) {
		return ""
	}
	return names[id]
}
