package lapi

import (
	"context"
	"fmt"
	"log/slog"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
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
	cache   *cache.Client
	log     *slog.Logger
	origins *originDictionary
}

// Cache is the map or Redis pool this store owns.
func (s *DecisionStore) Cache() *cache.Client {
	if s == nil {
		return nil
	}
	return s.cache
}

// InternOrigin assigns or reuses a uint16 id for a MetricsOrigin name on this store.
func (s *DecisionStore) InternOrigin(name string) (uint16, bool) {
	if s == nil || s.origins == nil {
		return 0, false
	}
	return s.origins.InternOrigin(name)
}

// OriginName is the interned MetricsOrigin for id, or empty. Lock-free after intern publishes.
func (s *DecisionStore) OriginName(id uint16) string {
	if s == nil || s.origins == nil {
		return ""
	}
	return s.origins.OriginName(id)
}

// RemediationStored interns origin and packs kind plus id, or keeps the leftover string path.
func (s *DecisionStore) RemediationStored(kind, origin string) cache.Stored {
	if s == nil {
		return cache.Leftover(cache.RemediationWithOrigin(kind, origin))
	}
	if origin == "" {
		return cache.Leftover(kind)
	}
	id, interned := s.InternOrigin(origin)
	if !interned {
		return cache.Leftover(cache.RemediationWithOrigin(kind, origin))
	}
	return cache.Packed(kind, id)
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
		store := &DecisionStore{cache: cacheClient, log: log, origins: newOriginDictionary(log)}
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
