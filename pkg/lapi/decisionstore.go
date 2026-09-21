package lapi

import (
	"context"
	"log/slog"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

const decisionStoreKeyPrefix = "decisionstore:"

// storeParams is the Redis location hashed into the LAPI Client reclaim key.
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

// StoreKey is the reclaim table key: CrowdSec cursor SessionHex only.
func StoreKey(cfg *configuration.Config) string {
	return decisionStoreKeyPrefix + SessionHex(cfg)
}

// OpenDecisionStore reclaims one store per SessionHex on the Traefik New context.
// name is Traefik New(..., name); create() writes it write-once as createdBy.
func OpenDecisionStore(ctx context.Context, cfg *configuration.Config, log *slog.Logger, name string) (*decisionstore.Store, error) {
	return decisionstore.Open(ctx, StoreKey(cfg), SessionHex(cfg), cfg, log, name)
}
