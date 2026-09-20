package lapi

import (
	"log/slog"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

const decisionStoreKeyPrefix = "decisionstore:"

// storeParams is the Redis location hashed into StoreKey (composition helper).
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

// StoreKey is a composition helper: CrowdSec cursor SessionHex plus Redis store parameters.
// It is not a sibling reclaim Open for this Client’s store.
func StoreKey(cfg *configuration.Config) string {
	return decisionStoreKeyPrefix + SessionHex(cfg) + ":" + hashJSON(storeParamsFrom(cfg))
}

// newChildStore constructs the Client’s DecisionStore. Redis keys stay under SessionHex.
func newChildStore(cfg *configuration.Config, log *slog.Logger) *decisionstore.Store {
	if cfg.RedisCacheEnabled {
		return decisionstore.NewRedis(
			log,
			cfg.RedisCacheHost,
			cfg.RedisCacheReadHosts,
			cfg.RedisCachePassword,
			cfg.RedisCacheDatabase,
			SessionHex(cfg),
		)
	}
	return decisionstore.NewMemory(log)
}
