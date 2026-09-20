package lapi

import (
	"context"
	"log/slog"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
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

// OpenDecisionStore reclaims one store per cursor plus Redis params on the Traefik New context.
func OpenDecisionStore(ctx context.Context, cfg *configuration.Config, log *slog.Logger) (*decisionstore.Store, error) {
	return decisionstore.Open(ctx, StoreKey(cfg), SessionHex(cfg), cfg, log, countActiveFromMode(cfg.CrowdsecMode))
}

// countActiveFromMode is true only for stream and alone so live/none memo Put cannot increment.
func countActiveFromMode(mode string) bool {
	return mode == configuration.StreamMode || mode == configuration.AloneMode
}
