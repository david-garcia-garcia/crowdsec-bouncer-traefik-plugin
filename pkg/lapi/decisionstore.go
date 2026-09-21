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
	LapiRedisEnabled   bool     `json:"lapiRedisEnabled"`
	LapiRedisHost      string   `json:"lapiRedisHost"`
	LapiRedisReadHosts []string `json:"lapiRedisReadHosts"`
	LapiRedisPassword  string   `json:"lapiRedisPassword"`
	LapiRedisDatabase  string   `json:"lapiRedisDatabase"`
}

// storeParamsFrom copies Redis store fields off cfg. Call after Prepare (password is resolved there).
func storeParamsFrom(cfg *configuration.Config) storeParams {
	return storeParams{
		LapiRedisEnabled:   cfg.LapiRedisEnabled,
		LapiRedisHost:      cfg.LapiRedisHost,
		LapiRedisReadHosts: cfg.LapiRedisReadHosts,
		LapiRedisPassword:  cfg.LapiRedisPassword,
		LapiRedisDatabase:  cfg.LapiRedisDatabase,
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
