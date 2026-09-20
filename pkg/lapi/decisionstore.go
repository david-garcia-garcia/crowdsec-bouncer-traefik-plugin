package lapi

import (
	"log/slog"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

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
