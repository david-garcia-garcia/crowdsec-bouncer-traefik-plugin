package lapi

import (
	"log/slog"
	"os"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const unknownCacheInstanceID = "unknown-instance"

// ResolveCacheInstanceIdentity sets RedisCacheEffectiveInstanceID once per cfg.
// Call from Prepare when Redis is enabled.
func ResolveCacheInstanceIdentity(cfg *configuration.Config, log *slog.Logger) {
	if cfg.RedisCacheEffectiveInstanceID != "" {
		return
	}
	configured := strings.TrimSpace(cfg.RedisCacheInstanceId)
	if configured != "" {
		cfg.RedisCacheEffectiveInstanceID = configured
		return
	}
	host, err := os.Hostname()
	if err != nil {
		if log != nil {
			log.Warn("redis cache instance id: hostname unavailable, using unknown-instance", "error", err)
		}
		cfg.RedisCacheEffectiveInstanceID = unknownCacheInstanceID
		return
	}
	cfg.RedisCacheEffectiveInstanceID = host
}

// cachePrefixBase is SessionHex for stream/alone, IdentityHex for live/none.
func cachePrefixBase(cfg *configuration.Config) string {
	if cfg.CrowdsecMode == configuration.StreamMode || cfg.CrowdsecMode == configuration.AloneMode {
		return SessionHex(cfg)
	}
	return IdentityHex(cfg)
}
