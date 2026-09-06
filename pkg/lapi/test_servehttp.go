package lapi

import (
	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestServeHTTPLapiOptions configures a minimal lapi.Client for bouncer ServeHTTP tests.
type TestServeHTTPLapiOptions struct {
	Mode                  string
	FailureAction         string
	StreamHealthy         bool
	RedisUnreachableBlock bool
	CacheClient           *cache.Client
}

// NewTestServeHTTPLapiClient returns a minimal Client for pkg/bouncer ServeHTTP tests.
func NewTestServeHTTPLapiClient(opts TestServeHTTPLapiOptions) *Client {
	cacheClient := opts.CacheClient
	if cacheClient == nil {
		cacheClient = &cache.Client{}
		cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	}
	return &Client{
		crowdsecMode:            opts.Mode,
		lapiFailureAction:       configuration.EffectiveFailureAction(opts.FailureAction),
		isCrowdsecStreamHealthy: opts.StreamHealthy,
		redisUnreachableBlock:   opts.RedisUnreachableBlock,
		cacheClient:             cacheClient,
		log:                     logger.New("ERROR", ""),
	}
}
