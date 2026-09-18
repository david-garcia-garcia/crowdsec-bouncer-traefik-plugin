package lapi

import (
	"log/slog"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// NewTestClient returns an in-memory Client whose Cache tests can seed.
func NewTestClient(log *slog.Logger) (*Client, *cache.Client) {
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	return &Client{cacheClient: cacheClient, log: log}, cacheClient
}
