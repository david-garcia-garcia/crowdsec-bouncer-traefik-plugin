package lapi

import (
	"log/slog"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// NewTestClient returns an in-memory Client whose Cache tests can seed.
func NewTestClient(log *slog.Logger) (*Client, *cache.Client) {
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	return &Client{cacheClient: cacheClient, log: log}, cacheClient
}

// AttachTestInternStore wires a memory DecisionStore so tests can intern origins.
func AttachTestInternStore(client *Client) *DecisionStore {
	store := &DecisionStore{cache: client.cacheClient}
	store.internNames.Store([]string{""})
	client.decisionStore = store
	return store
}

// AttachTestMetricsReporter wires a stream-mode reporter so tests can read IncDropped.
func AttachTestMetricsReporter(client *Client) {
	client.crowdsecMode = configuration.StreamMode
	client.metricsReporter = newMetricsReporter(client, time.Now())
}

// TestDroppedCount is the current window dropped count for origin+ipType+remediation.
func (c *Client) TestDroppedCount(origin, ipType, remediation string) int64 {
	if c == nil || c.metricsReporter == nil {
		return 0
	}
	key := usageMetricKey{
		name:        "dropped",
		unit:        "request",
		origin:      origin,
		ipType:      ipType,
		remediation: remediation,
	}
	c.metricsReporter.metricsMu.Lock()
	defer c.metricsReporter.metricsMu.Unlock()
	return c.metricsReporter.windowCounters[key]
}
