package lapi

import (
	"log/slog"
	"sync/atomic"
	"time"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

// NewTestClient returns an in-memory Client whose Cache tests can seed.
func NewTestClient(log *slog.Logger) (*Client, *cache.Client) {
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	return &Client{cacheClient: cacheClient, log: log}, cacheClient
}

// AttachTestInternStore wires a memory decision store so tests can intern origins.
func AttachTestInternStore(client *Client) *decisionstore.Store {
	store := decisionstore.NewMemory(client.cacheClient, client.log)
	client.decisionStore = store
	return store
}

// SeedLiveSnapshotForTest publishes one stream/alone memory slot for bouncer tests.
func SeedLiveSnapshotForTest(store *decisionstore.Store, key, kind, origin string, durationSec int64) {
	store.SeedSlotForTest(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: key, Kind: kind, Origin: origin, DurationSec: durationSec,
	})
}

// AttachTestMetricsReporter wires a stream-mode reporter so tests can read IncDropped.
func AttachTestMetricsReporter(client *Client) {
	client.crowdsecMode = configuration.StreamMode
	client.metricsReporter = newMetricsReporter(client, time.Now())
}

// SetStreamHealthyForTest sets stream health for bouncer tests.
func (c *Client) SetStreamHealthyForTest(healthy bool) {
	if c == nil {
		return
	}
	if healthy {
		atomic.StoreInt64(&c.isCrowdsecStreamHealthy, 1)
		return
	}
	atomic.StoreInt64(&c.isCrowdsecStreamHealthy, 0)
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
