package lapi

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// NewTestClient returns an in-memory Client with a memory DecisionStore.
func NewTestClient(log *slog.Logger) (*Client, *decisionstore.Store) {
	store := decisionstore.NewMemory(log)
	return &Client{decisionStore: store, log: log, crowdsecMode: configuration.StreamMode}, store
}

// SetCrowdsecModeForTest sets crowdsecMode for tests that bind a client onto a bouncer.
func (c *Client) SetCrowdsecModeForTest(mode string) {
	if c == nil {
		return
	}
	c.crowdsecMode = mode
}

// newTestRangeClient is a stream-mode memory Client plus its DecisionStore.
func newTestRangeClient(t *testing.T) (*Client, *decisionstore.Store) {
	t.Helper()
	client, store := NewTestClient(logger.New("ERROR", ""))
	client.crowdsecMode = configuration.StreamMode
	return client, store
}

func newTestRedisStore(t *testing.T, host string, readHosts []string, prefix string) *decisionstore.Store {
	t.Helper()
	store := decisionstore.NewRedis(logger.New("ERROR", ""), host, readHosts, "", "", prefix)
	t.Cleanup(store.Close)
	return store
}

// AttachTestInternStore wires a memory decision store so tests can intern origins.
func AttachTestInternStore(client *Client) *decisionstore.Store {
	store := decisionstore.NewMemory(client.log)
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

// ClosedForTest reports whether Close has run on this incarnation.
func (c *Client) ClosedForTest() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// SleepingForTest reports whether Sleep has run and Close has not.
func (c *Client) SleepingForTest() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sleeping && !c.closed
}

// RunStreamTickerForTest runs the production stream ticker loop so a Yaegi program can drive it.
func RunStreamTickerForTest(ticks <-chan time.Time, stop <-chan bool, work func()) {
	runStreamTicker(ticks, stop, work)
}

// RunMetricsTickerForTest runs the production metrics ticker loop so a Yaegi program can drive it.
func RunMetricsTickerForTest(ticks <-chan time.Time, stop <-chan bool, work func()) {
	runMetricsTicker(ticks, stop, work)
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
