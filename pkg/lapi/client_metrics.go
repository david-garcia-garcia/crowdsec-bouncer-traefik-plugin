package lapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

const crowdsecLapiMetricsRoute = "v1/usage-metrics"

// Origins for drops that are not a CrowdSec decision. cscli shows origin rows;
// empty origin is totals-only. Do not reuse crowdsec / CAPI / appsec / lists:.
const (
	OriginPluginTechGetRemoteFail = "plugin:tech_getremotefail" // GetRemoteIP failed
	OriginPluginTechTrustIPFail   = "plugin:tech_trustipfail"   // trusted-IP checker failed
	OriginPluginTechCacheFail     = "plugin:tech_cachefail"     // cache error fail-closed
	OriginPluginTechStreamFail    = "plugin:tech_streamfail"    // stream unhealthy
	OriginPluginLapiFailure       = "plugin:lapi_failure"       // live LAPI lookup error
	OriginPluginAppsecFailure     = "plugin:appsec_failure"     // AppSec failure-action
)

// crowdsecQueryFunc POSTs through the Client's current LAPI transport.
type crowdsecQueryFunc func(stringURL string, data []byte) ([]byte, error)

// MetricsReporter owns the usage-metrics window and POST/restore path.
// Client holds one pointer for the cursor reclaim lifetime; tickers stay on Client.
type MetricsReporter struct {
	scheme        string
	host          string
	path          string
	pluginVersion string
	startedAt     time.Time
	crowdsecMode  string
	query         crowdsecQueryFunc
	log           *slog.Logger

	lastMetricsPush     time.Time
	metricsMu           sync.Mutex
	reportMu            sync.Mutex               // one usage-metrics POST at a time (ticker, Sleep drain, Close drain)
	windowCounters      map[usageMetricKey]int64 // dropped counters for the current push window
	processedIPv4       int64                    // processed ipv4; atomic on the request path
	processedIPv6       int64
	processedUnknown    int64 // processed when Family is empty
	activeDecisions     map[usageMetricKey]int64
	activeDecisionSlots map[string]usageMetricKey
}

// newMetricsReporter snapshots write-once URL and envelope scalars and binds query to crowdsecQuery.
func newMetricsReporter(client *Client, startedAt time.Time) *MetricsReporter {
	return &MetricsReporter{
		scheme:              client.crowdsecScheme,
		host:                client.crowdsecHost,
		path:                client.crowdsecPath,
		pluginVersion:       client.pluginVersion,
		startedAt:           startedAt,
		crowdsecMode:        client.crowdsecMode,
		query:               client.crowdsecQuery,
		log:                 client.log,
		windowCounters:      make(map[usageMetricKey]int64),
		activeDecisions:     make(map[usageMetricKey]int64),
		activeDecisionSlots: make(map[string]usageMetricKey),
	}
}

// handleMetricsTicker POSTs the current usage-metrics window from the Client ticker.
func (c *Client) handleMetricsTicker() {
	if err := c.reportMetrics(); err != nil {
		c.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}

// drainMetrics POSTs the current usage-metrics window to LAPI. No-op when metrics are disabled.
func (c *Client) drainMetrics() {
	if c.metricsInterval <= 0 {
		return
	}
	if err := c.reportMetrics(); err != nil {
		c.log.Error("drainMetrics:reportMetrics " + err.Error())
	}
}

// usageMetricKey is one LAPI usage-metrics item identity: name, unit, and optional labels.
type usageMetricKey struct {
	name        string
	unit        string
	origin      string
	ipType      string
	remediation string
}

// MetricsOrigin is the usage-metrics origin label. CrowdSec list decisions become lists:<scenario>.
func MetricsOrigin(origin, scenario string) string {
	trimmedOrigin := strings.TrimSpace(origin)
	if strings.EqualFold(trimmedOrigin, "lists") {
		listName := strings.TrimSpace(scenario)
		if listName != "" {
			return "lists:" + listName
		}
	}
	return trimmedOrigin
}

// IncProcessed counts a handled request (bypass, pass, or drop) by ip_type.
// Lock-free: ServeHTTP calls this on every request.
func (c *Client) IncProcessed(ipType string) {
	// New always sets the reporter; Client literals in other packages do not.
	if c.metricsReporter == nil {
		return
	}
	c.metricsReporter.IncProcessed(ipType)
}

// IncProcessed counts a handled request (bypass, pass, or drop) by ip_type.
func (r *MetricsReporter) IncProcessed(ipType string) {
	switch ipType {
	case "ipv4":
		atomic.AddInt64(&r.processedIPv4, 1)
	case "ipv6":
		atomic.AddInt64(&r.processedIPv6, 1)
	default:
		atomic.AddInt64(&r.processedUnknown, 1)
	}
}

// IncDropped counts a remediating response. Empty origin/ipType/remediation labels are omitted on POST.
func (c *Client) IncDropped(origin, ipType, remediation string) {
	if c.metricsReporter == nil {
		return
	}
	c.metricsReporter.IncDropped(origin, ipType, remediation)
}

// IncDropped counts a remediating response. Empty origin/ipType/remediation labels are omitted on POST.
func (r *MetricsReporter) IncDropped(origin, ipType, remediation string) {
	r.addWindow(usageMetricKey{
		name:        "dropped",
		unit:        "request",
		origin:      origin,
		ipType:      ipType,
		remediation: remediation,
	}, 1)
}

// addWindow adds delta to a dropped counter for this push window.
func (r *MetricsReporter) addWindow(key usageMetricKey, delta int64) {
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	if r.windowCounters == nil {
		r.windowCounters = make(map[usageMetricKey]int64)
	}
	r.windowCounters[key] += delta
}

// rememberActiveDecision records one stream/alone decision for the active_decisions gauge.
func (c *Client) rememberActiveDecision(slot, origin, decisionValue string) {
	if c.metricsReporter == nil {
		return
	}
	c.metricsReporter.rememberActiveDecision(slot, origin, decisionValue)
}

// rememberActiveDecision records one stream/alone decision for the active_decisions gauge.
func (r *MetricsReporter) rememberActiveDecision(slot, origin, decisionValue string) {
	if r.crowdsecMode != configuration.StreamMode && r.crowdsecMode != configuration.AloneMode {
		return
	}
	key := usageMetricKey{
		name:   "active_decisions",
		unit:   "ip",
		origin: origin,
		ipType: ip.FamilyOfHostOrCIDR(decisionValue),
	}
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	if r.activeDecisionSlots == nil {
		r.activeDecisionSlots = make(map[string]usageMetricKey)
	}
	if r.activeDecisions == nil {
		r.activeDecisions = make(map[usageMetricKey]int64)
	}
	if previous, ok := r.activeDecisionSlots[slot]; ok {
		r.activeDecisions[previous]--
		if r.activeDecisions[previous] <= 0 {
			delete(r.activeDecisions, previous)
		}
	}
	r.activeDecisionSlots[slot] = key
	r.activeDecisions[key]++
}

// forgetActiveDecision drops a previously counted stream/alone decision from the gauge.
func (c *Client) forgetActiveDecision(slot string) {
	if c.metricsReporter == nil {
		return
	}
	c.metricsReporter.forgetActiveDecision(slot)
}

// forgetActiveDecision drops a previously counted stream/alone decision from the gauge.
func (r *MetricsReporter) forgetActiveDecision(slot string) {
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	if r.activeDecisionSlots == nil {
		return
	}
	previous, ok := r.activeDecisionSlots[slot]
	if !ok {
		return
	}
	delete(r.activeDecisionSlots, slot)
	r.activeDecisions[previous]--
	if r.activeDecisions[previous] <= 0 {
		delete(r.activeDecisions, previous)
	}
}

// reportMetrics POSTs the current window of usage-metrics items to LAPI.
// Dropped and processed counters reset only after LAPI accepts the POST.
func (c *Client) reportMetrics() error {
	if c.metricsReporter == nil {
		return nil
	}
	return c.metricsReporter.reportMetrics()
}

// reportMetrics POSTs the current window of usage-metrics items to LAPI.
// Dropped and processed counters reset only after LAPI accepts the POST.
func (r *MetricsReporter) reportMetrics() error {
	r.reportMu.Lock()
	defer r.reportMu.Unlock()

	now := time.Now()
	windowSizeSeconds := int(now.Sub(r.lastMetricsPush).Seconds())

	// Snapshot dropped and gauge items, then swap processed atomics.
	r.metricsMu.Lock()
	window := r.windowCounters
	r.windowCounters = make(map[usageMetricKey]int64)
	items := make([]map[string]interface{}, 0, len(window)+len(r.activeDecisions)+3)
	for key, value := range window {
		items = append(items, usageMetricItem(key, value))
	}
	for key, value := range r.activeDecisions {
		if value > 0 {
			items = append(items, usageMetricItem(key, value))
		}
	}
	r.metricsMu.Unlock()

	processedIPv4 := atomic.SwapInt64(&r.processedIPv4, 0)
	processedIPv6 := atomic.SwapInt64(&r.processedIPv6, 0)
	processedUnknown := atomic.SwapInt64(&r.processedUnknown, 0)
	items = appendProcessedWindow(items, "ipv4", processedIPv4)
	items = appendProcessedWindow(items, "ipv6", processedIPv6)
	items = appendProcessedWindow(items, "", processedUnknown)

	r.log.Debug(fmt.Sprintf("reportMetrics: items=%d window_size=%ds", len(items), windowSizeSeconds))

	metrics := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": r.pluginVersion,
				"type":    "bouncer",
				"name":    "traefik_plugin",
				"metrics": []map[string]interface{}{
					{
						"items": items,
						"meta": map[string]interface{}{
							"window_size_seconds": windowSizeSeconds,
							"utc_now_timestamp":   now.Unix(),
						},
					},
				},
				"utc_startup_timestamp": r.startedAt.Unix(),
				"feature_flags":         []string{},
				"os": map[string]string{
					"name":    "unknown",
					"version": "unknown",
				},
			},
		},
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		r.restoreMetricsWindow(window, processedIPv4, processedIPv6, processedUnknown)
		return fmt.Errorf("reportMetrics:marshal %w", err)
	}

	metricsURL := url.URL{
		Scheme: r.scheme,
		Host:   r.host,
		Path:   r.path + crowdsecLapiMetricsRoute,
	}

	_, err = r.query(metricsURL.String(), data)
	if err != nil {
		r.restoreMetricsWindow(window, processedIPv4, processedIPv6, processedUnknown)
		return fmt.Errorf("reportMetrics:query %w", err)
	}

	r.lastMetricsPush = now
	return nil
}

// restoreMetricsWindow puts a failed POST’s counters back so the next drain or ticker can send them.
func (r *MetricsReporter) restoreMetricsWindow(window map[usageMetricKey]int64, processedIPv4, processedIPv6, processedUnknown int64) {
	r.metricsMu.Lock()
	if r.windowCounters == nil {
		r.windowCounters = make(map[usageMetricKey]int64)
	}
	for key, value := range window {
		r.windowCounters[key] += value
	}
	r.metricsMu.Unlock()
	atomic.AddInt64(&r.processedIPv4, processedIPv4)
	atomic.AddInt64(&r.processedIPv6, processedIPv6)
	atomic.AddInt64(&r.processedUnknown, processedUnknown)
}

// appendProcessedWindow adds a processed item when the swapped window count is non-zero.
func appendProcessedWindow(items []map[string]interface{}, ipType string, value int64) []map[string]interface{} {
	if value == 0 {
		return items
	}
	return append(items, usageMetricItem(usageMetricKey{name: "processed", unit: "request", ipType: ipType}, value))
}

// usageMetricItem is one JSON item in the usage-metrics window (empty labels omitted).
func usageMetricItem(key usageMetricKey, value int64) map[string]interface{} {
	labels := map[string]string{}
	if key.origin != "" {
		labels["origin"] = key.origin
	}
	if key.ipType != "" {
		labels["ip_type"] = key.ipType
	}
	if key.remediation != "" {
		labels["remediation"] = key.remediation
	}
	item := map[string]interface{}{
		"name":  key.name,
		"value": value,
		"unit":  key.unit,
	}
	if len(labels) > 0 {
		item["labels"] = labels
	}
	return item
}
