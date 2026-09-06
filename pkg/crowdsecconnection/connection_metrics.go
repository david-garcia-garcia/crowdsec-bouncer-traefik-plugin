package crowdsecconnection

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
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

func (c *CrowdsecConnection) handleMetricsTicker() {
	if err := c.reportMetrics(); err != nil {
		c.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}

// drainMetrics POSTs the current usage-metrics window to LAPI. No-op when metrics are disabled.
func (c *CrowdsecConnection) drainMetrics() {
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
func (c *CrowdsecConnection) IncProcessed(ipType string) {
	switch ipType {
	case "ipv4":
		atomic.AddInt64(&c.processedIPv4, 1)
	case "ipv6":
		atomic.AddInt64(&c.processedIPv6, 1)
	default:
		atomic.AddInt64(&c.processedUnknown, 1)
	}
}

// IncDropped counts a remediating response. Empty origin/ipType/remediation labels are omitted on POST.
func (c *CrowdsecConnection) IncDropped(origin, ipType, remediation string) {
	c.addWindow(usageMetricKey{
		name:        "dropped",
		unit:        "request",
		origin:      origin,
		ipType:      ipType,
		remediation: remediation,
	}, 1)
}

// addWindow adds delta to a dropped counter for this push window.
func (c *CrowdsecConnection) addWindow(key usageMetricKey, delta int64) {
	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()
	if c.windowCounters == nil {
		c.windowCounters = make(map[usageMetricKey]int64)
	}
	c.windowCounters[key] += delta
}

// rememberActiveDecision records one stream/alone decision for the active_decisions gauge.
func (c *CrowdsecConnection) rememberActiveDecision(slot, origin, decisionValue string) {
	if c.crowdsecMode != configuration.StreamMode && c.crowdsecMode != configuration.AloneMode {
		return
	}
	key := usageMetricKey{
		name:   "active_decisions",
		unit:   "ip",
		origin: origin,
		ipType: ip.FamilyOfHostOrCIDR(decisionValue),
	}
	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()
	if c.activeDecisionSlots == nil {
		c.activeDecisionSlots = make(map[string]usageMetricKey)
	}
	if c.activeDecisions == nil {
		c.activeDecisions = make(map[usageMetricKey]int64)
	}
	if previous, ok := c.activeDecisionSlots[slot]; ok {
		c.activeDecisions[previous]--
		if c.activeDecisions[previous] <= 0 {
			delete(c.activeDecisions, previous)
		}
	}
	c.activeDecisionSlots[slot] = key
	c.activeDecisions[key]++
}

// forgetActiveDecision drops a previously counted stream/alone decision from the gauge.
func (c *CrowdsecConnection) forgetActiveDecision(slot string) {
	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()
	if c.activeDecisionSlots == nil {
		return
	}
	previous, ok := c.activeDecisionSlots[slot]
	if !ok {
		return
	}
	delete(c.activeDecisionSlots, slot)
	c.activeDecisions[previous]--
	if c.activeDecisions[previous] <= 0 {
		delete(c.activeDecisions, previous)
	}
}

// reportMetrics POSTs the current window of usage-metrics items to LAPI.
// Dropped and processed counters reset only after LAPI accepts the POST.
func (c *CrowdsecConnection) reportMetrics() error {
	c.reportMu.Lock()
	defer c.reportMu.Unlock()

	now := time.Now()
	windowSizeSeconds := int(now.Sub(c.lastMetricsPush).Seconds())

	c.metricsMu.Lock()
	window := c.windowCounters
	c.windowCounters = make(map[usageMetricKey]int64)
	items := make([]map[string]interface{}, 0, len(window)+len(c.activeDecisions)+3)
	for key, value := range window {
		items = append(items, usageMetricItem(key, value))
	}
	for key, value := range c.activeDecisions {
		if value > 0 {
			items = append(items, usageMetricItem(key, value))
		}
	}
	c.metricsMu.Unlock()

	processedIPv4 := atomic.SwapInt64(&c.processedIPv4, 0)
	processedIPv6 := atomic.SwapInt64(&c.processedIPv6, 0)
	processedUnknown := atomic.SwapInt64(&c.processedUnknown, 0)
	items = appendProcessedWindow(items, "ipv4", processedIPv4)
	items = appendProcessedWindow(items, "ipv6", processedIPv6)
	items = appendProcessedWindow(items, "", processedUnknown)

	c.log.Debug(fmt.Sprintf("reportMetrics: items=%d window_size=%ds", len(items), windowSizeSeconds))

	metrics := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": c.pluginVersion,
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
				"utc_startup_timestamp": c.startedAt.Unix(),
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
		c.restoreMetricsWindow(window, processedIPv4, processedIPv6, processedUnknown)
		return fmt.Errorf("reportMetrics:marshal %w", err)
	}

	metricsURL := url.URL{
		Scheme: c.crowdsecScheme,
		Host:   c.crowdsecHost,
		Path:   c.crowdsecPath + crowdsecLapiMetricsRoute,
	}

	_, err = c.crowdsecQuery(metricsURL.String(), data)
	if err != nil {
		c.restoreMetricsWindow(window, processedIPv4, processedIPv6, processedUnknown)
		return fmt.Errorf("reportMetrics:query %w", err)
	}

	c.lastMetricsPush = now
	return nil
}

// restoreMetricsWindow puts a failed POST’s counters back so the next drain or ticker can send them.
func (c *CrowdsecConnection) restoreMetricsWindow(window map[usageMetricKey]int64, processedIPv4, processedIPv6, processedUnknown int64) {
	c.metricsMu.Lock()
	if c.windowCounters == nil {
		c.windowCounters = make(map[usageMetricKey]int64)
	}
	for key, value := range window {
		c.windowCounters[key] += value
	}
	c.metricsMu.Unlock()
	atomic.AddInt64(&c.processedIPv4, processedIPv4)
	atomic.AddInt64(&c.processedIPv6, processedIPv6)
	atomic.AddInt64(&c.processedUnknown, processedUnknown)
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
