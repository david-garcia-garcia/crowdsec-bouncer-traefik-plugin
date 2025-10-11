/*TODO: NEEDS HUMAN REVIEW*/
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecclient"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decision"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// BlockedRequestMetric represents a blocked request metric
type BlockedRequestMetric struct {
	Source    decision.DecisionSource `json:"source"`
	Scope     decision.DecisionScope  `json:"scope"`
	Type      decision.DecisionType   `json:"type"`
	Scenario  string                  `json:"scenario"`
	Count     int64                   `json:"count"`
	Timestamp time.Time               `json:"timestamp"`
}

// MetricsCollector collects and reports metrics about blocked requests
type MetricsCollector struct {
	mu               sync.RWMutex
	blockedRequests  map[string]*BlockedRequestMetric // key: source_scope_type_scenario
	totalBlocked     int64
	lastReportTime   time.Time
	log              *logger.Log
	reportingEnabled bool
	crowdsecClient   *crowdsecclient.Client
}

// HTTPClient interface for making HTTP requests (for testing)
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config contains configuration for the metrics collector
type Config struct {
	ReportingEnabled bool
	CrowdsecClient   *crowdsecclient.Client
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(log *logger.Log, config *Config) *MetricsCollector {
	return &MetricsCollector{
		blockedRequests:  make(map[string]*BlockedRequestMetric),
		lastReportTime:   time.Now(),
		log:              log,
		reportingEnabled: config.ReportingEnabled,
		crowdsecClient:   config.CrowdsecClient,
	}
}

// RecordBlockedRequest records a blocked request
func (m *MetricsCollector) RecordBlockedRequest(result *decision.DecisionResult) {
	if result == nil || !result.Blocked {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalBlocked++

	// For now, assume source is CrowdSec (we can enhance this later)
	source := decision.SourceCrowdSec

	// Create a key for this specific type of block
	key := fmt.Sprintf("%s_%s_%s_%s",
		source,
		result.MatchedBy,
		result.Type,
		result.Scenario)

	metric, exists := m.blockedRequests[key]
	if exists {
		metric.Count++
		metric.Timestamp = time.Now()
	} else {
		m.blockedRequests[key] = &BlockedRequestMetric{
			Source:    source,
			Scope:     result.MatchedBy,
			Type:      result.Type,
			Scenario:  result.Scenario,
			Count:     1,
			Timestamp: time.Now(),
		}
	}

	m.log.Debug(fmt.Sprintf("Recorded blocked request: source=%s scope=%s type=%s scenario=%s",
		source, result.MatchedBy, result.Type, result.Scenario))
}

// GetTotalBlocked returns the total number of blocked requests
func (m *MetricsCollector) GetTotalBlocked() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.totalBlocked
}

// GetMetricsSummary returns a summary of all metrics
func (m *MetricsCollector) GetMetricsSummary() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	summary := map[string]interface{}{
		"total_blocked": m.totalBlocked,
		"by_source":     make(map[string]int64),
		"by_scope":      make(map[string]int64),
		"by_type":       make(map[string]int64),
		"by_scenario":   make(map[string]int64),
		"detailed":      make([]*BlockedRequestMetric, 0, len(m.blockedRequests)),
	}

	bySource := summary["by_source"].(map[string]int64)
	byScope := summary["by_scope"].(map[string]int64)
	byType := summary["by_type"].(map[string]int64)
	byScenario := summary["by_scenario"].(map[string]int64)
	detailed := summary["detailed"].([]*BlockedRequestMetric)

	for _, metric := range m.blockedRequests {
		bySource[string(metric.Source)] += metric.Count
		byScope[string(metric.Scope)] += metric.Count
		byType[string(metric.Type)] += metric.Count
		byScenario[metric.Scenario] += metric.Count

		// Add to detailed list
		detailed = append(detailed, &BlockedRequestMetric{
			Source:    metric.Source,
			Scope:     metric.Scope,
			Type:      metric.Type,
			Scenario:  metric.Scenario,
			Count:     metric.Count,
			Timestamp: metric.Timestamp,
		})
	}

	summary["detailed"] = detailed
	return summary
}

// ReportMetrics reports metrics to CrowdSec
func (m *MetricsCollector) ReportMetrics() error {
	if !m.reportingEnabled {
		m.log.Debug("Metrics reporting is disabled")
		return nil
	}

	now := time.Now()
	windowSizeSeconds := int(now.Sub(m.lastReportTime).Seconds())

	m.mu.Lock()
	currentTotal := m.totalBlocked
	currentMetrics := make([]*BlockedRequestMetric, 0, len(m.blockedRequests))
	for _, metric := range m.blockedRequests {
		currentMetrics = append(currentMetrics, &BlockedRequestMetric{
			Source:    metric.Source,
			Scope:     metric.Scope,
			Type:      metric.Type,
			Scenario:  metric.Scenario,
			Count:     metric.Count,
			Timestamp: metric.Timestamp,
		})
	}

	// Reset counters after collecting
	m.totalBlocked = 0
	m.blockedRequests = make(map[string]*BlockedRequestMetric)
	m.lastReportTime = now
	m.mu.Unlock()

	m.log.Debug(fmt.Sprintf("Reporting metrics: total_blocked=%d window_size=%ds detailed_metrics=%d",
		currentTotal, windowSizeSeconds, len(currentMetrics)))

	// Build the metrics payload
	metricsItems := []map[string]interface{}{
		{
			"name":  "dropped",
			"value": currentTotal,
			"unit":  "request",
			"labels": map[string]string{
				"type": "traefik_plugin",
			},
		},
	}

	// Add detailed metrics for each source/scope/type/scenario combination
	for _, metric := range currentMetrics {
		metricsItems = append(metricsItems, map[string]interface{}{
			"name":  "dropped_detailed",
			"value": metric.Count,
			"unit":  "request",
			"labels": map[string]string{
				"type":     "traefik_plugin",
				"source":   string(metric.Source),
				"scope":    string(metric.Scope),
				"decision": string(metric.Type),
				"scenario": metric.Scenario,
			},
		})
	}

	payload := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": "1.X.X",
				"type":    "bouncer",
				"name":    "traefik_plugin",
				"metrics": []map[string]interface{}{
					{
						"items": metricsItems,
						"meta": map[string]interface{}{
							"window_size_seconds": windowSizeSeconds,
							"utc_now_timestamp":   now.Unix(),
						},
					},
				},
				"utc_startup_timestamp": time.Now().Unix(),
				"feature_flags":         []string{},
				"os": map[string]string{
					"name":    "unknown",
					"version": "unknown",
				},
			},
		},
	}

	err := m.crowdsecClient.SendMetrics(payload)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	m.log.Debug(fmt.Sprintf("Successfully reported metrics: %d total blocked requests", currentTotal))
	return nil
}
