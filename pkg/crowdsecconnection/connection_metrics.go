package crowdsecconnection

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync/atomic"
	"time"
)

const crowdsecLapiMetricsRoute = "v1/usage-metrics"

func (c *CrowdsecConnection) handleMetricsTicker() {
	if err := c.reportMetrics(); err != nil {
		c.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}

func (c *CrowdsecConnection) reportMetrics() error {
	now := time.Now()
	currentCount := atomic.LoadInt64(&c.blockedRequests)
	windowSizeSeconds := int(now.Sub(c.lastMetricsPush).Seconds())

	c.log.Debug(fmt.Sprintf("reportMetrics: blocked_requests=%d window_size=%ds", currentCount, windowSizeSeconds))

	metrics := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": c.pluginVersion,
				"type":    "bouncer",
				"name":    "traefik_plugin",
				"metrics": []map[string]interface{}{
					{
						"items": []map[string]interface{}{
							{
								"name":  "dropped",
								"value": currentCount,
								"unit":  "request",
								"labels": map[string]string{
									"type": "traefik_plugin",
								},
							},
						},
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

	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("reportMetrics:marshal %w", err)
	}

	metricsURL := url.URL{
		Scheme: c.crowdsecScheme,
		Host:   c.crowdsecHost,
		Path:   c.crowdsecPath + crowdsecLapiMetricsRoute,
	}

	_, err = c.crowdsecQuery(metricsURL.String(), data)
	if err != nil {
		return fmt.Errorf("reportMetrics:query %w", err)
	}

	atomic.StoreInt64(&c.blockedRequests, 0)
	c.lastMetricsPush = now
	return nil
}
