package crowdsecconnection

const crowdsecLapiMetricsRoute = "v1/usage-metrics"

func (c *CrowdsecConnection) handleMetricsTicker() {
	if err := c.reportMetrics(); err != nil {
		c.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}
