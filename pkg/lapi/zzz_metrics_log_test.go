package lapi

import (
	"log/slog"
	"strings"
	"testing"
)

func TestReportMetricsDebugCarriesNestedBackend(t *testing.T) {
	client, _ := newUsageMetricsClient(t)
	log, sink := newTestLogSink(slog.LevelDebug)
	client.log = log.With(
		"traefikName", "bouncer-captcha",
		"instanceName", "shared",
		"leg", "lapi",
		"sessionKey", "lapi:owner:abc",
	)
	attachTestMetricsReporter(client, client.metricsReporter.startedAt)
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	logged := sink.String()
	if !strings.Contains(logged, `"msg":"reportMetrics"`) {
		t.Fatalf("missing reportMetrics:\n%s", logged)
	}
	for _, field := range []string{
		`"traefikName":"bouncer-captcha"`,
		`"instanceName":"shared"`,
		`"leg":"lapi"`,
		`"sessionKey":"lapi:owner:abc"`,
	} {
		if !strings.Contains(logged, field) {
			t.Fatalf("missing %s:\n%s", field, logged)
		}
	}
}
