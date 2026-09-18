package lapi

import (
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestActiveDecisionsLabelsAfterCompactSlots(t *testing.T) {
	store := newTestMemoryDecisionStore()
	client, body := newUsageMetricsClient(t)
	client.decisionStore = store
	client.crowdsecMode = configuration.StreamMode
	client.metricsReporter.origins = store
	client.rememberActiveDecision("ip:1.2.3.4", "crowdsec", "1.2.3.4")
	slot, ok := client.metricsReporter.activeDecisionSlots["ip:1.2.3.4"]
	if !ok || slot.originID == 0 || slot.originText != "" || slot.family != '4' {
		t.Fatalf("compact slot %#v ok %v", slot, ok)
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] != "active_decisions" {
			continue
		}
		labels := asObject(t, item["labels"])
		if labels["origin"] != "crowdsec" || labels["ip_type"] != "ipv4" {
			t.Fatalf("active labels %#v", labels)
		}
		found = true
	}
	if !found {
		t.Fatal("missing active_decisions")
	}
}

func TestForgetActiveDecisionClearsCompactSlot(t *testing.T) {
	client, body := newUsageMetricsClient(t)
	client.rememberActiveDecision("ip:1.2.3.4", "crowdsec", "1.2.3.4")
	client.forgetActiveDecision("ip:1.2.3.4")
	if _, ok := client.metricsReporter.activeDecisionSlots["ip:1.2.3.4"]; ok {
		t.Fatal("forget must drop the slot")
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] == "active_decisions" {
			t.Fatalf("forget must omit active_decisions, item %#v", item)
		}
	}
}

func TestEmptyOriginSlotKeepsTodayLabels(t *testing.T) {
	store := newTestMemoryDecisionStore()
	client, body := newUsageMetricsClient(t)
	client.metricsReporter.origins = store
	client.rememberActiveDecision("ip:1.2.3.4", "", "1.2.3.4")
	slot := client.metricsReporter.activeDecisionSlots["ip:1.2.3.4"]
	if slot.originID != 0 || slot.originText != "" {
		t.Fatalf("empty origin slot %#v", slot)
	}
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] != "active_decisions" {
			continue
		}
		if rawLabels, ok := item["labels"]; ok && rawLabels != nil {
			labels := asObject(t, rawLabels)
			if _, hasOrigin := labels["origin"]; hasOrigin {
				t.Fatalf("empty origin must omit origin label %#v", labels)
			}
		}
	}
}
