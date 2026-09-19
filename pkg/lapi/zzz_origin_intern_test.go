package lapi

import (
	"testing"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestInternStore() *DecisionStore {
	return &DecisionStore{origins: intern.New()}
}

func TestPackUsesInternOnMemoryStore(t *testing.T) {
	store := newTestInternStore()
	word, ok := decisionscope.Pack(decisionscope.BannedValue, "crowdsec", store).(uint32)
	if !ok {
		t.Fatal("pack")
	}
	kind, _, originID := decisionscope.Unpack(word)
	if kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q", kind, store.OriginName(originID))
	}
}

func TestPackSkippedOnRedisStore(t *testing.T) {
	store := newTestInternStore()
	store.redisBacked = true
	if _, ok := decisionscope.Pack(decisionscope.BannedValue, "crowdsec", store).(uint32); ok {
		t.Fatal("redis must keep leftover")
	}
}

func TestStoreStreamDecisionPacksMemory(t *testing.T) {
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	store := newTestInternStore()
	store.cache = cacheClient
	client := &Client{cacheClient: cacheClient, decisionStore: store, log: logger.New("ERROR", "")}
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "crowdsec"}, 60)
	slot := decisionscope.IPCacheKey("203.0.113.10")
	word, err := cacheClient.GetInt(slot)
	if err != nil {
		t.Fatalf("GetInt %v", err)
	}
	kind, _, originID := decisionscope.Unpack(word)
	if kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q", kind, store.OriginName(originID))
	}
	if _, getErr := cacheClient.Get(slot); getErr == nil {
		t.Fatal("leftover Get must miss a packed word")
	}
}

func TestRememberActiveDecisionForgetCompactSlot(t *testing.T) {
	store := newTestInternStore()
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client, body := newUsageMetricsClient(t)
	client.decisionStore = store
	client.cacheClient = cacheClient
	client.rememberActiveDecision("ip:1.2.3.4", "crowdsec", "1.2.3.4")
	if len(client.metricsReporter.activeDecisionSlots) != 1 {
		t.Fatalf("slots %d", len(client.metricsReporter.activeDecisionSlots))
	}
	rec := client.metricsReporter.activeDecisionSlots["ip:1.2.3.4"]
	if rec.originID == 0 || rec.leftover != "" || rec.ipType != "ipv4" {
		t.Fatalf("slot %#v", rec)
	}
	client.forgetActiveDecision("ip:1.2.3.4")
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] == "active_decisions" {
			t.Fatalf("forgot slot still posted %#v", item)
		}
	}
}

func TestStorePackedOrLeftoverOverflowUsesLeftover(t *testing.T) {
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	store := newTestInternStore()
	store.cache = cacheClient
	names := make([]string, 65536)
	names[0] = ""
	for i := 1; i < 65536; i++ {
		names[i] = "filled"
	}
	store.origins.ReplaceNamesForTest(names)
	client := &Client{cacheClient: cacheClient, decisionStore: store, log: logger.New("ERROR", "")}
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.99", Origin: "overflow-origin"}, 60)
	slot := decisionscope.IPCacheKey("203.0.113.99")
	if _, err := cacheClient.GetInt(slot); err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("GetInt leftover got %v, want cache:miss", err)
	}
	got, err := cacheClient.Get(slot)
	want := decisionscope.RemediationWithOrigin(decisionscope.BannedValue, "overflow-origin")
	if err != nil || got != want {
		t.Fatalf("leftover %q err %v, want %q", got, err, want)
	}
}
