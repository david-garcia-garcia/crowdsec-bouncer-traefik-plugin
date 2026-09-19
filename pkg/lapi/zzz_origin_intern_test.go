package lapi

import (
	"testing"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestInternStore() *DecisionStore {
	store := &DecisionStore{origins: intern.New()}
	store.initStreamStore(logger.New("ERROR", ""))
	return store
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
	store.beginStreamTick()
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "crowdsec"}, 60)
	store.publishStreamTick()
	slot := decisionscope.IPCacheKey("203.0.113.10")
	live, ok := store.streamMapForTest()[slot]
	if !ok {
		t.Fatal("live slot missing")
	}
	kind, _, originID := decisionscope.Unpack(live.Word)
	if kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q", kind, store.OriginName(originID))
	}
	if _, getErr := cacheClient.GetInt(slot); getErr == nil {
		t.Fatal("ttl heap must not duplicate packed Ip")
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

func TestStorePackedOrLeftoverOverflowUsesKindOnly(t *testing.T) {
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	store := newTestInternStore()
	store.cache = cacheClient
	store.origins.FillUntilMaxForTest()
	client := &Client{cacheClient: cacheClient, decisionStore: store, log: logger.New("ERROR", "")}
	store.beginStreamTick()
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.99", Origin: "overflow-origin"}, 60)
	store.publishStreamTick()
	slot := decisionscope.IPCacheKey("203.0.113.99")
	live, ok := store.streamMapForTest()[slot]
	if !ok {
		t.Fatal("live slot missing")
	}
	kind, origin, originID := decisionscope.Unpack(live.Word)
	if kind != decisionscope.BannedValue || origin != "" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
	if _, err := cacheClient.Get(slot); err == nil {
		t.Fatal("ttl heap must not duplicate overflow Ip")
	}
}
