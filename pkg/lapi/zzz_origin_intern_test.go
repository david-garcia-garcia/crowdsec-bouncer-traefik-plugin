package lapi

import (
	"testing"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestInternStore() *decisionstore.Store {
	return decisionstore.NewMemory(nil, logger.New("ERROR", ""))
}

func TestPackUsesInternOnMemoryStore(t *testing.T) {
	store := newTestInternStore()
	store.BeginTick()
	store.Put(decisionstore.Decision{Scope: decisionscope.ScopeIP, Value: "k", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60})
	store.PublishTick(0)
	kind, _, originID, err := store.LookupRemediation("k", nil, nil, nil)
	if err != nil || kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q err %v", kind, store.OriginName(originID), err)
	}
}

func TestPackSkippedOnRedisStore(t *testing.T) {
	cacheClient := &cache.Client{}
	log := logger.New("ERROR", "")
	cacheClient.New(log, false, "", nil, "", "", "")
	store := decisionstore.NewRedis(cacheClient)
	store.Put(decisionstore.Decision{Scope: decisionscope.ScopeIP, Value: "k", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60})
	if _, err := cacheClient.GetInt("k"); err == nil {
		t.Fatal("redis must keep leftover")
	}
	got, err := cacheClient.Get("k")
	if err != nil || decisionscope.RemediationKind(got) != decisionscope.BannedValue {
		t.Fatalf("leftover %q err %v", got, err)
	}
}

func TestStoreStreamDecisionPacksMemory(t *testing.T) {
	cacheClient := &cache.Client{}
	log := logger.New("ERROR", "")
	cacheClient.New(log, false, "", nil, "", "", "")
	store := decisionstore.NewMemory(cacheClient, log)
	client := &Client{cacheClient: cacheClient, decisionStore: store, log: log}
	store.BeginTick()
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "crowdsec"}, 60)
	store.PublishTick(0)
	slot := decisionscope.IPCacheKey("203.0.113.10")
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", nil, nil, nil)
	if err != nil || kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q err %v", kind, store.OriginName(originID), err)
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
	log := logger.New("ERROR", "")
	cacheClient.New(log, false, "", nil, "", "", "")
	store := decisionstore.NewMemory(cacheClient, log)
	store.FillUntilMaxForTest()
	client := &Client{cacheClient: cacheClient, decisionStore: store, log: log}
	store.BeginTick()
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.99", Origin: "overflow-origin"}, 60)
	store.PublishTick(0)
	slot := decisionscope.IPCacheKey("203.0.113.99")
	kind, origin, originID, err := store.LookupRemediation("203.0.113.99", nil, nil, nil)
	if err != nil || kind != decisionscope.BannedValue || origin != "" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
	if _, err := cacheClient.Get(slot); err == nil {
		t.Fatal("ttl heap must not duplicate overflow Ip")
	}
}
