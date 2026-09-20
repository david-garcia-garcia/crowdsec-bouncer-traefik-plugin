package lapi

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestInternStore() *decisionstore.Store {
	return decisionstore.NewMemory(logger.New("ERROR", ""), false)
}

func newTestCountedInternStore() *decisionstore.Store {
	return decisionstore.NewMemory(logger.New("ERROR", ""), true)
}

func TestPackUsesInternOnMemoryStore(t *testing.T) {
	store := newTestInternStore()
	store.BeginTick()
	store.Put(decisionstore.Decision{Scope: decisionscope.ScopeIP, Value: "k", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60})
	store.PublishTick(0)
	kind, _, originID, err := store.LookupRemediation("k", nil, nil)
	if err != nil || kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q err %v", kind, store.OriginName(originID), err)
	}
}

func TestPackSkippedOnRedisStore(t *testing.T) {
	redisServer := startTestLeaseRedis(t)
	store := newTestRedisStore(t, redisServer.addr(), nil, "sess")
	store.Put(decisionstore.Decision{Scope: decisionscope.ScopeIP, Value: "k", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60})
	kind, origin, originID, err := store.LookupRemediation("k", nil, nil)
	if err != nil || kind != decisionscope.BannedValue || origin != "crowdsec" || originID != 0 {
		t.Fatalf("redis kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
}

func TestStoreStreamDecisionPacksMemory(t *testing.T) {
	store := newTestInternStore()
	client := &Client{decisionStore: store, log: logger.New("ERROR", "")}
	store.BeginTick()
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.10", Origin: "crowdsec"}, 60)
	store.PublishTick(0)
	kind, _, originID, err := store.LookupRemediation("203.0.113.10", nil, nil)
	if err != nil || kind != decisionscope.BannedValue || store.OriginName(originID) != "crowdsec" {
		t.Fatalf("kind %q origin %q err %v", kind, store.OriginName(originID), err)
	}
}

func TestActiveDecisionDeleteOmitsGauge(t *testing.T) {
	store := newTestCountedInternStore()
	client, body := newUsageMetricsClient(t)
	client.decisionStore = store
	store.Put(decisionstore.Decision{
		Scope: decisionscope.ScopeIP, Value: "1.2.3.4", Kind: decisionscope.BannedValue, Origin: "crowdsec", DurationSec: 60,
	})
	store.Delete(decisionscope.ScopeIP, "1.2.3.4")
	if err := client.reportMetrics(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range usageMetricItems(t, body.bytes()) {
		item := asObject(t, raw)
		if item["name"] == "active_decisions" {
			t.Fatalf("deleted slot still posted %#v", item)
		}
	}
}

func TestStoreInternOverflowUsesGenericOrigin(t *testing.T) {
	store := newTestInternStore()
	store.FillUntilMaxForTest()
	client := &Client{decisionStore: store, log: logger.New("ERROR", "")}
	store.BeginTick()
	client.storeStreamDecision(Decision{Type: "ban", Scope: "ip", Value: "203.0.113.99", Origin: "overflow-origin"}, 60)
	store.PublishTick(0)
	kind, origin, originID, err := store.LookupRemediation("203.0.113.99", nil, nil)
	if err != nil || kind != decisionscope.BannedValue || origin != "" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d err %v", kind, origin, originID, err)
	}
}
