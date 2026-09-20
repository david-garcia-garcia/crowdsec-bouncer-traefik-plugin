package lapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func putBan(store *decisionstore.Store) {
	store.Put(decisionstore.Decision{Scope: decisionscope.ScopeIP, Value: "1.2.3.4", Kind: decisionscope.BannedValue, DurationSec: 10})
}

func lookupBan(store *decisionstore.Store) (string, error) {
	kind, _, originID, err := store.LookupRemediation("1.2.3.4", nil, nil)
	_ = originID
	return kind, err
}

// testLiveConfig is a live-mode config aimed at a mock LAPI host.
func testLiveConfig(updateInterval int64) *configuration.Config {
	return &configuration.Config{
		CrowdsecMode:                  configuration.LiveMode,
		CrowdsecLapiScheme:            "http",
		CrowdsecLapiHost:              "lapi.example:8080",
		CrowdsecLapiPath:              "/",
		CrowdsecLapiKey:               "test-key",
		CrowdsecLapiTLSInsecureVerify: true,
		CrowdsecLapiFailureAction:     configuration.FailureActionBan,
		UpdateIntervalSeconds:         updateInterval,
		MetricsUpdateIntervalSeconds:  0,
		HTTPTimeoutSeconds:            10,
		DefaultDecisionSeconds:        60,
	}
}

func TestStoreKey_IgnoresPollerKnobsAndHeaders(t *testing.T) {
	base := testStreamConfig("lapi.example:8080", 1)
	interval := testStreamConfig("lapi.example:8080", 1)
	interval.UpdateIntervalSeconds = 30
	headers := testStreamConfig("lapi.example:8080", 1)
	headers.DecisionScopeHeaders = map[string]string{"username": "X-User"}
	if StoreKey(base) != StoreKey(interval) {
		t.Fatal("store key must ignore updateIntervalSeconds")
	}
	if StoreKey(base) != StoreKey(headers) {
		t.Fatal("store key must ignore decisionScopeHeaders")
	}
}

func TestStoreKey_DifferentRedisHostsIsolate(t *testing.T) {
	redisA := testStreamConfig("lapi.example:8080", 1)
	redisA.RedisCacheEnabled = true
	redisA.RedisCacheHost = "redis-a:6379"
	redisB := testStreamConfig("lapi.example:8080", 1)
	redisB.RedisCacheEnabled = true
	redisB.RedisCacheHost = "redis-b:6379"
	if StoreKey(redisA) == StoreKey(redisB) {
		t.Fatal("different redis hosts must be different stores")
	}
}

func TestOpenLive_DifferentRedisHostsIsolate(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	redisA := testLiveConfig(1)
	redisB := testLiveConfig(1)
	redisA.RedisCacheHost = "redis-a:6379"
	redisB.RedisCacheHost = "redis-b:6379"
	first, err := OpenLive(ctx, redisA, log, "redis-a", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, redisB, log, "redis-b", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different redis hosts must open two live Clients")
	}
	if first.decisionStore == second.decisionStore {
		t.Fatal("different redis hosts must open two stores")
	}
	putBan(first.decisionStore)
	if _, getErr := lookupBan(second.decisionStore); getErr == nil {
		t.Fatal("ban present only in the first store must miss on the second")
	}
}

func TestOpenLive_LiveRedisPrefixIsSessionHexNotIdentityHex(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx := context.Background()
	log := logger.New("ERROR", "")
	cfg := testLiveConfig(1)
	other := testLiveConfig(60)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheHost = redisServer.addr()
	client, err := OpenLive(ctx, cfg, log, "live", "test")
	if err != nil {
		t.Fatal(err)
	}
	putBan(client.decisionStore)

	session := newTestRedisStore(t, redisServer.addr(), nil, SessionHex(cfg))
	kind, _, _, getErr := session.LookupRemediation("1.2.3.4", nil, nil)
	if getErr != nil || kind != decisionscope.BannedValue {
		t.Fatalf("SessionHex prefix lookup %q err %v", kind, getErr)
	}

	identity := newTestRedisStore(t, redisServer.addr(), nil, IdentityHex(cfg))
	_, _, originID, identErr := identity.LookupRemediation("1.2.3.4", nil, nil)
	_ = originID
	if identErr == nil || !errors.Is(identErr, decisionstore.ErrMiss) {
		t.Fatalf("IdentityHex prefix lookup err %v, want miss", identErr)
	}

	if SessionHex(cfg) != SessionHex(other) {
		t.Fatal("live SessionHex must ignore updateIntervalSeconds")
	}
	if IdentityHex(testLiveConfig(1)) != IdentityHex(testLiveConfig(60)) {
		t.Fatal("live IdentityHex must omit updateIntervalSeconds")
	}
}

func TestOpenLive_MetricsIntervalSplitDoesNotShareStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testNoneConfig("lapi.example:8080", 3600)
	slow := testNoneConfig("lapi.example:8080", 7200)
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "slow", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("metrics-interval split must open two Clients")
	}
	if first.decisionStore == second.decisionStore {
		t.Fatal("metrics-interval split must not share a reclaim store")
	}
	putBan(first.decisionStore)
	if _, getErr := lookupBan(second.decisionStore); getErr == nil {
		t.Fatal("memory backends must isolate: ban in the first store must miss on the second")
	}
}

func TestOpenLive_TwoClientsShareOneStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig(1)
	slow := testLiveConfig(60)
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "slow", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("different live intervals must share one Client")
	}
	if first.decisionStore != second.decisionStore {
		t.Fatal("those Clients must share one decision store")
	}
	putBan(first.decisionStore)
	got, getErr := lookupBan(second.decisionStore)
	if getErr != nil || got != decisionscope.BannedValue {
		t.Fatalf("sibling lookup %q err %v", got, getErr)
	}
}

func TestClientClose_LeavesSiblingCacheLive(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig(1)
	slow := testLiveConfig(60)
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "slow", "test")
	if err != nil {
		t.Fatal(err)
	}
	putBan(first.decisionStore)
	first.Close()
	got, getErr := lookupBan(second.decisionStore)
	if getErr != nil || got != decisionscope.BannedValue {
		t.Fatalf("after sibling Close lookup %q err %v", got, getErr)
	}
}

func TestClientClose_ClosesChildRedisStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig(1)
	fast.RedisCacheEnabled = true
	fast.RedisCacheHost = redisServer.addr()
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	putBan(first.decisionStore)
	first.Close()
	_, _, originID, closedErr := first.decisionStore.LookupRemediation("1.2.3.4", nil, nil)
	_ = originID
	if closedErr == nil || !errors.Is(closedErr, decisionstore.ErrUnreachable) {
		t.Fatalf("after Client Close lookup err %v, want unreachable", closedErr)
	}
}

func TestOpenLive_LastHolderGraceClosesRedisPool(t *testing.T) {
	reclaim.ResetForTestWith(20 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	log := logger.New("ERROR", "")
	cfg := testLiveConfig(1)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheHost = redisServer.addr()
	client, err := OpenLive(ctx, cfg, log, "live", "test")
	if err != nil {
		t.Fatal(err)
	}
	store := client.decisionStore
	putBan(store)
	kind, _, _, getErr := store.LookupRemediation("1.2.3.4", nil, nil)
	if getErr != nil || kind != decisionscope.BannedValue {
		t.Fatalf("before cancel lookup %q err %v", kind, getErr)
	}
	cancel()
	time.Sleep(80 * time.Millisecond)
	_, _, originID, closedErr := store.LookupRemediation("1.2.3.4", nil, nil)
	_ = originID
	if closedErr == nil || !errors.Is(closedErr, decisionstore.ErrUnreachable) {
		t.Fatalf("after last-holder grace lookup err %v, want unreachable", closedErr)
	}
}
