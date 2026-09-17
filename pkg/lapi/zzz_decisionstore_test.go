package lapi

import (
	"context"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// testLiveConfig is a live-mode config aimed at a mock LAPI host.
func testLiveConfig(host string, updateInterval int64) *configuration.Config {
	return &configuration.Config{
		CrowdsecMode:                  configuration.LiveMode,
		CrowdsecLapiScheme:            "http",
		CrowdsecLapiHost:              host,
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
	a := testStreamConfig("lapi.example:8080", 1)
	a.RedisCacheEnabled = true
	a.RedisCacheHost = "redis-a:6379"
	b := testStreamConfig("lapi.example:8080", 1)
	b.RedisCacheEnabled = true
	b.RedisCacheHost = "redis-b:6379"
	if StoreKey(a) == StoreKey(b) {
		t.Fatal("different redis hosts must be different stores")
	}
}

func TestOpenDecisionStore_DifferentRedisHostsIsolate(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	a := testStreamConfig("lapi.example:8080", 1)
	b := testStreamConfig("lapi.example:8080", 1)
	a.RedisCacheEnabled = true
	a.RedisCacheHost = "127.0.0.1:1"
	b.RedisCacheEnabled = true
	b.RedisCacheHost = "127.0.0.1:2"
	first, err := OpenDecisionStore(ctx, a, log)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, b, log)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different redis hosts must open two stores")
	}
}

func TestCachePrefix_LiveIsSessionHexNotIdentityHex(t *testing.T) {
	cfg := testLiveConfig("lapi.example:8080", 1)
	other := testLiveConfig("lapi.example:8080", 60)
	if CachePrefix(cfg) != SessionHex(cfg) {
		t.Fatal("live cache prefix must be SessionHex")
	}
	if CachePrefix(cfg) == IdentityHex(cfg) {
		t.Fatal("live cache prefix must not be IdentityHex")
	}
	if CachePrefix(cfg) != CachePrefix(other) {
		t.Fatal("live cache prefix must ignore updateIntervalSeconds")
	}
	if IdentityHex(cfg) == IdentityHex(other) {
		t.Fatal("live Client identity must still include updateIntervalSeconds")
	}
}

func TestOpenDecisionStore_LiveIntervalSplitSharesStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig("lapi.example:8080", 1)
	slow := testLiveConfig("lapi.example:8080", 60)
	first, err := OpenDecisionStore(ctx, fast, log)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, slow, log)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same cursor and Redis params must reclaim one store")
	}
	first.Cache().Set("1.2.3.4", "t", 10)
	got, getErr := second.Cache().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("shared store Get %q err %v", got, getErr)
	}
}

func TestOpenDecisionStore_HeaderMismatchStillShares(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	a := testStreamConfig("lapi.example:8080", 1)
	b := testStreamConfig("lapi.example:8080", 1)
	b.DecisionScopeHeaders = map[string]string{"username": "X-User"}
	first, err := OpenDecisionStore(ctx, a, log)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, b, log)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("header-map mismatch must still share the store")
	}
}

func TestOpenLive_TwoClientsShareOneStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig("lapi.example:8080", 1)
	slow := testLiveConfig("lapi.example:8080", 60)
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "slow", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different live intervals must be two Clients")
	}
	if first.Cache() != second.Cache() {
		t.Fatal("those Clients must share one cache incarnation")
	}
	first.Cache().Set("1.2.3.4", "t", 10)
	got, getErr := second.Cache().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("sibling Get %q err %v", got, getErr)
	}
}

func TestClientClose_LeavesSiblingCacheLive(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig("lapi.example:8080", 1)
	slow := testLiveConfig("lapi.example:8080", 60)
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "slow", "test")
	if err != nil {
		t.Fatal(err)
	}
	first.Cache().Set("1.2.3.4", "t", 10)
	first.Close()
	got, getErr := second.Cache().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("after sibling Close Get %q err %v", got, getErr)
	}
}

func TestClientClose_LeavesSiblingRedisPoolLive(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig("lapi.example:8080", 1)
	slow := testLiveConfig("lapi.example:8080", 60)
	fast.RedisCacheEnabled = true
	fast.RedisCacheHost = redisServer.addr()
	slow.RedisCacheEnabled = true
	slow.RedisCacheHost = redisServer.addr()
	first, err := OpenLive(ctx, fast, log, "fast", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "slow", "test")
	if err != nil {
		t.Fatal(err)
	}
	first.Cache().Set("1.2.3.4", "t", 10)
	first.Close()
	got, getErr := second.Cache().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("after sibling Close Redis Get %q err %v", got, getErr)
	}
}
