package lapi

import (
	"context"
	"errors"
	"testing"
	"time"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

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

func TestOpenDecisionStore_DifferentRedisHostsIsolate(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	redisA := testStreamConfig("lapi.example:8080", 1)
	redisB := testStreamConfig("lapi.example:8080", 1)
	redisA.RedisCacheEnabled = true
	redisA.RedisCacheHost = "127.0.0.1:1"
	redisB.RedisCacheEnabled = true
	redisB.RedisCacheHost = "127.0.0.1:2"
	first, err := OpenDecisionStore(ctx, redisA, log)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, redisB, log)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different redis hosts must open two stores")
	}
}

func TestOpenDecisionStore_LiveRedisPrefixIsSessionHexNotIdentityHex(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx := context.Background()
	log := logger.New("ERROR", "")
	cfg := testLiveConfig(1)
	other := testLiveConfig(60)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheHost = redisServer.addr()
	store, err := OpenDecisionStore(ctx, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	store.CacheForTest().Set("1.2.3.4", "t", 10)

	sessionClient := &cache.Client{}
	sessionClient.New(log, true, redisServer.addr(), nil, "", "", SessionHex(cfg))
	got, getErr := sessionClient.Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("SessionHex prefix Get %q err %v", got, getErr)
	}

	identityClient := &cache.Client{}
	identityClient.New(log, true, redisServer.addr(), nil, "", "", IdentityHex(cfg))
	_, identErr := identityClient.Get("1.2.3.4")
	if identErr == nil || !errors.Is(identErr, cache.ErrMiss) {
		t.Fatalf("IdentityHex prefix Get err %v, want miss", identErr)
	}

	if SessionHex(cfg) != SessionHex(other) {
		t.Fatal("live SessionHex must ignore updateIntervalSeconds")
	}
	if IdentityHex(testLiveConfig(1)) != IdentityHex(testLiveConfig(60)) {
		t.Fatal("live IdentityHex must omit updateIntervalSeconds")
	}
}

func TestOpenDecisionStore_LiveIntervalSplitSharesStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig(1)
	slow := testLiveConfig(60)
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
	first.CacheForTest().Set("1.2.3.4", "t", 10)
	got, getErr := second.CacheForTest().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("shared store Get %q err %v", got, getErr)
	}
}

func TestOpenDecisionStore_HeaderMismatchStillShares(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	base := testStreamConfig("lapi.example:8080", 1)
	withHeaders := testStreamConfig("lapi.example:8080", 1)
	withHeaders.DecisionScopeHeaders = map[string]string{"username": "X-User"}
	first, err := OpenDecisionStore(ctx, base, log)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, withHeaders, log)
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
	if first.CacheForTest() != second.CacheForTest() {
		t.Fatal("those Clients must share one cache incarnation")
	}
	first.CacheForTest().Set("1.2.3.4", "t", 10)
	got, getErr := second.CacheForTest().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("sibling Get %q err %v", got, getErr)
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
	first.CacheForTest().Set("1.2.3.4", "t", 10)
	first.Close()
	got, getErr := second.CacheForTest().Get("1.2.3.4")
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
	fast := testLiveConfig(1)
	slow := testLiveConfig(60)
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
	first.CacheForTest().Set("1.2.3.4", "t", 10)
	first.Close()
	got, getErr := second.CacheForTest().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("after sibling Close Redis Get %q err %v", got, getErr)
	}
}

func TestOpenDecisionStore_LastHolderGraceClosesRedisPool(t *testing.T) {
	reclaim.ResetForTestWith(20 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	log := logger.New("ERROR", "")
	cfg := testLiveConfig(1)
	cfg.RedisCacheEnabled = true
	cfg.RedisCacheHost = redisServer.addr()
	store, err := OpenDecisionStore(ctx, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	store.CacheForTest().Set("1.2.3.4", "t", 10)
	got, getErr := store.CacheForTest().Get("1.2.3.4")
	if getErr != nil || got != "t" {
		t.Fatalf("before cancel Get %q err %v", got, getErr)
	}
	cancel()
	time.Sleep(80 * time.Millisecond)
	_, closedErr := store.CacheForTest().Get("1.2.3.4")
	if closedErr == nil || !errors.Is(closedErr, cache.ErrUnreachable) {
		t.Fatalf("after last-holder grace Get err %v, want unreachable", closedErr)
	}
}
