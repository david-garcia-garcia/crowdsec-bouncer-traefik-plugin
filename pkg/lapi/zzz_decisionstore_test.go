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
		LapiMode:                  configuration.LiveMode,
		LapiScheme:            "http",
		LapiHost:              "lapi.example:8080",
		LapiPath:              "/",
		LapiKey:               "test-key",
		LapiTLSInsecureVerify: true,
		BouncerLapiFailureAction:     configuration.FailureActionBan,
		LapiUpdateIntervalSeconds:         updateInterval,
		LapiMetricsUpdateIntervalSeconds:  0,
		LapiHTTPTimeoutSeconds:        10,
		LapiDefaultDecisionSeconds:        60,
	}
}

func TestStoreKey_IgnoresPollerKnobsAndHeaders(t *testing.T) {
	base := testStreamConfig("lapi.example:8080", 1)
	interval := testStreamConfig("lapi.example:8080", 1)
	interval.LapiUpdateIntervalSeconds = 30
	headers := testStreamConfig("lapi.example:8080", 1)
	headers.BouncerDecisionScopeHeaders = map[string]string{"username": "X-User"}
	if StoreKey(base) != StoreKey(interval) {
		t.Fatal("store key must ignore updateIntervalSeconds")
	}
	if StoreKey(base) != StoreKey(headers) {
		t.Fatal("store key must ignore decisionScopeHeaders")
	}
}

func TestStoreKey_DifferentRedisHostsShare(t *testing.T) {
	redisA := testStreamConfig("lapi.example:8080", 1)
	redisA.LapiRedisEnabled = true
	redisA.LapiRedisHost = "redis-a:6379"
	redisB := testStreamConfig("lapi.example:8080", 1)
	redisB.LapiRedisEnabled = true
	redisB.LapiRedisHost = "redis-b:6379"
	if StoreKey(redisA) == StoreKey(redisB) {
		t.Fatal("S3: different redis hosts must fork the store key")
	}
}

func TestOpenDecisionStore_DifferentRedisHostsShare(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	redisA := testStreamConfig("lapi.example:8080", 1)
	redisB := testStreamConfig("lapi.example:8080", 1)
	redisA.LapiRedisEnabled = true
	redisA.LapiRedisHost = "127.0.0.1:1"
	redisB.LapiRedisEnabled = true
	redisB.LapiRedisHost = "127.0.0.1:2"
	first, err := OpenDecisionStore(ctx, redisA, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, redisB, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("S3: different redis hosts must open distinct stores")
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
	cfg.LapiRedisEnabled = true
	cfg.LapiRedisHost = redisServer.addr()
	store, err := OpenDecisionStore(ctx, cfg, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	putBan(store)

	session := newTestRedisStore(t, redisServer.addr(), nil, SessionHex(cfg))
	kind, _, _, getErr := session.LookupRemediation("1.2.3.4", nil, nil)
	if getErr != nil || kind != decisionscope.BannedValue {
		t.Fatalf("SessionHex prefix lookup %q err %v", kind, getErr)
	}

	identity := newTestRedisStore(t, redisServer.addr(), nil, IdentityHex(cfg))
	identKind, _, originID, identErr := identity.LookupRemediation("1.2.3.4", nil, nil)
	_ = originID
	if identErr != nil || identKind != "" {
		t.Fatalf("IdentityHex prefix lookup kind %q err %v, want empty kind", identKind, identErr)
	}

	other.LapiRedisEnabled = true
	other.LapiRedisHost = redisServer.addr()
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
	first, err := OpenDecisionStore(ctx, fast, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, slow, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same cursor and Redis params must reclaim one store")
	}
	putBan(first)
	got, getErr := lookupBan(second)
	if getErr != nil || got != decisionscope.BannedValue {
		t.Fatalf("shared store lookup %q err %v", got, getErr)
	}
}

func TestOpenDecisionStore_HeaderMismatchStillShares(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	base := testStreamConfig("lapi.example:8080", 1)
	withHeaders := testStreamConfig("lapi.example:8080", 1)
	withHeaders.BouncerDecisionScopeHeaders = map[string]string{"username": "X-User"}
	first, err := OpenDecisionStore(ctx, base, log, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenDecisionStore(ctx, withHeaders, log, "test")
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
	first, err := OpenLive(ctx, fast, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("I1: different live intervals must open distinct Clients")
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
	first, err := OpenLive(ctx, fast, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "shared", "test")
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

func TestClientClose_LeavesSiblingRedisPoolLive(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx := context.Background()
	log := logger.New("ERROR", "")
	fast := testLiveConfig(1)
	slow := testLiveConfig(60)
	fast.LapiRedisEnabled = true
	fast.LapiRedisHost = redisServer.addr()
	slow.LapiRedisEnabled = true
	slow.LapiRedisHost = redisServer.addr()
	first, err := OpenLive(ctx, fast, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenLive(ctx, slow, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	putBan(first.decisionStore)
	first.Close()
	kind, _, _, getErr := second.decisionStore.LookupRemediation("1.2.3.4", nil, nil)
	if getErr != nil || kind != decisionscope.BannedValue {
		t.Fatalf("after sibling Close lookup %q err %v", kind, getErr)
	}
}

func TestOpenDecisionStore_LastHolderGraceClosesRedisPool(t *testing.T) {
	reclaim.ResetForTestWith(20 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	redisServer := startTestLeaseRedis(t)
	ctx, cancel := context.WithCancel(context.Background())
	log := logger.New("ERROR", "")
	cfg := testLiveConfig(1)
	cfg.LapiRedisEnabled = true
	cfg.LapiRedisHost = redisServer.addr()
	store, err := OpenDecisionStore(ctx, cfg, log, "test")
	if err != nil {
		t.Fatal(err)
	}
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

func TestOpenDecisionStore_StreamPublishTickCounts(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	log := logger.New("ERROR", "")
	stream, err := OpenDecisionStore(ctx, testStreamConfig("lapi.example:8080", 0), log, "stream")
	if err != nil {
		t.Fatal(err)
	}
	putBan(stream)
	stream.BeginTick()
	stream.PublishTick(0)
	if len(stream.ActiveCounts()) == 0 {
		t.Fatal("stream OpenDecisionStore after PublishTick must count ActiveCounts")
	}

	live, err := OpenDecisionStore(ctx, testLiveConfig(1), log, "live")
	if err != nil {
		t.Fatal(err)
	}
	putBan(live)
	if got := live.ActiveCounts(); len(got) != 0 {
		t.Fatalf("live OpenDecisionStore Put must not increment, got %#v", got)
	}
}
