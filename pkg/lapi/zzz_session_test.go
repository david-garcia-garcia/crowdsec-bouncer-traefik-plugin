package lapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// testStreamConfig is a stream-mode config aimed at a mock LAPI host.
func testStreamConfig(host string, metricsInterval int64) *configuration.Config {
	return &configuration.Config{
		CrowdsecMode:                  configuration.StreamMode,
		CrowdsecLapiScheme:            "http",
		CrowdsecLapiHost:              host,
		CrowdsecLapiPath:              "/",
		CrowdsecLapiKey:               "test-key",
		CrowdsecLapiTLSInsecureVerify: true,
		CrowdsecLapiFailureAction:     configuration.FailureActionBan,
		UpdateIntervalSeconds:         60,
		MetricsUpdateIntervalSeconds:  metricsInterval,
		HTTPTimeoutSeconds:            10,
		DefaultDecisionSeconds:        60,
		StreamStartupBlock:            true,
	}
}

// attachTestTransport stores LAPI HTTP+auth on client for same-package tests.
func attachTestTransport(client *Client, httpClient *http.Client, key string) {
	client.transport.Store(&transport{httpClient: httpClient, header: crowdsecLapiHeader, key: key})
}

// testStreamLAPI counts GET /v1/decisions/stream hits and returns empty deltas.
func testStreamLAPI(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "stream") {
			atomic.AddInt64(&hits, 1)
			_ = json.NewEncoder(w).Encode(map[string][]Decision{
				"new":     {},
				"deleted": {},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func waitStreamFetches(t *testing.T, client *Client, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && client.StreamFetches() < want {
		time.Sleep(10 * time.Millisecond)
	}
	if got := client.StreamFetches(); got < want {
		t.Fatalf("stream fetches=%d, want >= %d", got, want)
	}
}

func TestSessionKey_SameLapiKeySharesCursorAndRedisHash(t *testing.T) {
	fast := testStreamConfig("lapi.example:8080", 1)
	fast.UpdateIntervalSeconds = 30
	slow := testStreamConfig("lapi.example:8080", 1)
	slow.UpdateIntervalSeconds = 120
	if SessionPrefix(fast) != SessionPrefix(slow) {
		t.Fatal("same LAPI URL+key must share a session prefix even when update intervals differ")
	}
	if SessionKey(fast) != SessionKey(slow) {
		t.Fatal("updateIntervalSeconds must not split SessionKey")
	}
	if OwnershipKey(fast, "mw") == OwnershipKey(slow, "mw") {
		t.Fatal("updateIntervalSeconds must split the ownership Open key")
	}
	if SessionHex(fast) != SessionHex(slow) {
		t.Fatal("stream cache prefix must follow the session, not metrics interval")
	}
	if !strings.HasPrefix(SessionKey(fast), "lapi:stream:") {
		t.Fatal("stream Open key must keep lapi:stream: prefix")
	}
	if !strings.HasPrefix(Key(fast), "lapi:") || strings.HasPrefix(Key(fast), "lapi:stream:") {
		t.Fatal("live Open key must be lapi: plus SessionHex, not StoreKey")
	}
	if strings.HasPrefix(SessionKey(fast), "decisionstore:") || SessionKey(fast) == StoreKey(fast) {
		t.Fatal("Client Open key must not reuse StoreKey")
	}
}

func testNoneConfig(host string, metricsInterval int64) *configuration.Config {
	cfg := testStreamConfig(host, metricsInterval)
	cfg.CrowdsecMode = configuration.NoneMode
	return cfg
}

func TestKey_NoneMetricsIntervalSplitsClientKeepsStore(t *testing.T) {
	fast := testNoneConfig("lapi.example:8080", 1)
	slow := testNoneConfig("lapi.example:8080", 600)
	if Key(fast) == Key(slow) {
		t.Fatal("none Key must include MetricsUpdateIntervalSeconds")
	}
	if StoreKey(fast) != StoreKey(slow) {
		t.Fatal("none StoreKey must omit MetricsUpdateIntervalSeconds")
	}
	streamFast := testStreamConfig("lapi.example:8080", 1)
	streamSlow := testStreamConfig("lapi.example:8080", 600)
	if SessionKey(streamFast) != SessionKey(streamSlow) {
		t.Fatal("stream SessionKey must still omit metrics interval")
	}
}

func TestSessionKey_DifferentHostsAreDistinct(t *testing.T) {
	a := testStreamConfig("lapi-a:8080", 1)
	b := testStreamConfig("lapi-b:8080", 1)
	if SessionKey(a) == SessionKey(b) {
		t.Fatal("different LAPI hosts must be different stream sessions")
	}
}

func TestSessionKey_PolicyAndTLSDoNotChangeKey(t *testing.T) {
	base := testStreamConfig("lapi.example:8080", 1)
	policy := testStreamConfig("lapi.example:8080", 1)
	policy.CrowdsecLapiFailureAction = configuration.FailureActionPassthrough
	policy.RedisCacheUnreachableBlock = true
	policy.DefaultDecisionSeconds = 5
	policy.StreamStartupBlock = false
	tlsOnly := testStreamConfig("lapi.example:8080", 1)
	tlsOnly.HTTPTimeoutSeconds = 30
	tlsOnly.CrowdsecLapiTLSInsecureVerify = false
	tlsOnly.CrowdsecLapiTLSCertificateAuthority = "ca"
	tlsOnly.CrowdsecLapiTLSCertificateBouncer = "cert"
	if SessionHex(base) == SessionHex(policy) {
		t.Fatal("defaultDecisionSeconds must change SessionHex")
	}
	policy.DefaultDecisionSeconds = base.DefaultDecisionSeconds
	if SessionKey(base) != SessionKey(policy) || IdentityHex(base) != IdentityHex(policy) {
		t.Fatal("failure-action policy must not change stream or live store keys")
	}
	if SessionKey(base) != SessionKey(tlsOnly) || IdentityHex(base) != IdentityHex(tlsOnly) {
		t.Fatal("HTTP timeout and LAPI TLS must not change SessionHex or IdentityHex")
	}
	if OwnershipKey(base, "mw") == OwnershipKey(tlsOnly, "mw") {
		t.Fatal("HTTP timeout and LAPI TLS must change the ownership Open key")
	}
}

func TestClient_ReclaimGrace(t *testing.T) {
	if reclaim.ProcessGrace != 30*time.Second {
		t.Fatalf("ProcessGrace: %v", reclaim.ProcessGrace)
	}
}

func TestClient_LifecycleLogs(t *testing.T) {
	log, logSink := newTestLogSink(slog.LevelDebug)
	log = log.With("leg", "lapi", "sessionKey", "lapi:test-key")
	client := &Client{
		log:          log,
		crowdsecMode: configuration.LiveMode,
		crowdsecHost: "lapi.example:8080",
		sessionKey:   "lapi:test-key",
	}
	client.Sleep()
	client.Wake()
	client.Close()
	logged := logSink.String()
	for _, msg := range []string{MsgConnectionSleeping, MsgConnectionWaking, MsgConnectionClosed} {
		if !strings.Contains(logged, msg) {
			t.Fatalf("missing %q in %s", msg, logged)
		}
	}
	for _, field := range []string{`"sessionKey":"lapi:test-key"`, `"reason":"sleeping"`, `"reason":"waking"`, `"reason":"closed"`} {
		if !strings.Contains(logged, field) {
			t.Fatalf("missing %q in %s", field, logged)
		}
	}
}

func TestOpenStream_LiveMetricsMismatchSharesSilently(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, logSink := newTestLogSink(slog.LevelDebug)
	ctx := context.Background()

	ownerCfg := testStreamConfig(parsed.Host, 1)
	ownerCfg.UpdateIntervalSeconds = 30
	owner, err := OpenStream(ctx, ownerCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	joinerCfg := testStreamConfig(parsed.Host, 1)
	joinerCfg.UpdateIntervalSeconds = 120
	joiner, err := OpenStream(ctx, joinerCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if owner == joiner {
		t.Fatal("interval mismatch must open a new Client")
	}
	if SessionHex(ownerCfg) != SessionHex(joinerCfg) {
		t.Fatal("interval mismatch must keep SessionHex")
	}
	if owner.decisionStore != joiner.decisionStore {
		t.Fatal("interval mismatch must keep one DecisionStore")
	}
	owner.Close()
	joiner.Close()
	logged := logSink.String()
	if strings.Contains(logged, "lapi session joiner ignored") || strings.Contains(logged, "wiring this middleware") {
		t.Fatalf("interval mismatch must not warn-and-wire: %s", logged)
	}
}

func TestOpenStream_SleepingIntervalChangeWakesSameSlot(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx, cancel := context.WithCancel(context.Background())
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.UpdateIntervalSeconds = 30
	first, err := OpenStream(ctx, firstCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	waitStreamFetches(t, first, 1)
	readyDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(readyDeadline) && first.decisionStore.StreamReady() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if first.decisionStore.StreamReady() == 0 {
		t.Fatal("first stream poll must mark the store ready")
	}
	cancel()
	waitClientSleeping(t, first)

	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.UpdateIntervalSeconds = 120
	second, err := OpenStream(context.Background(), secondCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("sleeping interval change must Open a new Client")
	}
	if SessionHex(firstCfg) != SessionHex(secondCfg) {
		t.Fatal("interval change must keep SessionHex")
	}
	if atomic.LoadInt64(&second.isCrowdsecStreamStartup) != 0 {
		t.Fatal("new Client on a warm store must not send startup=true")
	}
}

func TestOpenStream_SleepingRedisHostDoesNotOverlapPollers(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.RedisCacheHost = "redis-a:6379"
	ctx, cancel := context.WithCancel(context.Background())
	first, err := OpenStream(ctx, firstCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && first.StreamFetches() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	fetchesBeforeCancel := first.StreamFetches()
	cancel()
	waitClientSleeping(t, first)

	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.RedisCacheHost = "redis-b:6379"
	second, err := OpenStream(context.Background(), secondCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("sleeping Redis host change must Open a new Client")
	}
	if first.StreamFetches() != fetchesBeforeCancel {
		t.Fatal("old ticker must stay Sleep’d")
	}
	if first.decisionStore != second.decisionStore {
		t.Fatal("same Traefik name must keep the DecisionStore across Redis host change")
	}
	if atomic.LoadInt64(&second.isCrowdsecStreamStartup) != 0 {
		t.Fatal("new Client on a warm store must not send startup=true")
	}
}

func TestOpenStream_NewClientKeepsStoreStreamFlags(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.RedisCacheHost = "redis-a:6379"
	first, err := OpenStream(context.Background(), firstCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	store := first.decisionStore
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && store.StreamReady() == 0 {
		time.Sleep(time.Millisecond)
	}
	if store.StreamReady() == 0 {
		t.Fatal("first poll must mark streamReady")
	}
	held := false
	for time.Now().Before(deadline) {
		if store.TryBeginStreamPoll() {
			held = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !held {
		t.Fatal("store poll CAS")
	}
	hitsBeforeHold := atomic.LoadInt64(hits)
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.RedisCacheHost = "redis-b:6379"
	second, err := OpenStream(context.Background(), secondCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("Redis host change must Open a new Client")
	}
	if second.decisionStore != store {
		t.Fatal("new Client must keep the same store")
	}
	if store.StreamReady() == 0 {
		t.Fatal("new Client must not zero store streamReady")
	}
	if store.TryBeginStreamPoll() {
		t.Fatal("new Client must not zero store streamPollInFlight")
	}
	second.handleStreamTicker()
	if atomic.LoadInt64(hits) != hitsBeforeHold {
		t.Fatal("Wake/New poll must skip while the store CAS is held")
	}
	store.EndStreamPoll()
}

func TestOpenStream_DifferentRedisIsolatesClientKeepsStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx := context.Background()
	redisACfg := testStreamConfig(parsed.Host, 1)
	redisACfg.RedisCacheHost = "redis-a:6379"
	redisBCfg := testStreamConfig(parsed.Host, 1)
	redisBCfg.RedisCacheHost = "redis-b:6379"
	redisAClient, err := OpenStream(ctx, redisACfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	redisBClient, err := OpenStream(ctx, redisBCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if redisAClient == redisBClient {
		t.Fatal("different Redis must isolate the Client")
	}
	if redisAClient.decisionStore != redisBClient.decisionStore {
		t.Fatal("different Redis must keep one DecisionStore")
	}
	putBan(redisAClient.decisionStore)
	got, getErr := lookupBan(redisBClient.decisionStore)
	if getErr != nil || got == "" {
		t.Fatalf("ban in store A must hit in store B: %q err %v", got, getErr)
	}
}

func TestOpenStream_HeaderMapMismatchSharesClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx := context.Background()
	countryCfg := testStreamConfig(parsed.Host, 1)
	countryCfg.DecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	userCfg := testStreamConfig(parsed.Host, 1)
	userCfg.DecisionScopeHeaders = map[string]string{"username": "X-User"}
	countryClient, err := OpenStream(ctx, countryCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	userClient, err := OpenStream(ctx, userCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if countryClient != userClient {
		t.Fatal("header-map mismatch must share one Client")
	}
}

func TestOpenStream_FailureActionOnlyKeepsClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.CrowdsecLapiFailureAction = configuration.FailureActionBan
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.CrowdsecLapiFailureAction = configuration.FailureActionPassthrough

	first, err := OpenStream(ctx, firstCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	waitStreamFetches(t, first, 1)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt64(hits) < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt64(hits) < 1 {
		t.Fatal("first Open must hit LAPI stream")
	}
	fetches := first.StreamFetches()
	hitsBefore := atomic.LoadInt64(hits)
	second, err := OpenStream(ctx, secondCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("failure-action-only New must reuse the Client")
	}
	quiet := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(quiet) {
		if second.StreamFetches() != fetches {
			t.Fatal("failure-action-only New must not start another stream fetch")
		}
		if atomic.LoadInt64(hits) != hitsBefore {
			t.Fatal("failure-action-only New must not hit LAPI again")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestOpenStream_TLSOnlyAdoptsTransport(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.HTTPTimeoutSeconds = 10
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.HTTPTimeoutSeconds = 30

	first, err := OpenStream(ctx, firstCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("timeout-only New must open a new Client")
	}
	second.Close()
}

func TestOpenStream_LapiOverrideAdoptsTimeout(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.HTTPTimeoutSeconds = 10
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.HTTPTimeoutSeconds = 10
	secondCfg.CrowdsecLapiHTTPTimeoutSeconds = 30

	first, err := OpenStream(ctx, firstCfg, slog.Default(), "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, slog.Default(), "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("LAPI override-only New must open a new Client")
	}
}

func TestOpenStream_SharedDefaultChangeAdoptsWhenOverrideZero(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.HTTPTimeoutSeconds = 10
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.HTTPTimeoutSeconds = 20

	first, err := OpenStream(ctx, firstCfg, slog.Default(), "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, slog.Default(), "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("shared-default timeout New must open a new Client")
	}
}

func TestOpenStream_OverrideEqualSharedDoesNotReplace(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, logSink := newTestLogSink(slog.LevelInfo)
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.HTTPTimeoutSeconds = 10
	first, err := OpenStream(ctx, firstCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}

	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.HTTPTimeoutSeconds = 10
	secondCfg.CrowdsecLapiHTTPTimeoutSeconds = 10
	second, err := OpenStream(ctx, secondCfg, log, "shared", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("override 10 vs inherit 10 must reuse the Client")
	}
	current := second.currentTransport()
	if current == nil || current.httpTimeoutSeconds != 10 {
		t.Fatalf("stored timeout: %+v", current)
	}
	if current.httpClient.Timeout != 10*time.Second {
		t.Fatalf("HTTP timeout %v", current.httpClient.Timeout)
	}
	replaced, adoptErr := second.AdoptTransport(secondCfg)
	if adoptErr != nil {
		t.Fatal(adoptErr)
	}
	if replaced {
		t.Fatal("override 10 vs inherit 10 must not fieldsDiffer")
	}
	second.Close()
	if strings.Contains(logSink.String(), "lapi transport replaced") {
		t.Fatalf("no-op must not log transport replace: %s", logSink.String())
	}
}

func TestSessionKey_TimeoutKnobsDoNotChangeKey(t *testing.T) {
	base := testStreamConfig("lapi.example:8080", 1)
	timeouts := testStreamConfig("lapi.example:8080", 1)
	timeouts.HTTPTimeoutSeconds = 30
	timeouts.CrowdsecLapiHTTPTimeoutSeconds = 5
	timeouts.CrowdsecAppsecHTTPTimeoutSeconds = 2
	timeouts.CaptchaSiteverifyHTTPTimeoutSeconds = 1
	if SessionKey(base) != SessionKey(timeouts) {
		t.Fatal("timeout knobs must not change SessionKey")
	}
	if IdentityHex(base) != IdentityHex(timeouts) {
		t.Fatal("timeout knobs must not change IdentityHex")
	}
	if Key(base) != Key(timeouts) {
		t.Fatal("timeout knobs must not change live Key")
	}
}

// waitClientSleeping fails if the Client never Sleeps after its last holder is gone.
func waitClientSleeping(t *testing.T, client *Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		sleeping := client.sleeping
		client.mu.Unlock()
		if sleeping {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Client never Sleep'd")
}

func TestOpenStream_DifferentNameFailsBeforeStoreOpen(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx := context.Background()
	owner, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "foo", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, peekState, peekOK := reclaim.Peek(StoreKey(testStreamConfig(parsed.Host, 1)))
	if !peekOK || peekState != reclaim.Awake {
		t.Fatal("owner store must Peek Awake")
	}
	joiner, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "bar", "test")
	if err != nil {
		t.Fatal(err)
	}
	if joiner == owner {
		t.Fatal("different Traefik names must be different Clients")
	}
	if owner.decisionStore != joiner.decisionStore {
		t.Fatal("same SessionHex must share one DecisionStore")
	}
}

func TestOpenStream_EmptyNameStillExclusiveOwns(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	log := slog.Default()
	empty, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	named, namedErr := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "named", "test")
	if namedErr != nil {
		t.Fatal(namedErr)
	}
	if empty == named {
		t.Fatal("empty vs named middleware must isolate Clients")
	}
	secondEmpty, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	if empty != secondEmpty {
		t.Fatal("two empty names must share the Client")
	}
}

func TestOpenStream_SameNameDuringGraceWakesStore(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx, cancel := context.WithCancel(context.Background())
	first, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "foo", "test")
	if err != nil {
		t.Fatal(err)
	}
	store := first.decisionStore
	cancel()
	waitClientSleeping(t, first)
	_, state, ok := reclaim.Peek(StoreKey(testStreamConfig(parsed.Host, 1)))
	if !ok || state != reclaim.Asleep {
		t.Fatalf("store must Peek Asleep during grace: ok=%v state=%v", ok, state)
	}
	second, err := OpenStream(context.Background(), testStreamConfig(parsed.Host, 1), log, "foo", "test")
	if err != nil {
		t.Fatal(err)
	}
	if second.decisionStore != store {
		t.Fatal("same name during grace must Wake the same store")
	}
	if store.CreatedBy() != "foo" {
		t.Fatalf("Wake must not overwrite createdBy: %q", store.CreatedBy())
	}
}

func TestOpenDecisionStore_CreatedByWriteOnce(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx, cancel := context.WithCancel(context.Background())
	cfg := testStreamConfig("lapi.example:8080", 1)
	log := slog.Default()
	first, err := OpenDecisionStore(ctx, cfg, log, "foo")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	asleep := false
	for time.Now().Before(deadline) {
		_, state, ok := reclaim.Peek(StoreKey(cfg))
		if ok && state == reclaim.Asleep {
			asleep = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !asleep {
		t.Fatal("store must Sleep after last holder is gone")
	}
	second, err := OpenDecisionStore(context.Background(), cfg, log, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.CreatedBy() != "foo" {
		t.Fatalf("Wake must keep createdBy foo: %p %p %q", first, second, first.CreatedBy())
	}
}
