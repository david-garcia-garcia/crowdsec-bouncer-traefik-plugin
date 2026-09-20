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
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
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

func TestSessionKey_SameLapiKeySharesCursorNotRedis(t *testing.T) {
	fast := testStreamConfig("lapi.example:8080", 1)
	fast.UpdateIntervalSeconds = 30
	slow := testStreamConfig("lapi.example:8080", 1)
	slow.UpdateIntervalSeconds = 120
	if SessionKey(fast) != SessionKey(slow) {
		t.Fatal("updateIntervalSeconds must not split the stream Open key")
	}
	if SessionHex(fast) != SessionHex(slow) {
		t.Fatal("stream cache prefix must follow the session, not metrics interval")
	}
	if SessionKey(fast) != "lapi:stream:"+SessionHex(fast) {
		t.Fatal("stream Open key must be lapi:stream: plus SessionHex only")
	}
	if !strings.HasPrefix(Key(fast), "lapi:") || strings.HasPrefix(Key(fast), "lapi:stream:") {
		t.Fatal("live Open key must be lapi: plus SessionHex, not StoreKey")
	}
	if strings.HasPrefix(SessionKey(fast), "decisionstore:") || SessionKey(fast) == StoreKey(fast) {
		t.Fatal("Client Open key must not reuse StoreKey")
	}
	redisA := testStreamConfig("lapi.example:8080", 1)
	redisA.RedisCacheHost = "redis-a:6379"
	redisB := testStreamConfig("lapi.example:8080", 1)
	redisB.RedisCacheHost = "redis-b:6379"
	if SessionKey(redisA) != SessionKey(redisB) {
		t.Fatal("stream SessionKey must omit Redis store parameters")
	}
}

func TestSessionKey_DifferentLapiKeysAreDistinct(t *testing.T) {
	a := testStreamConfig("lapi.example:8080", 1)
	b := testStreamConfig("lapi.example:8080", 1)
	b.CrowdsecLapiKey = "other-key"
	if SessionKey(a) == SessionKey(b) {
		t.Fatal("two LAPI keys on one host must be different stream sessions")
	}
}

func testNoneConfig(host string, metricsInterval int64) *configuration.Config {
	cfg := testStreamConfig(host, metricsInterval)
	cfg.CrowdsecMode = configuration.NoneMode
	return cfg
}

func TestKey_NoneMetricsIntervalSplitsClient(t *testing.T) {
	fast := testNoneConfig("lapi.example:8080", 1)
	slow := testNoneConfig("lapi.example:8080", 600)
	if Key(fast) == Key(slow) {
		t.Fatal("none Key must include MetricsUpdateIntervalSeconds")
	}
	if StoreKey(fast) != StoreKey(slow) {
		t.Fatal("none StoreKey helper must omit MetricsUpdateIntervalSeconds")
	}
	streamFast := testStreamConfig("lapi.example:8080", 1)
	streamSlow := testStreamConfig("lapi.example:8080", 600)
	if SessionKey(streamFast) != SessionKey(streamSlow) {
		t.Fatal("stream SessionKey must still omit metrics interval")
	}
	redisA := testNoneConfig("lapi.example:8080", 1)
	redisA.RedisCacheHost = "redis-a:6379"
	redisB := testNoneConfig("lapi.example:8080", 1)
	redisB.RedisCacheHost = "redis-b:6379"
	if Key(redisA) == Key(redisB) {
		t.Fatal("live/none Key must still include Redis store parameters")
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
	if SessionKey(base) != SessionKey(policy) || IdentityHex(base) != IdentityHex(policy) {
		t.Fatal("policy knobs must not change stream or live reclaim keys")
	}
	if SessionKey(base) != SessionKey(tlsOnly) || IdentityHex(base) != IdentityHex(tlsOnly) {
		t.Fatal("HTTP timeout and LAPI TLS must not change stream or live reclaim keys")
	}
}

func TestClient_ReclaimGrace(t *testing.T) {
	if reclaim.ProcessGrace != 30*time.Second {
		t.Fatalf("ProcessGrace: %v", reclaim.ProcessGrace)
	}
}

func TestClient_LifecycleLogs(t *testing.T) {
	log, logSink := newTestLogSink(slog.LevelInfo)
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

func TestOpenStream_LiveMetricsMismatchSharesAndWarns(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	log, logSink := newTestLogSink(slog.LevelDebug)
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	joinerCtx, joinerCancel := context.WithCancel(context.Background())
	t.Cleanup(ownerCancel)
	t.Cleanup(joinerCancel)

	ownerCfg := testStreamConfig(parsed.Host, 1)
	ownerCfg.UpdateIntervalSeconds = 30
	owner, err := OpenStream(ownerCtx, ownerCfg, log, "owner-mw", "test")
	if err != nil {
		t.Fatal(err)
	}
	joinerCfg := testStreamConfig(parsed.Host, 1)
	joinerCfg.UpdateIntervalSeconds = 120
	joiner, err := OpenStream(joinerCtx, joinerCfg, log, "joiner-mw", "test")
	if err != nil {
		t.Fatal(err)
	}
	if owner != joiner {
		t.Fatal("interval mismatch must share one Client")
	}
	if owner.updateInterval != 30 {
		t.Fatal("running ticker must keep the create-time interval")
	}
	if owner.StreamFetches() < 1 {
		t.Fatal("owner must have polled once")
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("one ticker must poll once at startup, hits=%d", atomic.LoadInt64(hits))
	}
	owner.Close() // stop the tickers that log into logSink before reading it
	logged := logSink.String()
	requireSessionOwnedWarn(t, logged, "updateIntervalSeconds", "joiner-mw", "owner-mw")
	if !strings.Contains(logged, msgProcessWideOwnership) {
		t.Fatalf("first create must name process-wide ownership: %s", logged)
	}
}

func TestOpenStream_SameKeyTwoNamesShareOneClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg := testStreamConfig(parsed.Host, 1)
	first, err := OpenStream(ctx, cfg, slog.Default(), "alpha", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, cfg, slog.Default(), "beta", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("two stream names on one LAPI key must share one Client")
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("only one stream ticker must poll, hits=%d", atomic.LoadInt64(hits))
	}
}

func TestOpenStream_TwoLapiKeysStayTwoClients(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.CrowdsecLapiKey = "other-key"
	first, err := OpenStream(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two LAPI keys on one host must stay two Clients")
	}
	if SessionKey(firstCfg) == SessionKey(secondCfg) {
		t.Fatal("two LAPI keys must Open different SessionKey values")
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
	log, logSink := newTestLogSink(slog.LevelInfo)
	ctx, cancel := context.WithCancel(context.Background())
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.UpdateIntervalSeconds = 30
	first, err := OpenStream(ctx, firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitClientSleeping(t, first)

	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.UpdateIntervalSeconds = 120
	second, err := OpenStream(context.Background(), secondCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("sleeping interval change must Wake the same Client")
	}
	if atomic.LoadInt64(&first.isCrowdsecStreamStartup) != 0 {
		t.Fatal("Wake must resume with startup=false")
	}
	second.Close()
	requireSessionOwnedWarn(t, logSink.String(), "updateIntervalSeconds", "reload")
}

func TestOpenStream_SleepingRedisHostWakesSameSlot(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, logSink := newTestLogSink(slog.LevelInfo)
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.RedisCacheHost = "redis-a:6379"
	ctx, cancel := context.WithCancel(context.Background())
	first, err := OpenStream(ctx, firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	createStore := first.decisionStore
	cancel()
	waitClientSleeping(t, first)

	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.RedisCacheHost = "redis-b:6379"
	second, err := OpenStream(context.Background(), secondCfg, log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("sleeping Redis host change must Wake the same Client")
	}
	if atomic.LoadInt64(&first.isCrowdsecStreamStartup) != 0 {
		t.Fatal("Wake must resume with startup=false")
	}
	if first.decisionStore != createStore {
		t.Fatal("Wake must keep the store create() opened")
	}
	second.Close()
	requireSessionOwnedWarn(t, logSink.String(), "redisCacheHost", "reload")
}

func TestOpenStream_DifferentRedisSharesClientAndStore(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, logSink := newTestLogSink(slog.LevelInfo)
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	joinerCtx, joinerCancel := context.WithCancel(context.Background())
	t.Cleanup(ownerCancel)
	t.Cleanup(joinerCancel)
	redisACfg := testStreamConfig(parsed.Host, 1)
	redisACfg.RedisCacheHost = "redis-a:6379"
	redisBCfg := testStreamConfig(parsed.Host, 1)
	redisBCfg.RedisCacheHost = "redis-b:6379"
	redisAClient, err := OpenStream(ownerCtx, redisACfg, log, "redis-a", "test")
	if err != nil {
		t.Fatal(err)
	}
	redisBClient, err := OpenStream(joinerCtx, redisBCfg, log, "redis-b", "test")
	if err != nil {
		t.Fatal(err)
	}
	if redisAClient != redisBClient {
		t.Fatal("different Redis must share the Client")
	}
	if redisAClient.decisionStore != redisBClient.decisionStore {
		t.Fatal("different Redis must share the store")
	}
	if SessionKey(redisACfg) != SessionKey(redisBCfg) {
		t.Fatal("different Redis must share SessionKey")
	}
	putBan(redisAClient.decisionStore)
	got, getErr := lookupBan(redisBClient.decisionStore)
	if getErr != nil || got != decisionscope.BannedValue {
		t.Fatalf("ban in store A must hit in store B: %q err %v", got, getErr)
	}
	redisAClient.Close()
	requireSessionOwnedWarn(t, logSink.String(), "redisCacheHost", "redis-a", "redis-b")
}

func TestOpenStream_HeaderMapMismatchSharesClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, logSink := newTestLogSink(slog.LevelInfo)
	ctx := context.Background()
	countryCfg := testStreamConfig(parsed.Host, 1)
	countryCfg.DecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	userCfg := testStreamConfig(parsed.Host, 1)
	userCfg.DecisionScopeHeaders = map[string]string{"username": "X-User"}
	countryClient, err := OpenStream(ctx, countryCfg, log, "country", "test")
	if err != nil {
		t.Fatal(err)
	}
	userClient, err := OpenStream(ctx, userCfg, log, "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	if countryClient != userClient {
		t.Fatal("header-map mismatch must share one Client")
	}
	putBan(countryClient.decisionStore)
	got, getErr := lookupBan(userClient.decisionStore)
	if getErr != nil || got != decisionscope.BannedValue {
		t.Fatalf("header-map mismatch must still share remediations: %q err %v", got, getErr)
	}
	countryClient.Close()
	if strings.Contains(logSink.String(), MsgSessionOwnedIgnored) {
		t.Fatalf("header-map mismatch must not WARN session-owned knobs: %s", logSink.String())
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

	first, err := OpenStream(ctx, firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	fetches := first.StreamFetches()
	hitsBefore := atomic.LoadInt64(hits)
	second, err := OpenStream(ctx, secondCfg, log, "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("failure-action-only New must reuse the Client")
	}
	if second.StreamFetches() != fetches {
		t.Fatal("failure-action-only New must not start another stream fetch")
	}
	if atomic.LoadInt64(hits) != hitsBefore {
		t.Fatal("failure-action-only New must not hit LAPI again")
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
	log, logSink := newTestLogSink(slog.LevelInfo)
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.HTTPTimeoutSeconds = 10
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.HTTPTimeoutSeconds = 30

	first, err := OpenStream(ctx, firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, log, "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("TLS/timeout-only New must reuse the Client")
	}
	current := second.currentTransport()
	if current == nil || current.httpTimeoutSeconds != 30 {
		t.Fatalf("adopted timeout: %+v", current)
	}
	if current.httpClient.Timeout != 30*time.Second {
		t.Fatalf("HTTP timeout %v", current.httpClient.Timeout)
	}
	second.Close() // stop the tickers that log into logSink before reading it
	logged := logSink.String()
	if !strings.Contains(logged, "lapi transport replaced") {
		t.Fatalf("INFO must name transport replace: %s", logged)
	}
	if !strings.Contains(logged, "lapi session joiner adopted") {
		t.Fatalf("INFO must mark joiner adopted: %s", logged)
	}
	if strings.Contains(logged, MsgSessionOwnedIgnored) {
		t.Fatalf("TLS/timeout must not WARN session-owned knobs: %s", logged)
	}
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

	first, err := OpenStream(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("LAPI override-only New must reuse the Client")
	}
	current := second.currentTransport()
	if current == nil || current.httpTimeoutSeconds != 30 {
		t.Fatalf("adopted timeout: %+v", current)
	}
	if current.httpClient.Timeout != 30*time.Second {
		t.Fatalf("HTTP timeout %v", current.httpClient.Timeout)
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

	first, err := OpenStream(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenStream(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("shared-default timeout New must reuse the Client")
	}
	current := second.currentTransport()
	if current == nil || current.httpTimeoutSeconds != 20 {
		t.Fatalf("adopted timeout: %+v", current)
	}
	if current.httpClient.Timeout != 20*time.Second {
		t.Fatalf("HTTP timeout %v", current.httpClient.Timeout)
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
	first, err := OpenStream(ctx, firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}

	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.HTTPTimeoutSeconds = 10
	secondCfg.CrowdsecLapiHTTPTimeoutSeconds = 10
	second, err := OpenStream(ctx, secondCfg, log, "second", "test")
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

// requireSessionOwnedWarn fails unless logged has the subscribe WARN, field, holder names, and isolation clause.
func requireSessionOwnedWarn(t *testing.T, logged, field string, names ...string) {
	t.Helper()
	if !strings.Contains(logged, MsgSessionOwnedIgnored) {
		t.Fatalf("missing subscribe WARN: %s", logged)
	}
	if !strings.Contains(logged, field) {
		t.Fatalf("WARN must list %s: %s", field, logged)
	}
	for _, name := range names {
		if !strings.Contains(logged, name) {
			t.Fatalf("WARN must list holder %s: %s", name, logged)
		}
	}
	if !strings.Contains(logged, msgIsolationNeedsSecondKey) {
		t.Fatalf("WARN must name second API key: %s", logged)
	}
}

func TestOpenStream_TwoRoutersOneAliasOneNameOnWarn(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, logSink := newTestLogSink(slog.LevelInfo)
	firstCtx, firstCancel := context.WithCancel(context.Background())
	secondCtx, secondCancel := context.WithCancel(context.Background())
	t.Cleanup(firstCancel)
	t.Cleanup(secondCancel)
	firstCfg := testStreamConfig(parsed.Host, 1)
	firstCfg.UpdateIntervalSeconds = 30
	if _, err := OpenStream(firstCtx, firstCfg, log, "same-alias", "test"); err != nil {
		t.Fatal(err)
	}
	secondCfg := testStreamConfig(parsed.Host, 1)
	secondCfg.UpdateIntervalSeconds = 120
	second, err := OpenStream(secondCtx, secondCfg, log, "same-alias", "test")
	if err != nil {
		t.Fatal(err)
	}
	second.Close()
	logged := logSink.String()
	requireSessionOwnedWarn(t, logged, "updateIntervalSeconds", "same-alias")
	if strings.Count(logged, `"same-alias"`) < 1 {
		t.Fatalf("distinct names must contain the alias once: %s", logged)
	}
}
