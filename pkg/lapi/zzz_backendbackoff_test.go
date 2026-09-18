package lapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// attachTestGate puts a one-failure Gate on client and freezes jitter.
func attachTestGate(t *testing.T, client *Client) *backendbackoff.Gate {
	t.Helper()
	gate, err := backendbackoff.New(backendbackoff.Config{
		FailureRatio: 0.30,
		TripFailures: 1,
		BaseCooldown: time.Second,
		MaxCooldown:  time.Second,
		Jitter:       0,
		TTL:          time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	client.gate = gate
	return gate
}

func testFailingLiveLAPI(t *testing.T) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func TestLiveLookup_GateSkipDoesNotHitLAPI(t *testing.T) {
	server, hits := testFailingLiveLAPI(t)
	client := newTestLiveClient(t, server)
	attachTestGate(t, client)

	value, err := client.LiveLookup(context.Background(), "1.2.3.4", nil, 0)
	if err == nil || decisionscope.IsActiveRemediation(value) {
		t.Fatalf("first failure must be a query error, value %q err %v", value, err)
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("first lookup hits=%d, want 1", atomic.LoadInt64(hits))
	}

	value, err = client.LiveLookup(context.Background(), "1.2.3.4", nil, 0)
	if err == nil || decisionscope.IsActiveRemediation(value) {
		t.Fatalf("denied lookup must apply FailureAction, value %q err %v", value, err)
	}
	if !strings.Contains(err.Error(), "queryLiveDecisions:skipped") {
		t.Fatalf("skip error %q", err)
	}
	if strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "banned") {
		t.Fatalf("skip must not reuse unreachable/banned: %v", err)
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("denied lookup must not hit LAPI, hits=%d", atomic.LoadInt64(hits))
	}
}

func TestLiveLookup_SuccessReportRecovers(t *testing.T) {
	var hits int64
	var serveOK atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		if !serveOK.Load() {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = rw.Write([]byte("null"))
	}))
	t.Cleanup(server.Close)
	client := newTestLiveClient(t, server)
	gate := attachTestGate(t, client)

	if _, err := client.LiveLookup(context.Background(), "1.2.3.4", nil, 0); err == nil {
		t.Fatal("first failure expected")
	}
	now := time.Now().Add(2 * time.Second)
	gate.SetNowForTest(func() time.Time { return now })
	serveOK.Store(true)

	if _, err := client.LiveLookup(context.Background(), "1.2.3.4", nil, 0); err != nil {
		t.Fatalf("HALF-OPEN success: %v", err)
	}
	if _, err := client.LiveLookup(context.Background(), "1.2.3.4", nil, 0); err != nil {
		t.Fatalf("recovered lookup: %v", err)
	}
	if atomic.LoadInt64(&hits) != 3 {
		t.Fatalf("hits=%d, want 3 (fail, recover, follow-up)", atomic.LoadInt64(&hits))
	}
}

func TestLiveLookup_LaterScopeGETAlsoSkips(t *testing.T) {
	var hits int64
	var scopeHits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt64(&hits, 1)
		if req.URL.Query().Get("scope") != "" {
			atomic.AddInt64(&scopeHits, 1)
		}
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client := newTestLiveClient(t, server)
	attachTestGate(t, client)

	if _, err := client.LiveLookup(context.Background(), "1.2.3.4", nil, 0); err == nil {
		t.Fatal("first IP failure expected")
	}
	if _, err := client.LiveLookup(context.Background(), "1.2.3.4", map[string]string{"country": "FR"}, 0); err == nil {
		t.Fatal("scoped lookup after trip must error")
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Fatalf("scoped lookup after trip must not hit LAPI, hits=%d", atomic.LoadInt64(&hits))
	}
	if atomic.LoadInt64(&scopeHits) != 0 {
		t.Fatalf("header-scope GET must be skipped, scopeHits=%d", atomic.LoadInt64(&scopeHits))
	}
}

func TestLiveLookup_ActiveBanOutranksDeniedScopeGET(t *testing.T) {
	server, _ := testFailingLiveLAPI(t)
	client := newTestLiveClient(t, server)
	attachTestGate(t, client)
	if _, err := client.LiveLookup(context.Background(), "1.2.3.4", nil, 0); err == nil {
		t.Fatal("trip expected")
	}
	banned := decisionscope.BannedValue
	chosen, _, err := client.mergeLiveScope(context.Background(), banned, time.Hour, "country", "FR", true, 60)
	if err == nil {
		t.Fatal("denied scope GET must return an error")
	}
	if chosen != banned {
		t.Fatalf("ban must outrank a denied scope GET, got %q", chosen)
	}
}

func TestHandleStreamCache_PollsStayUngated(t *testing.T) {
	server, hits := testFailThenServeStreamLAPI(t, 8)
	client, _ := newTestStreamPoller(t, server)
	if client.gate != nil {
		t.Fatal("stream poller must not own a Gate")
	}
	for range 8 {
		_ = client.handleStreamCache()
	}
	if got := atomic.LoadInt64(hits); got != 8 {
		t.Fatalf("stream polls must keep hitting LAPI, hits=%d want 8", got)
	}
}

func TestOpen_LiveHasGateStreamDoesNot(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	streamCfg := testStreamConfig(parsed.Host, 0)
	streamClient, err := OpenStream(ctx, streamCfg, slog.Default(), "stream", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(streamClient.Close)
	if streamClient.gate != nil {
		t.Fatal("stream Client must not construct a Gate")
	}

	liveCfg := testStreamConfig(parsed.Host, 0)
	liveCfg.CrowdsecMode = configuration.LiveMode
	liveClient, err := OpenLive(ctx, liveCfg, slog.Default(), "live", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(liveClient.Close)
	if liveClient.gate == nil {
		t.Fatal("live Client must own a Gate")
	}
}

func TestOpenLive_BackoffKnobDoesNotSplitClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	firstCfg := testStreamConfig(parsed.Host, 0)
	firstCfg.CrowdsecMode = configuration.LiveMode
	first, err := OpenLive(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(first.Close)
	secondCfg := testStreamConfig(parsed.Host, 0)
	secondCfg.CrowdsecMode = configuration.LiveMode
	secondCfg.BackendBackoffTripFailures = 9
	second, err := OpenLive(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("backoff knobs must not split the live Client")
	}
}
