package crowdsecconnection

import (
	"bytes"
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

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
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

func TestSessionKey_SameLapiKeyIgnoresMetricsInterval(t *testing.T) {
	fast := testStreamConfig("lapi.example:8080", 1)
	slow := testStreamConfig("lapi.example:8080", 600)
	if SessionKey(fast) != SessionKey(slow) {
		t.Fatal("same LAPI URL+key must share a stream session even when metrics intervals differ")
	}
	if CachePrefix(fast) != CachePrefix(slow) {
		t.Fatal("stream cache prefix must follow the session, not metrics interval")
	}
	if IdentityHex(fast) == IdentityHex(slow) {
		t.Fatal("live/none identity must still include metrics interval")
	}
}

func TestSessionKey_DifferentHostsAreDistinct(t *testing.T) {
	a := testStreamConfig("lapi-a:8080", 1)
	b := testStreamConfig("lapi-b:8080", 1)
	if SessionKey(a) == SessionKey(b) {
		t.Fatal("different LAPI hosts must be different stream sessions")
	}
}

func TestOpenStream_LiveMetricsMismatchWarnsAndShares(t *testing.T) {
	reclaim.ResetWith(0)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	owner, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "owner-mw", "test")
	if err != nil {
		t.Fatal(err)
	}
	joiner, err := OpenStream(ctx, testStreamConfig(parsed.Host, 600), log, "joiner-mw", "test")
	if err != nil {
		t.Fatal(err)
	}
	if owner != joiner {
		t.Fatal("second live middleware on the same LAPI key must wire to the owner connection")
	}
	if owner.streamOwner != "owner-mw" {
		t.Fatalf("owner name: %q", owner.streamOwner)
	}
	if owner.StreamFetches() < 1 {
		t.Fatal("owner must have polled once")
	}
	if atomic.LoadInt64(hits) != 1 {
		t.Fatalf("one ticker must poll once at startup, hits=%d", atomic.LoadInt64(hits))
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "owner-mw") || !strings.Contains(logged, "joiner-mw") {
		t.Fatalf("warn must name both middlewares: %s", logged)
	}
	if !strings.Contains(logged, "metricsUpdateIntervalSeconds") {
		t.Fatalf("warn must name ignored knobs: %s", logged)
	}
	if !strings.Contains(logged, "one cursor per bouncer row") {
		t.Fatalf("warn must mention CrowdSec cursor: %s", logged)
	}
}

func TestOpenStream_GraceSnapshotChangeStopsOldTickerFirst(t *testing.T) {
	reclaim.ResetWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetWith(reclaim.DefaultGrace) })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	ctx, cancel := context.WithCancel(context.Background())
	first, err := OpenStream(ctx, testStreamConfig(parsed.Host, 1), log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	fetchesBeforeCancel := first.StreamFetches()
	cancel()
	waitStreamSessionInGrace(t, testStreamConfig(parsed.Host, 1))

	second, err := OpenStream(context.Background(), testStreamConfig(parsed.Host, 600), log, "reload", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changed snapshot during grace must replace the connection")
	}
	if first.StreamFetches() != fetchesBeforeCancel {
		t.Fatal("old ticker must be stopped before the new poller starts")
	}
	if second.StreamFetches() < 1 {
		t.Fatal("new snapshot must start its own stream poll")
	}
}

// waitStreamSessionInGrace fails if the session never reaches zero holders with grace armed.
func waitStreamSessionInGrace(t *testing.T, cfg *configuration.Config) {
	t.Helper()
	sessionKey := SessionKey(cfg)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, holderCount, sleeping, found := reclaim.Peek(sessionKey)
		if found && holderCount == 0 && sleeping {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("stream session did not enter grace")
}
