package lapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// testDelayedStreamLAPI counts stream GETs, tracks peak in-flight, and sleeps delay per GET.
func testDelayedStreamLAPI(t *testing.T, delay time.Duration) (*httptest.Server, *int64, *int64) {
	t.Helper()
	var hits, inFlight, maxInFlight int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, "stream") {
			w.WriteHeader(http.StatusOK)
			return
		}
		atomic.AddInt64(&hits, 1)
		current := atomic.AddInt64(&inFlight, 1)
		for {
			peak := atomic.LoadInt64(&maxInFlight)
			if current <= peak || atomic.CompareAndSwapInt64(&maxInFlight, peak, current) {
				break
			}
		}
		time.Sleep(delay)
		atomic.AddInt64(&inFlight, -1)
		_ = json.NewEncoder(w).Encode(map[string][]Decision{
			"new":     {},
			"deleted": {},
		})
	}))
	t.Cleanup(server.Close)
	return server, &hits, &maxInFlight
}

func TestHandleStreamTicker_SlowPollSkipsBusyTicks(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, hits, maxInFlight := testDelayedStreamLAPI(t, 2200*time.Millisecond)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 0)
	cfg.LapiUpdateIntervalSeconds = 1
	cfg.BouncerStartupBlock = false
	client, err := Open(context.Background(), cfg, logger.New("ERROR", ""), "slow-poll", "test")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3500 * time.Millisecond)
	if got := atomic.LoadInt64(maxInFlight); got > 1 {
		t.Fatalf("in-flight peak=%d, want at most 1", got)
	}
	if got := client.StreamFetches(); got > 2 {
		t.Fatalf("streamFetches=%d, want at most 2 in 3.5s", got)
	}
	if got := atomic.LoadInt64(hits); got > 2 {
		t.Fatalf("LAPI hits=%d, want at most 2 in 3.5s", got)
	}
}

func TestHandleStreamTicker_LeaseValidOverlapOneFetch(t *testing.T) {
	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := decisionstore.NewMemory(logger.New("ERROR", ""))
	client := newSharedStreamPoller(t, store, parsed.Host)
	attachTestTransport(client, server.Client(), "test-key")

	var started sync.WaitGroup
	var release sync.WaitGroup
	started.Add(2)
	release.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	run := func() {
		defer done.Done()
		started.Done()
		release.Wait()
		client.handleStreamTicker()
	}
	go run()
	go run()
	started.Wait()
	release.Done()
	done.Wait()

	if got := client.StreamFetches(); got != 1 {
		t.Fatalf("streamFetches=%d, want 1", got)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("LAPI hits=%d, want 1", got)
	}
}

func TestStreamHealthy_ConcurrentWithPollWrite(t *testing.T) {
	server, _, _ := testDelayedStreamLAPI(t, 50*time.Millisecond)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := decisionstore.NewMemory(logger.New("ERROR", ""))
	client := newSharedStreamPoller(t, store, parsed.Host)
	atomic.StoreInt64(&client.isCrowdsecStreamHealthy, 1)
	attachTestTransport(client, server.Client(), "test-key")

	var done sync.WaitGroup
	done.Add(1)
	go func() {
		defer done.Done()
		for range 1000 {
			_ = client.StreamHealthy()
		}
	}()
	client.handleStreamTicker()
	done.Wait()
}

func TestHandleStreamTicker_SleepThenWakeWhileInFlight(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, hits, maxInFlight := testDelayedStreamLAPI(t, 400*time.Millisecond)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 0)
	cfg.LapiUpdateIntervalSeconds = 60
	cfg.BouncerStartupBlock = false
	ctx, cancel := context.WithCancel(context.Background())
	first, err := Open(ctx, cfg, logger.New("ERROR", ""), "inflight-wake", "test")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	waitClientSleeping(t, first)
	second, err := Open(context.Background(), cfg, logger.New("ERROR", ""), "inflight-wake", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("Sleep then Wake must reuse the Client")
	}
	time.Sleep(600 * time.Millisecond)
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("LAPI hits=%d, want 1", got)
	}
	if got := atomic.LoadInt64(maxInFlight); got > 1 {
		t.Fatalf("in-flight peak=%d, want at most 1", got)
	}
}
