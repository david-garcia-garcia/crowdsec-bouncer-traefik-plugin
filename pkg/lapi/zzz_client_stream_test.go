package lapi

import (
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestHandleStreamCacheIntervalOneStoresLease proves updateInterval 1 still stores
// cache key updated so a second poll skips LAPI (upstream #370 TTL 0 never stored).
func TestHandleStreamCacheIntervalOneStoresLease(t *testing.T) {
	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	lapiClient, cacheClient := newTestRangeClient(t)
	lapiClient.updateInterval = 1
	lapiClient.crowdsecScheme = "http"
	lapiClient.crowdsecHost = parsed.Host
	lapiClient.crowdsecPath = "/"
	lapiClient.crowdsecStreamRoute = crowdsecLapiStreamRoute
	attachTestTransport(lapiClient, server.Client(), "test-key")

	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("interval-1 miss: %v", err)
	}
	if _, err := cacheClient.Get(cacheTimeoutKey); err != nil {
		t.Fatalf("interval-1 must store lease, Get: %v", err)
	}
	if got := lapiClient.StreamFetches(); got != 1 {
		t.Fatalf("first poll streamFetches=%d, want 1", got)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("first poll LAPI hits=%d, want 1", got)
	}

	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("interval-1 lease hit: %v", err)
	}
	if got := lapiClient.StreamFetches(); got != 1 {
		t.Fatalf("lease hit streamFetches=%d, want 1", got)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("lease hit LAPI hits=%d, want 1", got)
	}
}

func newSharedStreamPoller(t *testing.T, cacheClient *cache.Client, host string) *Client {
	t.Helper()
	return &Client{
		cacheClient:         cacheClient,
		log:                 logger.New("ERROR", ""),
		crowdsecScheme:      "http",
		crowdsecHost:        host,
		crowdsecPath:        "/",
		crowdsecStreamRoute: crowdsecLapiStreamRoute,
		updateInterval:      60,
	}
}

func TestHandleStreamCache_TwoMemoryPollersOneFetch(t *testing.T) {
	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	shared := &cache.Client{}
	shared.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	first := newSharedStreamPoller(t, shared, parsed.Host)
	second := newSharedStreamPoller(t, shared, parsed.Host)
	attachTestTransport(first, server.Client(), "test-key")
	attachTestTransport(second, server.Client(), "test-key")

	var started sync.WaitGroup
	var release sync.WaitGroup
	started.Add(2)
	release.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	run := func(client *Client) {
		defer done.Done()
		started.Done()
		release.Wait()
		if pollErr := client.handleStreamCache(); pollErr != nil {
			t.Errorf("handleStreamCache: %v", pollErr)
		}
	}
	go run(first)
	go run(second)
	started.Wait()
	release.Done()
	done.Wait()

	if got := first.StreamFetches() + second.StreamFetches(); got != 1 {
		t.Fatalf("streamFetches=%d, want 1", got)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("LAPI hits=%d, want 1", got)
	}
}

func TestHandleStreamCache_TwoRedisPollersOneFetch(t *testing.T) {
	lapiServer, hits := testStreamLAPI(t)
	parsed, err := url.Parse(lapiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	redisServer := startTestLeaseRedis(t)
	shared := &cache.Client{}
	shared.New(logger.New("ERROR", ""), true, redisServer.addr(), nil, "", "", "sess")
	defer shared.Close()
	first := newSharedStreamPoller(t, shared, parsed.Host)
	second := newSharedStreamPoller(t, shared, parsed.Host)
	attachTestTransport(first, lapiServer.Client(), "test-key")
	attachTestTransport(second, lapiServer.Client(), "test-key")

	var started sync.WaitGroup
	var release sync.WaitGroup
	started.Add(2)
	release.Add(1)
	var done sync.WaitGroup
	done.Add(2)
	run := func(client *Client) {
		defer done.Done()
		started.Done()
		release.Wait()
		if pollErr := client.handleStreamCache(); pollErr != nil {
			t.Errorf("handleStreamCache: %v", pollErr)
		}
	}
	go run(first)
	go run(second)
	started.Wait()
	release.Done()
	done.Wait()

	if got := first.StreamFetches() + second.StreamFetches(); got != 1 {
		t.Fatalf("streamFetches=%d, want 1", got)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("LAPI hits=%d, want 1", got)
	}
}
