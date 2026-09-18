package lapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// testFailThenServeStreamLAPI fails the first failures stream GETs, then answers empty deltas.
func testFailThenServeStreamLAPI(t *testing.T, failures int64) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, "stream") {
			rw.WriteHeader(http.StatusOK)
			return
		}
		if atomic.AddInt64(&hits, 1) <= failures {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := json.NewEncoder(rw).Encode(map[string][]Decision{"new": {}, "deleted": {}}); err != nil {
			t.Errorf("stream stub encode: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

// newTestStreamPoller builds a stream Client pointed at host that shares cacheClient.
func newTestStreamPoller(t *testing.T, server *httptest.Server) (*Client, *cache.Client) {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, cacheClient := newTestRangeClient(t)
	client.updateInterval = 60
	client.crowdsecScheme = "http"
	client.crowdsecHost = parsed.Host
	client.crowdsecPath = "/"
	client.crowdsecStreamRoute = crowdsecLapiStreamRoute
	attachTestTransport(client, server.Client(), "test-key")
	return client, cacheClient
}

// TestHandleStreamCache_FailedGetReleasesLease proves a poll that won the lease and then failed
// drops cache key updated, instead of parking every poller until the TTL expires.
func TestHandleStreamCache_FailedGetReleasesLease(t *testing.T) {
	server, _ := testFailThenServeStreamLAPI(t, 1)
	client, cacheClient := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err == nil {
		t.Fatal("stream 500 must return an error")
	}
	if _, err := cacheClient.Get(cacheTimeoutKey); err == nil {
		t.Fatal("a failed poll must release the stream lease")
	}
}

// TestHandleStreamCache_NextTickRepollsAfterFailure proves the released lease lets the very next
// tick call LAPI again rather than waiting out max(updateInterval-1, 1) seconds.
func TestHandleStreamCache_NextTickRepollsAfterFailure(t *testing.T) {
	server, hits := testFailThenServeStreamLAPI(t, 1)
	client, cacheClient := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err == nil {
		t.Fatal("stream 500 must return an error")
	}
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("retry after a released lease: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("LAPI stream hits=%d, want 2 (the retry did not re-poll)", got)
	}
	if _, err := cacheClient.Get(cacheTimeoutKey); err != nil {
		t.Fatalf("a successful poll must keep the lease: %v", err)
	}
}

// TestHandleStreamCache_UndecodableBodyReleasesLease proves the release covers a failure after the
// GET, so the decode stage does not diverge from the fetch stage.
func TestHandleStreamCache_UndecodableBodyReleasesLease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if _, err := rw.Write([]byte("{not json")); err != nil {
			t.Errorf("stream stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	client, cacheClient := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err == nil {
		t.Fatal("an undecodable stream body must return an error")
	}
	if _, err := cacheClient.Get(cacheTimeoutKey); err == nil {
		t.Fatal("a poll that failed to decode must release the stream lease")
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
