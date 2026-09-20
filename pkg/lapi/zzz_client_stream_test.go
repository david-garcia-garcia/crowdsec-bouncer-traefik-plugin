package lapi

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestHandleStreamCacheIntervalOnePollsEveryTick proves updateInterval 1 still GETs stream on every tick.
func TestHandleStreamCacheIntervalOnePollsEveryTick(t *testing.T) {
	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	lapiClient, _ := newTestRangeClient(t)
	lapiClient.updateInterval = 1
	lapiClient.crowdsecScheme = "http"
	lapiClient.crowdsecHost = parsed.Host
	lapiClient.crowdsecPath = "/"
	lapiClient.crowdsecStreamRoute = crowdsecLapiStreamRoute
	attachTestTransport(lapiClient, server.Client(), "test-key")

	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if got := lapiClient.StreamFetches(); got != 1 {
		t.Fatalf("first poll streamFetches=%d, want 1", got)
	}
	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := lapiClient.StreamFetches(); got != 2 {
		t.Fatalf("second poll streamFetches=%d, want 2", got)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("LAPI hits=%d, want 2", got)
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

func newTestStreamPoller(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newTestRangeClient(t)
	client.updateInterval = 60
	client.crowdsecScheme = "http"
	client.crowdsecHost = parsed.Host
	client.crowdsecPath = "/"
	client.crowdsecStreamRoute = crowdsecLapiStreamRoute
	attachTestTransport(client, server.Client(), "test-key")
	return client
}

func TestHandleStreamCache_FailedGetAllowsRetry(t *testing.T) {
	server, _ := testFailThenServeStreamLAPI(t, 1)
	client := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err == nil {
		t.Fatal("stream 500 must return an error")
	}
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
}

// TestHandleStreamCache_NextTickRepollsAfterFailure proves the released lease lets the very next
// tick call LAPI again rather than waiting out max(updateInterval-1, 1) seconds.
func TestHandleStreamCache_NextTickRepollsAfterFailure(t *testing.T) {
	server, hits := testFailThenServeStreamLAPI(t, 1)
	client := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err == nil {
		t.Fatal("stream 500 must return an error")
	}
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("LAPI stream hits=%d, want 2 (the retry did not re-poll)", got)
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
	client := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err == nil {
		t.Fatal("an undecodable stream body must return an error")
	}
}

func newSharedStreamPoller(t *testing.T, store *decisionstore.Store, host string) *Client {
	t.Helper()
	client := &Client{
		decisionStore:       store,
		log:                 logger.New("ERROR", ""),
		crowdsecScheme:      "http",
		crowdsecHost:        host,
		crowdsecPath:        "/",
		crowdsecStreamRoute: crowdsecLapiStreamRoute,
		updateInterval:      60,
	}
	return client
}

func TestHandleStreamCache_TwoMemoryPollersBothFetch(t *testing.T) {
	server, hits := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := decisionstore.NewMemory(logger.New("ERROR", ""), false)
	first := newSharedStreamPoller(t, store, parsed.Host)
	second := newSharedStreamPoller(t, store, parsed.Host)
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

	if got := first.StreamFetches() + second.StreamFetches(); got != 2 {
		t.Fatalf("streamFetches=%d, want 2", got)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("LAPI hits=%d, want 2", got)
	}
}

func TestHandleStreamCache_TwoRedisPollersBothFetch(t *testing.T) {
	lapiServer, hits := testStreamLAPI(t)
	parsed, err := url.Parse(lapiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	redisServer := startTestLeaseRedis(t)
	store := newTestRedisStore(t, redisServer.addr(), nil, "sess")
	first := newSharedStreamPoller(t, store, parsed.Host)
	second := newSharedStreamPoller(t, store, parsed.Host)
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

	if got := first.StreamFetches() + second.StreamFetches(); got != 2 {
		t.Fatalf("streamFetches=%d, want 2", got)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("LAPI hits=%d, want 2", got)
	}
}

// testReplacementStreamLAPI serves one stream payload with the given new and deleted decisions.
func testReplacementStreamLAPI(t *testing.T, newItems, deletedItems []Decision) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !strings.Contains(req.URL.Path, "stream") {
			rw.WriteHeader(http.StatusOK)
			return
		}
		if err := json.NewEncoder(rw).Encode(Stream{New: newItems, Deleted: deletedItems}); err != nil {
			t.Errorf("stream stub encode: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// TestHunt_StreamAppliesDeletedBeforeNew proves a same-window IP replacement stays banned.
func TestHunt_StreamAppliesDeletedBeforeNew(t *testing.T) {
	const ipValue = "203.0.113.10"
	server := testReplacementStreamLAPI(t, []Decision{{
		Type:     "ban",
		Scope:    "ip",
		Value:    ipValue,
		Duration: "1h",
		Origin:   "crowdsec",
	}}, []Decision{{
		Type:  "ban",
		Scope: "ip",
		Value: ipValue,
	}})
	client := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("replacement poll: %v", err)
	}
	kind, _, _, err := client.LookupRemediation(ipValue, net.ParseIP(ipValue), nil)
	if err != nil || kind != decisionscope.BannedValue {
		t.Fatalf("same-window IP replacement must stay banned, got %q err %v", kind, err)
	}
}

// TestHunt_StreamRangeAppliesDeletedBeforeNew proves a same-window Range replacement stays banned.
func TestHunt_StreamRangeAppliesDeletedBeforeNew(t *testing.T) {
	const cidr = "10.0.0.0/8"
	server := testReplacementStreamLAPI(t, []Decision{{
		Type:     "ban",
		Scope:    "range",
		Value:    cidr,
		Duration: "1h",
		Origin:   "crowdsec",
	}}, []Decision{{
		Type:  "ban",
		Scope: "range",
		Value: cidr,
	}})
	client := newTestStreamPoller(t, server)

	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("replacement poll: %v", err)
	}
	got, _, _, err := client.LookupRemediation("10.1.2.3", net.ParseIP("10.1.2.3"), nil)
	if err != nil || !decisionscope.IsActiveRemediation(got) {
		t.Fatalf("same-window Range replacement must stay banned, got %q err %v", got, err)
	}
}
