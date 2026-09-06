package lapi

import (
	"net/url"
	"testing"
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
	lapiClient.crowdsecHeader = crowdsecLapiHeader
	lapiClient.crowdsecKey = "test-key"
	lapiClient.httpClient = server.Client()

	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("interval-1 miss: %v", err)
	}
	if _, err := cacheClient.Get(cacheTimeoutKey); err != nil {
		t.Fatalf("interval-1 must store lease, Get: %v", err)
	}
	if got := lapiClient.StreamFetches(); got != 1 {
		t.Fatalf("first poll streamFetches=%d, want 1", got)
	}
	if got := *hits; got != 1 {
		t.Fatalf("first poll LAPI hits=%d, want 1", got)
	}

	if err := lapiClient.handleStreamCache(); err != nil {
		t.Fatalf("interval-1 lease hit: %v", err)
	}
	if got := lapiClient.StreamFetches(); got != 1 {
		t.Fatalf("lease hit streamFetches=%d, want 1", got)
	}
	if got := *hits; got != 1 {
		t.Fatalf("lease hit LAPI hits=%d, want 1", got)
	}
}
