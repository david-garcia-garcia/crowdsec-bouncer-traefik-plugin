package lapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/health"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testLiveClient(t *testing.T, server *httptest.Server, tracker *health.Tracker) *Client {
	t.Helper()
	lapiURL, _ := url.Parse(server.URL)
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecHeader: crowdsecLapiHeader,
		crowdsecKey:    "test-key",
		crowdsecMode:   configuration.LiveMode,
		httpClient:     server.Client(),
		cacheClient:    cacheClient,
		failureTracker: tracker,
		log:            logger.New("ERROR", ""),
	}
}

func Test_liveLookup_backoffSkipsHTTP(t *testing.T) {
	var hits int32
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	client := testLiveClient(t, lapi, health.New(time.Minute, 0, 1, logger.New("ERROR", "")))

	if _, err := client.LiveLookup("1.2.3.4", nil); err == nil {
		t.Fatal("first live 500 expected an error")
	} else if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("first lookup err=%v hits=%d want 1", err, hits)
	}
	if _, err := client.LiveLookup("1.2.3.4", nil); err == nil {
		t.Fatal("backoff live lookup expected an error")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("backoff must skip HTTP, hits=%d", hits)
	}
}

func Test_liveLookup_bannedDecisionDoesNotRecordFailure(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(rw).Encode([]Decision{{
			Type:     "ban",
			Scope:    "ip",
			Value:    "1.2.3.4",
			Duration: "1h",
			Origin:   "cscli",
		}})
	}))
	defer lapi.Close()
	tracker := health.New(time.Minute, 0, 1, logger.New("ERROR", ""))
	client := testLiveClient(t, lapi, tracker)
	value, err := client.LiveLookup("1.2.3.4", nil)
	if err == nil {
		t.Fatal("banned live lookup returns a sentinel error")
	}
	if !decisionscope.IsActiveRemediation(value) {
		t.Fatalf("want ban, got %q", value)
	}
	if tracker.IsUnhealthy() {
		t.Fatal("a ban decision must not trip the Tracker")
	}
}

func TestIdentityHex_BackoffKnobsSplitLiveIdentity(t *testing.T) {
	a := configuration.New()
	b := configuration.New()
	a.CrowdsecLapiKey = "k"
	b.CrowdsecLapiKey = "k"
	b.LapiFailureBackoffBucketThreshold = 9
	if IdentityHex(a) == IdentityHex(b) {
		t.Fatal("live identity must include LAPI backoff knobs")
	}
	if SessionPrefix(a) != SessionPrefix(b) {
		t.Fatal("stream session prefix must not include LAPI backoff knobs")
	}
}
