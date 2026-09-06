package lapi

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func newTestStreamClient(t *testing.T, lapi *httptest.Server, updateMaxFailure int64) *Client {
	t.Helper()
	lapiURL, err := url.Parse(lapi.URL)
	if err != nil {
		t.Fatal(err)
	}
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	return &Client{
		crowdsecScheme:          lapiURL.Scheme,
		crowdsecHost:            lapiURL.Host,
		crowdsecPath:            "/",
		crowdsecHeader:          crowdsecLapiHeader,
		crowdsecStreamRoute:     crowdsecLapiStreamRoute,
		updateInterval:          60,
		updateMaxFailure:        updateMaxFailure,
		isCrowdsecStreamStartup: true,
		isCrowdsecStreamHealthy: true,
		httpClient:              lapi.Client(),
		cacheClient:             cacheClient,
		log:                     logger.New("ERROR", ""),
		pluginVersion:           "test",
		decisionScopeHeaders:    map[string]string{decisionscope.ScopeCountry: "X-Country"},
	}
}

func TestHandleStreamTickerMarksUnhealthyWhenUpdateMaxFailureZero(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	client := newTestStreamClient(t, lapi, 0)
	client.handleStreamTicker()
	if client.StreamHealthy() {
		t.Fatal("first failed poll with updateMaxFailure 0 must mark stream unhealthy")
	}
}

func TestHandleStreamTickerStaysHealthyWhenUpdateMaxFailureDisabled(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	client := newTestStreamClient(t, lapi, -1)
	client.handleStreamTicker()
	if !client.StreamHealthy() {
		t.Fatal("updateMaxFailure -1 must keep stream healthy across failed polls")
	}
}

func TestHandleStreamTickerRecoversAfterSuccessfulPoll(t *testing.T) {
	fail := true
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if fail {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(Stream{})
	}))
	defer lapi.Close()
	client := newTestStreamClient(t, lapi, 0)
	client.handleStreamTicker()
	if client.StreamHealthy() {
		t.Fatal("failed poll must mark unhealthy before recovery")
	}
	fail = false
	client.handleStreamTicker()
	if !client.StreamHealthy() {
		t.Fatal("successful poll must restore stream healthy")
	}
	if client.updateFailure != 0 {
		t.Fatalf("successful poll must reset updateFailure, got %d", client.updateFailure)
	}
}

func TestHandleStreamCacheAppliesStreamJSON(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(Stream{
			New: []Decision{
				{Type: "ban", Scope: "Ip", Value: "1.2.3.4", Duration: "1h", Origin: "cscli"},
				{Type: "ban", Scope: "Country", Value: "FR", Duration: "1h", Origin: "cscli"},
				{Type: "ban", Scope: "Range", Value: "10.0.0.0/8", Duration: "1h", Origin: "cscli"},
			},
			Deleted: []Decision{
				{Type: "ban", Scope: "Ip", Value: "9.9.9.9"},
			},
		})
	}))
	defer lapi.Close()
	client := newTestStreamClient(t, lapi, -1)
	client.cacheClient.Set("9.9.9.9", cache.BannedValue, 60)
	if err := client.handleStreamCache(); err != nil {
		t.Fatalf("handleStreamCache: %v", err)
	}
	gotIP, err := client.cacheClient.Get("1.2.3.4")
	if err != nil || cache.RemediationKind(gotIP) != cache.BannedValue {
		t.Fatalf("IP ban not applied, got %q err=%v", gotIP, err)
	}
	countryKey := decisionscope.HeaderScopeKey(decisionscope.ScopeCountry, "FR")
	gotCountry, err := client.cacheClient.Get(countryKey)
	if err != nil || cache.RemediationKind(gotCountry) != cache.BannedValue {
		t.Fatalf("header scope ban not applied, got %q err=%v", gotCountry, err)
	}
	if got := client.RangeMembership().Remediation(net.ParseIP("10.1.2.3")); cache.RemediationKind(got) != cache.BannedValue {
		t.Fatalf("range ban not applied, got %q", got)
	}
	if _, err := client.cacheClient.Get("9.9.9.9"); err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("deleted IP should miss cache, err=%v", err)
	}
}

func TestHandleStreamCacheClearsLeaseOnFailure(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	client := newTestStreamClient(t, lapi, -1)
	if err := client.handleStreamCache(); err == nil {
		t.Fatal("failed stream GET must error")
	}
	if _, err := client.cacheClient.Get(cacheTimeoutKey); err == nil || err.Error() != cache.CacheMiss {
		t.Fatalf("failed poll must clear updated lease, err=%v", err)
	}
}

func TestCrowdsecQueryTransportErrorDoesNotPanic(t *testing.T) {
	client := &Client{
		crowdsecHeader: crowdsecLapiHeader,
		crowdsecKey:    "test-key",
		httpClient: &http.Client{
			Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("transport down")
			}),
		},
		log:           logger.New("ERROR", ""),
		pluginVersion: "test",
	}
	if _, err := client.crowdsecQuery("http://example.test/v1/decisions", nil); err == nil {
		t.Fatal("transport error must return unreachable")
	}
}

func TestCrowdsecQueryAloneMode401RetriesPostBody(t *testing.T) {
	var metricsAttempts int32
	var firstBody, secondBody []byte
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasSuffix(req.URL.Path, crowdsecCapiLoginRoute):
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(`{"code":200,"token":"renewed-token"}`))
		case strings.HasSuffix(req.URL.Path, crowdsecLapiMetricsRoute):
			body, _ := io.ReadAll(req.Body)
			attempt := atomic.AddInt32(&metricsAttempts, 1)
			if attempt == 1 {
				firstBody = append([]byte(nil), body...)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			secondBody = append([]byte(nil), body...)
			if req.Method != http.MethodPost {
				t.Errorf("retry must keep POST, got %s", req.Method)
			}
			rw.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected path %s", req.URL.Path)
		}
	}))
	defer lapi.Close()
	lapiURL, _ := url.Parse(lapi.URL)
	payload := []byte(`{"remediation_components":[{"name":"traefik","type":"middleware","version":"test","author":"test","metrics":[]}]}`)
	client := &Client{
		crowdsecScheme:    lapiURL.Scheme,
		crowdsecHost:      lapiURL.Host,
		crowdsecPath:      "/",
		crowdsecHeader:    crowdsecCapiHeader,
		crowdsecKey:       "expired-token",
		crowdsecMode:      configuration.AloneMode,
		crowdsecMachineID: "machine",
		crowdsecPassword:  "secret",
		crowdsecScenarios: []string{"test"},
		httpClient:        lapi.Client(),
		log:               logger.New("ERROR", ""),
		pluginVersion:     "test",
	}
	if _, err := client.crowdsecQuery(lapiURL.JoinPath(crowdsecLapiMetricsRoute).String(), payload); err != nil {
		t.Fatalf("alone 401 POST retry: %v", err)
	}
	if atomic.LoadInt32(&metricsAttempts) != 2 {
		t.Fatalf("expected 2 metrics attempts, got %d", metricsAttempts)
	}
	if string(firstBody) != string(payload) || string(secondBody) != string(payload) {
		t.Fatalf("POST body not replayed: first=%q second=%q", firstBody, secondBody)
	}
}

func TestCrowdsecQueryStreamMode401DoesNotRetry(t *testing.T) {
	var attempts int32
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer lapi.Close()
	lapiURL, _ := url.Parse(lapi.URL)
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecHeader: crowdsecLapiHeader,
		crowdsecKey:    "key",
		crowdsecMode:   configuration.StreamMode,
		httpClient:     lapi.Client(),
		log:            logger.New("ERROR", ""),
		pluginVersion:  "test",
	}
	if _, err := client.crowdsecQuery(lapi.URL+"/v1/decisions/stream?startup=true", nil); err == nil {
		t.Fatal("stream 401 must error")
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("stream GET 401 must stay single-attempt, got %d attempts", attempts)
	}
}

func TestLiveLookupScopeErrorPreservesActiveIPBan(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case strings.Contains(req.URL.RawQuery, "ip="):
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(`[{"duration":"1h","origin":"cscli","scope":"Ip","type":"ban","value":"1.2.3.4"}]`))
		case strings.Contains(req.URL.RawQuery, "scope="):
			rw.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected query %s", req.URL.RawQuery)
		}
	}))
	defer lapi.Close()
	lapiURL, _ := url.Parse(lapi.URL)
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecHeader: crowdsecLapiHeader,
		crowdsecKey:    "test-key",
		crowdsecMode:   configuration.LiveMode,
		httpClient:     lapi.Client(),
		cacheClient:    cacheClient,
		log:            logger.New("ERROR", ""),
	}
	value, err := client.LiveLookup("1.2.3.4", map[string]string{decisionscope.ScopeCountry: "FR"})
	if err == nil {
		t.Fatal("scope LAPI 500 must return error from LiveLookup when IP is banned")
	}
	if !decisionscope.IsActiveRemediation(value) {
		t.Fatalf("active IP ban must survive scope error, got %q err=%v", value, err)
	}
}

func TestLiveLookupScopeErrorPropagates(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case strings.Contains(req.URL.RawQuery, "ip="):
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("null"))
		case strings.Contains(req.URL.RawQuery, "scope="):
			rw.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected query %s", req.URL.RawQuery)
		}
	}))
	defer lapi.Close()
	lapiURL, _ := url.Parse(lapi.URL)
	cacheClient := &cache.Client{}
	cacheClient.New(logger.New("ERROR", ""), false, "", nil, "", "", "")
	client := &Client{
		crowdsecScheme: lapiURL.Scheme,
		crowdsecHost:   lapiURL.Host,
		crowdsecPath:   "/",
		crowdsecHeader: crowdsecLapiHeader,
		crowdsecKey:    "test-key",
		crowdsecMode:   configuration.LiveMode,
		httpClient:     lapi.Client(),
		cacheClient:    cacheClient,
		log:            logger.New("ERROR", ""),
	}
	value, err := client.LiveLookup("1.2.3.4", map[string]string{decisionscope.ScopeCountry: "FR"})
	if err == nil {
		t.Fatal("scope LAPI 500 must return error from LiveLookup")
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("scope error must not look like remediation, got %q", value)
	}
}

func TestHandleStreamTickerSerializesOverlappingPolls(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var inFlight int32
	var maxInFlight int32
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		current := atomic.AddInt32(&inFlight, 1)
		seen := atomic.LoadInt32(&maxInFlight)
		if current > seen {
			atomic.CompareAndSwapInt32(&maxInFlight, seen, current)
		}
		if current == 1 {
			select {
			case started <- struct{}{}:
			default:
			}
			<-release
		}
		atomic.AddInt32(&inFlight, -1)
		rw.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(rw).Encode(Stream{})
	}))
	defer lapi.Close()
	client := newTestStreamClient(t, lapi, -1)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		client.handleStreamTicker()
	}()
	<-started
	go func() {
		defer waitGroup.Done()
		client.handleStreamTicker()
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	waitGroup.Wait()
	if atomic.LoadInt32(&maxInFlight) > 1 {
		t.Fatalf("overlapping stream polls detected, max in flight=%d", maxInFlight)
	}
}
