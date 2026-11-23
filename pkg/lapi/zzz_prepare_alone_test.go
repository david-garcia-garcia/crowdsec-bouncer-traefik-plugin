package lapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestPrepare_AloneModeRewritesCAPIEndpoint(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.LapiMode = configuration.AloneMode
	cfg.LapiScheme = configuration.HTTP
	cfg.LapiCapiMachineID = "machine"
	cfg.LapiCapiPassword = "secret"
	cfg.LapiUpdateIntervalSeconds = 60
	if err := Prepare(cfg, nil, "router"); err != nil {
		t.Fatal(err)
	}
	if cfg.LapiHost != crowdsecCapiHost {
		t.Fatalf("LapiHost = %q, want %q", cfg.LapiHost, crowdsecCapiHost)
	}
	if cfg.LapiScheme != configuration.HTTPS || cfg.LapiPath != "/" {
		t.Fatalf("scheme=%q path=%q, want https /", cfg.LapiScheme, cfg.LapiPath)
	}
	if cfg.LapiUpdateIntervalSeconds != 7200 {
		t.Fatalf("update interval = %d, want 7200", cfg.LapiUpdateIntervalSeconds)
	}
	if cfg.LapiCapiMachineID != "machine" || cfg.LapiCapiPassword != "secret" {
		t.Fatalf("CAPI credentials were not kept: id=%q", cfg.LapiCapiMachineID)
	}
}

func TestNew_MissingLapiKey(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 0)
	cfg.LapiKey = ""
	store := decisionstore.NewMemory(logger.New("ERROR", ""))
	_, err := New(cfg, logger.New("ERROR", ""), "test", store, "router", "bind")
	if err == nil || !strings.Contains(err.Error(), "LapiKey") {
		t.Fatalf("New err = %v, want missing LapiKey", err)
	}
}

// testCapiOutage is a fake CAPI whose login fails until up is set. The stream route answers
// only the token the login hands out.
type testCapiOutage struct {
	up         int64
	loginHits  int64
	streamHits int64
	unauthHits int64
	host       string
}

// newTestCapiOutage starts a fake CAPI that is down until up is set.
func newTestCapiOutage(t *testing.T) *testCapiOutage {
	t.Helper()
	capi := &testCapiOutage{}
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case strings.Contains(req.URL.Path, crowdsecCapiLoginRoute):
			atomic.AddInt64(&capi.loginHits, 1)
			if atomic.LoadInt64(&capi.up) == 0 {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = rw.Write([]byte(`{"code":200,"token":"fresh","expire":"later"}`))
		case strings.Contains(req.URL.Path, crowdsecCapiStreamRoute):
			if req.Header.Get(crowdsecCapiHeader) != "fresh" {
				atomic.AddInt64(&capi.unauthHits, 1)
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}
			atomic.AddInt64(&capi.streamHits, 1)
			_, _ = rw.Write([]byte(`{"new":[],"deleted":[]}`))
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	capi.host = parsed.Host
	return capi
}

// waitStreamHealthy waits until client.StreamHealthy equals want or fails after five seconds.
func waitStreamHealthy(t *testing.T, client *Client, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for client.StreamHealthy() != want {
		if time.Now().After(deadline) {
			t.Fatalf("StreamHealthy=%t after 5s, want %t", client.StreamHealthy(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNew_AloneModeLoadsWhenCapiLoginFails proves a CAPI outage at startup does not fail New:
// the first poll marks the stream unhealthy, and once CAPI answers again a later poll logs in,
// pulls the stream, and the stream is healthy again.
func TestNew_AloneModeLoadsWhenCapiLoginFails(t *testing.T) {
	capi := newTestCapiOutage(t)
	cfg := testStreamConfig(capi.host, 0)
	cfg.LapiMode = configuration.AloneMode
	cfg.LapiKey = ""
	cfg.LapiCapiMachineID = "machine"
	cfg.LapiCapiPassword = "secret"
	// One second, so the failed-poll retry (one interval when shorter than failedPollRetry) is fast.
	cfg.LapiUpdateIntervalSeconds = 1
	store := decisionstore.NewMemory(logger.New("ERROR", ""))

	client, err := New(cfg, logger.New("ERROR", ""), "test", store, "router", "bind")
	if err != nil {
		t.Fatalf("New must not fail when the CAPI login fails at startup: %v", err)
	}
	t.Cleanup(client.Close)

	waitStreamHealthy(t, client, false)
	if got := atomic.LoadInt64(&capi.streamHits) + atomic.LoadInt64(&capi.unauthHits); got != 0 {
		t.Fatalf("stream requests=%d without a token, want 0: a poll must log in first", got)
	}

	atomic.StoreInt64(&capi.up, 1)
	waitStreamHealthy(t, client, true)
	if got := atomic.LoadInt64(&capi.streamHits); got < 1 {
		t.Fatalf("authorized stream requests=%d, want >= 1", got)
	}
	if got := atomic.LoadInt64(&capi.loginHits); got < 3 {
		t.Fatalf("login requests=%d, want >= 3 (startup, first poll, recovering poll)", got)
	}
}
