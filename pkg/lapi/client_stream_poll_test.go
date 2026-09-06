package lapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandleStreamTicker_SkipDoesNotClearFailure(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "stream") {
			atomic.AddInt64(&hits, 1)
			close(started)
			<-release
			_ = json.NewEncoder(w).Encode(map[string][]Decision{
				"new":     {},
				"deleted": {},
			})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 0)
	cfg.StreamStartupBlock = false
	cfg.MetricsUpdateIntervalSeconds = 0
	client, err := New(cfg, slog.Default(), "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first stream poll did not start")
	}
	client.updateFailure = 5
	client.isCrowdsecStreamHealthy = false
	for range 8 {
		client.handleStreamTicker()
	}
	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Fatalf("in-flight GETs: %d, want 1", got)
	}
	if client.updateFailure != 5 {
		t.Fatalf("skip cleared updateFailure: %d", client.updateFailure)
	}
	if client.isCrowdsecStreamHealthy {
		t.Fatal("skip marked stream healthy")
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if client.updateFailure == 0 && client.isCrowdsecStreamHealthy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("first poll did not finish healthy, failure=%d healthy=%t", client.updateFailure, client.isCrowdsecStreamHealthy)
}

func TestCrowdsecQuery_TimeoutBoundsHungLAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{
		httpClient:     &http.Client{Timeout: time.Second},
		log:            slog.Default(),
		crowdsecHeader: crowdsecLapiHeader,
		crowdsecKey:    "k",
		pluginVersion:  "test",
	}
	start := time.Now()
	_, err = client.crowdsecQuery(parsed.Scheme+"://"+parsed.Host+"/v1/decisions/stream", nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("hung LAPI must error")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout did not bound crowdsecQuery: %v", elapsed)
	}
}
