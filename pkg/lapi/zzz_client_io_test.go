package lapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestClient_SleepCancelsInFlightQuery(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := &Client{crowdsecMode: configuration.LiveMode, log: nil}
	client.mintIOLocked()
	attachTestTransport(client, server.Client(), "test-key")

	errCh := make(chan error, 1)
	go func() {
		_, err := client.sendQuery(server.URL, nil, false)
		errCh <- err
	}()
	<-started
	client.Sleep()
	err := <-errCh
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep must cancel in-flight GET: %v", err)
	}
	close(release)
}

func TestClient_WakeMintsNewIOContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
	}))
	t.Cleanup(server.Close)

	client := &Client{crowdsecMode: configuration.LiveMode}
	client.mintIOLocked()
	attachTestTransport(client, server.Client(), "test-key")
	client.Sleep()
	if _, err := client.sendQuery(server.URL, nil, false); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Sleep ctx must stay cancelled: %v", err)
	}
	client.Wake()
	if _, err := client.sendQuery(server.URL, nil, false); err != nil {
		t.Fatalf("Wake must mint a new IO context: %v", err)
	}
}

func TestClient_MetricsDrainUsesBackground(t *testing.T) {
	var posts int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "usage-metrics") {
			atomic.AddInt64(&posts, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string][]Decision{"new": {}, "deleted": {}})
	}))
	t.Cleanup(server.Close)

	client := &Client{
		crowdsecMode:    configuration.LiveMode,
		crowdsecScheme:  "http",
		crowdsecHost:    strings.TrimPrefix(server.URL, "http://"),
		crowdsecPath:    "/",
		metricsInterval: 60,
		pluginVersion:   "test",
		log:             slog.Default(),
	}
	client.mintIOLocked()
	attachTestTransport(client, server.Client(), "test-key")
	client.metricsReporter = newMetricsReporter(client, time.Now())
	client.IncProcessed("ipv4")
	client.Sleep()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&posts) >= 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Sleep drain must POST usage-metrics on Background")
}

func TestClient_CloseCancelsIOThenDrainsMetrics(t *testing.T) {
	var posts int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "usage-metrics") {
			atomic.AddInt64(&posts, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		crowdsecMode:    configuration.LiveMode,
		crowdsecScheme:  "http",
		crowdsecHost:    strings.TrimPrefix(server.URL, "http://"),
		crowdsecPath:    "/",
		metricsInterval: 60,
		pluginVersion:   "test",
		log:             slog.Default(),
	}
	client.mintIOLocked()
	attachTestTransport(client, server.Client(), "test-key")
	client.metricsReporter = newMetricsReporter(client, time.Now())
	client.IncProcessed("ipv4")
	client.Close()
	if atomic.LoadInt64(&posts) < 1 {
		t.Fatal("Close must POST remaining usage-metrics on Background")
	}
	if _, err := client.sendQuery(server.URL, nil, false); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Close must cancel the IO context: %v", err)
	}
}
