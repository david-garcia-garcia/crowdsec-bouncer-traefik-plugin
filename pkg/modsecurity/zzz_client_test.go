package modsecurity

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func testModsecConfig(url string) *configuration.Config {
	cfg := configuration.New()
	cfg.ModsecEnabled = true
	cfg.ModsecURL = url
	return cfg
}

func TestPrepare_fillsNameOnlyWhenOwned(t *testing.T) {
	owned := testModsecConfig("http://waf:80")
	owned.ModsecInstanceName = ""
	if err := Prepare(owned, slog.Default(), "cs-owner"); err != nil {
		t.Fatal(err)
	}
	if owned.ModsecInstanceName != "cs-owner" {
		t.Fatalf("owned name=%q want cs-owner", owned.ModsecInstanceName)
	}
	subscriber := testModsecConfig("http://waf:80")
	subscriber.ModsecEnabled = false
	subscriber.ModsecInstanceName = ""
	if err := Prepare(subscriber, slog.Default(), "cs-owner"); err != nil {
		t.Fatal(err)
	}
	if subscriber.ModsecInstanceName != "" {
		t.Fatalf("subscriber name=%q want empty", subscriber.ModsecInstanceName)
	}
}

func TestOpen_middlewareNameSplitsClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	cfg := testModsecConfig("http://127.0.0.1:1")
	ctx := context.Background()
	first, err := Open(ctx, cfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, cfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("distinct middleware names must be two Clients")
	}
}

func TestOpen_backoffKnobSplitsClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	ctx := context.Background()
	base := testModsecConfig("http://127.0.0.1:1")
	first, err := Open(ctx, base, slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	changed := testModsecConfig("http://127.0.0.1:1")
	changed.ModsecUnhealthyBackOffPeriodSecs = 30
	second, err := Open(ctx, changed, slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("backoff knob change must open a new Client")
	}
}

func TestOpen_sameKnobsWake(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })
	cfg := testModsecConfig("http://127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	first, err := Open(ctx, cfg, slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		second, err := Open(context.Background(), cfg, slog.Default(), "same", "test")
		if err != nil {
			t.Fatal(err)
		}
		if second == first {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("same name and knobs must Wake the same Client before grace ends")
}

func TestNew_omittedBackoffHasNoGate(t *testing.T) {
	cfg := testModsecConfig("http://127.0.0.1:1")
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.GateForTest() != nil {
		t.Fatal("omitted backoff must not build a gate")
	}
}

func TestNew_positiveBackoffBuildsGateAndCloseClosesIt(t *testing.T) {
	cfg := testModsecConfig("http://127.0.0.1:1")
	cfg.ModsecUnhealthyBackOffPeriodSecs = 30
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	if client.GateForTest() == nil {
		t.Fatal("positive backoff must build a gate")
	}
	client.Close()
	if err := client.GateForTest().Report(gateKey, true); err == nil {
		t.Fatal("closed gate must reject Report")
	}
}

func TestInspect_defaultDenyGetWithBody(t *testing.T) {
	cfg := testModsecConfig("http://127.0.0.1:1")
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("x"))
	if !client.Inspect(rw, req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("GET with body must write 400")
	}
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rw.Code)
	}
}

func TestInspect_explicitEmptyDenyListInspectsGetWithBody(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sidecarHits++
		body, _ := io.ReadAll(r.Body)
		if string(body) != "x" {
			t.Errorf("sidecar body=%q want x", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecDenyVerbsWithBody = []string{}
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("x"))
	if client.Inspect(rw, req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("empty deny list must continue after inspect")
	}
	if sidecarHits != 1 {
		t.Fatalf("sidecar hits=%d want 1", sidecarHits)
	}
}

func TestInspect_zeroBodyLimitIsUnlimited(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sidecarHits++
		body, _ := io.ReadAll(r.Body)
		if len(body) != 64 {
			t.Errorf("sidecar body len=%d want 64", len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecBodyLimit = 0
	cfg.ModsecDenyVerbsWithBody = []string{}
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(strings.Repeat("a", 64)))
	if client.Inspect(rw, req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("unlimited body must continue")
	}
	if sidecarHits != 1 {
		t.Fatalf("sidecar hits=%d want 1", sidecarHits)
	}
}

func TestInspect_bodyOverLimitIs413(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		sidecarHits++
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecBodyLimit = 4
	cfg.ModsecDenyVerbsWithBody = []string{}
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("12345"))
	if !client.Inspect(rw, req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("over-limit body must write")
	}
	if rw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", rw.Code)
	}
	if sidecarHits != 0 {
		t.Fatalf("sidecar hits=%d want 0", sidecarHits)
	}
}
