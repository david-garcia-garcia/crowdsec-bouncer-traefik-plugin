package modsecurity

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestInspect_cleanGETAllows(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com:443" {
			t.Errorf("Host=%q want example.com:443", r.Host)
		}
		if r.Header.Get("X-Real-IP") != "" {
			t.Error("plugin must not set X-Real-IP")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok-body"))
	}))
	defer sidecar.Close()
	client, err := New(testModsecConfig(sidecar.URL), slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com:443/", nil)
	req.Host = "example.com:443"
	if client.Inspect(rw, req, configuration.ModsecFailModeOpen, "X-Remediation") {
		t.Fatal("2xx must continue")
	}
	if rw.Body.Len() != 0 {
		t.Fatalf("allow must not copy sidecar body, got %q", rw.Body.String())
	}
}

func TestInspect_copiedBlockOmitsHopByHopAndSetsHeader(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Server", "crs")
		w.Header().Set("X-Block", "yes")
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer sidecar.Close()
	client, err := New(testModsecConfig(sidecar.URL), slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/?test=../etc", nil)
	if !client.Inspect(rw, req, configuration.ModsecFailModeOpen, "X-Remediation") {
		t.Fatal("403 must write")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
	if rw.Header().Get("Connection") == "close" {
		t.Fatal("Connection must not be copied")
	}
	if rw.Header().Get("Server") == "crs" {
		t.Fatal("Server must not be copied")
	}
	if rw.Header().Get("X-Block") != "yes" {
		t.Fatal("application header must be copied")
	}
	if rw.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatalf("header=%q want ban:modsec", rw.Header().Get("X-Remediation"))
	}
}

func TestInspect_sidecar3xxIsBlockNotFollowed(t *testing.T) {
	followed := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			followed++
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer sidecar.Close()
	client, err := New(testModsecConfig(sidecar.URL), slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if !client.Inspect(rw, req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("302 must write")
	}
	if rw.Code != http.StatusFound {
		t.Fatalf("status=%d want 302", rw.Code)
	}
	if followed != 0 {
		t.Fatal("plugin must not follow sidecar redirect")
	}
}

func TestInspect_sidecar5xxUsesFailMode(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "sidecar-5xx-marker", http.StatusServiceUnavailable)
	}))
	defer sidecar.Close()
	client, err := New(testModsecConfig(sidecar.URL), slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	openRW := httptest.NewRecorder()
	if client.Inspect(openRW, httptest.NewRequest(http.MethodGet, "http://example.com/", nil), configuration.ModsecFailModeOpen, "X-Remediation") {
		t.Fatal("open 5xx must continue")
	}
	if strings.Contains(openRW.Body.String(), "sidecar-5xx-marker") {
		t.Fatal("5xx body must not be forwarded")
	}
	if openRW.Header().Get("X-Remediation") != "" {
		t.Fatal("fail-open must omit remediation header")
	}

	closeRW := httptest.NewRecorder()
	if !client.Inspect(closeRW, httptest.NewRequest(http.MethodGet, "http://example.com/", nil), configuration.ModsecFailModeClose, "X-Remediation") {
		t.Fatal("close 5xx must write 502")
	}
	if closeRW.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502", closeRW.Code)
	}
	if closeRW.Header().Get("X-Remediation") != "" {
		t.Fatal("fail-close 502 must omit remediation header")
	}
}

func TestInspect_inboundCancelIsEmpty502(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}))
	defer sidecar.Close()
	defer close(release)
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecHTTPTimeoutSeconds = 30
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil).WithContext(ctx)
	done := make(chan struct{})
	rw := httptest.NewRecorder()
	go func() {
		defer close(done)
		_ = client.Inspect(rw, req, configuration.ModsecFailModeOpen, "")
	}()
	<-started
	cancel()
	<-done
	if rw.Code != http.StatusBadGateway {
		t.Fatalf("status=%d want 502", rw.Code)
	}
}

func TestInspect_gateSkipUsesFailMode(t *testing.T) {
	sidecarHits := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sidecarHits++
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer sidecar.Close()
	cfg := testModsecConfig(sidecar.URL)
	cfg.ModsecUnhealthyBackOffPeriodSecs = 30
	cfg.ModsecUnhealthyFailureThreshold = 1
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first := httptest.NewRecorder()
	if client.Inspect(first, httptest.NewRequest(http.MethodGet, "http://example.com/", nil), configuration.ModsecFailModeOpen, "") {
		t.Fatal("first 500 open must continue")
	}
	second := httptest.NewRecorder()
	if client.Inspect(second, httptest.NewRequest(http.MethodGet, "http://example.com/", nil), configuration.ModsecFailModeOpen, "") {
		t.Fatal("gate skip open must continue")
	}
	if sidecarHits != 1 {
		t.Fatalf("sidecar hits=%d want 1", sidecarHits)
	}
}

func TestInspect_doesNotAppendRemoteAddrToXFF(t *testing.T) {
	var gotXFF string
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer sidecar.Close()
	client, err := New(testModsecConfig(sidecar.URL), slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.RemoteAddr = "192.0.2.1:1234"
	if client.Inspect(httptest.NewRecorder(), req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("allow must continue")
	}
	if gotXFF != "203.0.113.9" {
		t.Fatalf("XFF=%q; plugin must not append RemoteAddr", gotXFF)
	}
}

func TestInspect_413OmitsRemediationHeader(t *testing.T) {
	cfg := testModsecConfig("http://127.0.0.1:1")
	cfg.ModsecBodyLimit = 1
	cfg.ModsecDenyVerbsWithBody = []string{}
	client, err := New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("ab"))
	if !client.Inspect(rw, req, configuration.ModsecFailModeClose, "X-Remediation") {
		t.Fatal("413 must write")
	}
	if rw.Header().Get("X-Remediation") != "" {
		t.Fatal("413 must omit remediation header")
	}
}

func TestInspect_restoresBodyForNext(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("payload"))
	if client.Inspect(httptest.NewRecorder(), req, configuration.ModsecFailModeOpen, "") {
		t.Fatal("allow must continue")
	}
	got, _ := io.ReadAll(req.Body)
	if string(got) != "payload" {
		t.Fatalf("restored body=%q want payload", got)
	}
}
