package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// TestServeHTTP_AppsecClientBodyReadIsNotABan covers upstream issue #395 / PR #401 end to end, also
// under Yaegi: a client body that fails while AppSec buffers it is never an AppSec ban. With the
// client still connected it is a 400; once net/http canceled the request context (HTTP/2 stream
// reset, HTTP/1.1 TCP reset) it is a silent disconnect, whatever the read error says.
func TestServeHTTP_AppsecClientBodyReadIsNotABan(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var lapiHits int64
	lapiSrv := liveLAPI(t, map[string]bool{}, &lapiHits)
	t.Cleanup(func() { lapiSrv.Close() })
	lapiURL, err := url.Parse(lapiSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var appsecHits int64
	appsecSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&appsecHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() { appsecSrv.Close() })
	appsecURL, err := url.Parse(appsecSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	cfg := cfgLiveAt(lapiURL.Host)
	cfg.LogLevel = "ERROR"
	cfg.AppsecEnabled = true
	cfg.AppsecScheme = "http"
	cfg.AppsecHost = appsecURL.Host
	cfg.AppsecPath = "/"
	cfg.AppsecKey = "test-key"
	cfg.BouncerRemediationHeadersCustomName = "X-Remediation"
	var originHits int64
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		atomic.AddInt64(&originHits, 1)
	})
	handler, err := New(context.Background(), next, cfg, "appsec-body-read")
	if err != nil {
		t.Fatal(err)
	}

	upload := func(ctx context.Context, readErr error) *httptest.ResponseRecorder {
		req := reqForIP("203.0.113.50").WithContext(ctx)
		req.Method = http.MethodPost
		req.Body = io.NopCloser(iotest.ErrReader(readErr))
		req.ContentLength = 100
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, req)
		return rw
	}

	slow := upload(context.Background(), errors.New("i/o timeout"))
	if slow.Code != http.StatusBadRequest {
		t.Fatalf("live client body read status=%d body=%q, want 400", slow.Code, slow.Body.String())
	}
	if got := slow.Header().Get("X-Remediation"); got != "error:client-body-read" {
		t.Fatalf("live client body read X-Remediation=%q, want error:client-body-read", got)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	reset := upload(canceled, errors.New("stream error: stream ID 1; CANCEL"))
	if got := reset.Header().Get("X-Remediation"); got != "error:client-disconnected" {
		t.Fatalf("stream reset X-Remediation=%q, want error:client-disconnected", got)
	}
	if reset.Code == http.StatusForbidden {
		t.Fatalf("stream reset served a ban (status %d)", reset.Code)
	}

	if got := atomic.LoadInt64(&appsecHits); got != 0 {
		t.Fatalf("AppSec called %d times, want 0", got)
	}
	if got := atomic.LoadInt64(&originHits); got != 0 {
		t.Fatalf("origin called %d times, want 0", got)
	}
}
