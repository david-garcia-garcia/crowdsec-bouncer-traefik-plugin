package appsec

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

type idleCloseSpy struct {
	closed int
}

func (s *idleCloseSpy) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, http.ErrNotSupported
}

func (s *idleCloseSpy) CloseIdleConnections() {
	s.closed++
}

func testAppsecConfig(host string) *configuration.Config {
	return &configuration.Config{
		AppsecEnabled:           true,
		AppsecScheme:            "http",
		AppsecHost:              host,
		AppsecPath:              "/",
		AppsecKey:               "test-key",
		HTTPTimeoutSeconds:              1,
		AppsecTLSInsecureVerify: true,
		AppsecBodyLimit:         10485760,
	}
}

func TestOpen_ReclaimsSameClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	cfg := testAppsecConfig("127.0.0.1:1")
	ctx := context.Background()
	first, err := Open(ctx, cfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, cfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("second Open must reclaim the same *Client")
	}
}

func TestOpen_TimeoutOnlyAdoptsTransport(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()
	firstCfg := testAppsecConfig("127.0.0.1:1")
	firstCfg.HTTPTimeoutSeconds = 10
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.HTTPTimeoutSeconds = 30

	first, err := Open(ctx, firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, secondCfg, log, "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("timeout-only New must reuse the Client")
	}
	current := second.currentTransport()
	if current == nil || current.httpTimeoutSeconds != 30 {
		t.Fatalf("adopted timeout: %+v", current)
	}
	if current.httpClient.Timeout != 30*time.Second {
		t.Fatalf("HTTP timeout %v", current.httpClient.Timeout)
	}
	if !strings.Contains(logBuf.String(), "appsec transport replaced") {
		t.Fatalf("INFO must name transport replace: %s", logBuf.String())
	}
}

func TestOpen_TLSOnlyAdoptsTransport(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	firstCfg := testAppsecConfig("127.0.0.1:1")
	firstCfg.AppsecTLSInsecureVerify = true
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.AppsecTLSInsecureVerify = false

	first, err := Open(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("TLS-only New must reuse the Client")
	}
	current := second.currentTransport()
	if current == nil || current.appsecTLSInsecureVerify {
		t.Fatalf("adopted TLS: %+v", current)
	}
}

func TestOpen_DifferentHostsIsolate(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	first, err := Open(ctx, testAppsecConfig("127.0.0.1:1"), slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, testAppsecConfig("127.0.0.1:2"), slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different AppSec hosts must isolate Clients")
	}
}

func TestOpen_BodyLimitSplitsClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	firstCfg := testAppsecConfig("127.0.0.1:1")
	firstCfg.AppsecBodyLimit = 100
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.AppsecBodyLimit = 200

	first, err := Open(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("body-limit change must open a new Client")
	}
}

func TestOpen_TimeoutOnlyClosesPreviousIdle(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	firstCfg := testAppsecConfig("127.0.0.1:1")
	firstCfg.HTTPTimeoutSeconds = 10
	first, err := Open(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	current := first.currentTransport()
	if current == nil {
		t.Fatal("missing transport")
	}
	spy := &idleCloseSpy{}
	first.transport.Store(&transport{
		httpClient:                    &http.Client{Transport: spy, Timeout: current.httpClient.Timeout},
		key:                           current.key,
		httpTimeoutSeconds:            current.httpTimeoutSeconds,
		appsecTLSInsecureVerify:       current.appsecTLSInsecureVerify,
		appsecTLSCertificateAuthority: current.appsecTLSCertificateAuthority,
		appsecTLSCertificateBouncer:   current.appsecTLSCertificateBouncer,
	})
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.HTTPTimeoutSeconds = 30
	second, err := Open(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("timeout-only New must reuse the Client")
	}
	if spy.closed != 1 {
		t.Fatalf("closeIdle on replaced client: %d", spy.closed)
	}
}
