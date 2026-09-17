package appsec

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func testAppsecConfig(host string) *configuration.Config {
	return &configuration.Config{
		CrowdsecAppsecEnabled:           true,
		CrowdsecAppsecScheme:            "http",
		CrowdsecAppsecHost:              host,
		CrowdsecAppsecPath:              "/",
		CrowdsecAppsecKey:               "test-key",
		HTTPTimeoutSeconds:              1,
		CrowdsecAppsecTLSInsecureVerify: true,
		CrowdsecAppsecBodyLimit:         10485760,
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
	firstCfg.CrowdsecAppsecTLSInsecureVerify = true
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.CrowdsecAppsecTLSInsecureVerify = false

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
	firstCfg.CrowdsecAppsecBodyLimit = 100
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.CrowdsecAppsecBodyLimit = 200

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
