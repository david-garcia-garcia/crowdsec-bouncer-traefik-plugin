package appsec

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func TestOpen_AppsecOverrideAdoptsTimeout(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ctx := context.Background()
	firstCfg := testAppsecConfig("127.0.0.1:1")
	firstCfg.HTTPTimeoutSeconds = 10
	secondCfg := testAppsecConfig("127.0.0.1:1")
	secondCfg.HTTPTimeoutSeconds = 10
	secondCfg.CrowdsecAppsecHTTPTimeoutSeconds = 30

	first, err := Open(ctx, firstCfg, slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, secondCfg, slog.Default(), "second", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("AppSec override-only New must open a new Client")
	}
}

func TestQuery_HangHonorsAppsecOverride(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	// Never Accept: Query must use the AppSec override, not the 10s shared default.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	cfg := testAppsecConfig(listener.Addr().String())
	cfg.HTTPTimeoutSeconds = 10
	cfg.CrowdsecAppsecHTTPTimeoutSeconds = 1
	cfg.CrowdsecAppsecFailureAction = configuration.FailureActionPassthrough
	client, err := Open(context.Background(), cfg, slog.Default(), "hang", "test")
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	decision, queryErr := client.Query("1.2.3.4", httptest.NewRequest(http.MethodGet, "http://localhost/", nil), Policy{
		FailureAction: configuration.FailureActionPassthrough,
	})
	elapsed := time.Since(started)
	if queryErr != nil {
		t.Fatalf("passthrough Query err = %v", queryErr)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough hang: %+v", decision)
	}
	if elapsed >= 4*time.Second {
		t.Fatalf("Query took %v, want well under the 10s shared default", elapsed)
	}
}
