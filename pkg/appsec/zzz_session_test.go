package appsec

import (
	"context"
	"log/slog"
	"testing"

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
