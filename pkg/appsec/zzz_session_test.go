package appsec

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func testAppsecConfig(host string) *configuration.Config {
	return &configuration.Config{
		AppsecEnabled:           true,
		AppsecScheme:            "http",
		AppsecHost:              host,
		AppsecPath:              "/",
		AppsecKey:               "test-key",
		AppsecHTTPTimeoutSeconds:        1,
		AppsecTLSInsecureVerify: true,
		AppsecBodyLimit:         10485760,
	}
}

func TestOpen_P1MiddlewareNameSplitsClient(t *testing.T) {
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
	if first == second {
		t.Fatal("P1: distinct middleware names must be two Clients")
	}
}

func TestOpen_P2KnobChangeSplitsClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	ctx := context.Background()
	base := testAppsecConfig("127.0.0.1:1")
	first, err := Open(ctx, base, slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mut  func(*configuration.Config)
	}{
		{name: "scheme", mut: func(c *configuration.Config) { c.AppsecScheme = "https" }},
		{name: "host", mut: func(c *configuration.Config) { c.AppsecHost = "127.0.0.1:2" }},
		{name: "path", mut: func(c *configuration.Config) { c.AppsecPath = "/waf" }},
		{name: "key", mut: func(c *configuration.Config) { c.AppsecKey = "other" }},
		{name: "bodyLimit", mut: func(c *configuration.Config) { c.AppsecBodyLimit = 200 }},
		{name: "tls", mut: func(c *configuration.Config) { c.AppsecTLSInsecureVerify = false }},
		{name: "timeout", mut: func(c *configuration.Config) { c.AppsecHTTPTimeoutSeconds = 30 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testAppsecConfig("127.0.0.1:1")
			tc.mut(cfg)
			second, err := Open(ctx, cfg, slog.Default(), "same", "test")
			if err != nil {
				t.Fatal(err)
			}
			if first == second {
				t.Fatalf("P2: %s change must open a new Client", tc.name)
			}
		})
	}
}

func TestOpen_P3SameMiddlewareAndKnobsWake(t *testing.T) {
	reclaim.ResetForTestWith(500 * time.Millisecond)
	t.Cleanup(func() { reclaim.ResetForTest() })

	cfg := testAppsecConfig("127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	first, err := Open(ctx, cfg, slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		first.mu.Lock()
		sleeping := first.sleeping
		first.mu.Unlock()
		if sleeping {
			break
		}
		time.Sleep(time.Millisecond)
	}
	second, err := Open(context.Background(), testAppsecConfig("127.0.0.1:1"), slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("P3: same middleware and knobs must Wake the same Client")
	}
}

func TestOpen_P4OmittedSchemeFollowsLAPI(t *testing.T) {
	httpCfg := testAppsecConfig("127.0.0.1:1")
	httpCfg.AppsecScheme = ""
	httpCfg.LapiScheme = "http"
	_ = Prepare(httpCfg, slog.Default(), "")
	httpsFromLAPI := testAppsecConfig("127.0.0.1:1")
	httpsFromLAPI.AppsecScheme = ""
	httpsFromLAPI.LapiScheme = "https"
	_ = Prepare(httpsFromLAPI, slog.Default(), "")
	httpsExplicit := testAppsecConfig("127.0.0.1:1")
	httpsExplicit.AppsecScheme = "https"
	httpsExplicit.LapiScheme = "http"
	_ = Prepare(httpsExplicit, slog.Default(), "")
	if Key(httpCfg, "mw") == Key(httpsFromLAPI, "mw") {
		t.Fatal("P4: omitted scheme following LAPI https must change the AppSec key")
	}
	if Key(httpsFromLAPI, "mw") != Key(httpsExplicit, "mw") {
		t.Fatal("P4: inherited https and explicit https must share the AppSec key")
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
	second, err := Open(ctx, testAppsecConfig("127.0.0.1:2"), slog.Default(), "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different AppSec hosts must isolate Clients")
	}
}

func TestKey_TimeoutKnobsChangeIdentity(t *testing.T) {
	base := testAppsecConfig("127.0.0.1:1")
	timeouts := testAppsecConfig("127.0.0.1:1")
	timeouts.AppsecHTTPTimeoutSeconds = 30
	if Key(base, "mw") == Key(timeouts, "mw") {
		t.Fatal("HTTP timeout knobs must change AppSec Key")
	}
}
