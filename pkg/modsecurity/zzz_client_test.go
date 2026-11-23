package modsecurity

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
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
	if _, err := client.GateForTest().Inner().Report(backendbackoff.Permit{}, true); err == nil {
		t.Fatal("closed gate must reject Report")
	}
}

// TestOpen_connectionKnobsSplitClient mirrors TestKey_TimeoutKnobsChangeIdentity: a router that changes
// the sidecar URL, the timeout, or the body limit gets its own Client.
func TestOpen_connectionKnobsSplitClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	ctx := context.Background()
	base, err := Open(ctx, testModsecConfig("http://127.0.0.1:1"), slog.Default(), "same", "test")
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*configuration.Config){
		"url":             func(c *configuration.Config) { c.ModsecURL = "http://127.0.0.1:2" },
		"timeout":         func(c *configuration.Config) { c.ModsecHTTPTimeoutSeconds = 30 },
		"bodyLimit":       func(c *configuration.Config) { c.ModsecBodyLimit = 1024 },
		"bodyReadTimeout": func(c *configuration.Config) { c.ModsecBodyReadTimeoutSeconds = 5 },
	} {
		cfg := testModsecConfig("http://127.0.0.1:1")
		change(cfg)
		other, err := Open(ctx, cfg, slog.Default(), "same", "test")
		if err != nil {
			t.Fatal(err)
		}
		if other == base || other.Incarnation() == base.Incarnation() {
			t.Fatalf("%s change must open a new Client", name)
		}
		if OwnershipKey(cfg, "same") == OwnershipKey(testModsecConfig("http://127.0.0.1:1"), "same") {
			t.Fatalf("%s change must change the ownership key", name)
		}
	}
}
