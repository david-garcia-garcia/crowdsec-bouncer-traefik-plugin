package decisionstore

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// TestStoreLifecycleLogs proves create/sleep/wake/close are INFO with storeKey, engine, and reason.
func TestStoreLifecycleLogs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store := NewMemory(log)
	store.bindLifecycle(log, "decisionstore:test")
	store.Sleep()
	store.Wake()
	store.Close()
	logged := buf.String()
	for _, msg := range []string{
		"crowdsec decision store started",
		"crowdsec decision store sleeping",
		"crowdsec decision store waking",
		"crowdsec decision store closed",
	} {
		if !strings.Contains(logged, msg) {
			t.Fatalf("missing %q in %s", msg, logged)
		}
	}
	for _, field := range []string{
		`"storeKey":"decisionstore:test"`,
		`"engine":"memory"`,
		`"reason":"started"`,
		`"reason":"sleeping"`,
		`"reason":"waking"`,
		`"reason":"closed"`,
	} {
		if !strings.Contains(logged, field) {
			t.Fatalf("missing %q in %s", field, logged)
		}
	}
}

// TestStoreLifecycleLogsStayOffDefaultDebug proves NewMemory without Open does not INFO-spam Close.
func TestNewMemoryCloseIsSilentWithoutLifecycle(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store := NewMemory(log)
	store.Close()
	if got := buf.String(); got != "" {
		t.Fatalf("NewMemory Close must not log without bindLifecycle, got %s", got)
	}
}

// TestOpenDecisionStoreLogsStartedAtInfo proves reclaim create emits started at INFO, not only reclaim_put.
func TestOpenLogsStartedAtInfo(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := &configuration.Config{
		CrowdsecMode:       configuration.StreamMode,
		CrowdsecLapiScheme: "http",
		CrowdsecLapiHost:   "lapi.example:8080",
		CrowdsecLapiPath:   "/",
		CrowdsecLapiKey:    "test-key",
	}
	store, err := Open(context.Background(), "decisionstore:open-started", "prefix", cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		t.Fatal("Open returned nil store")
	}
	logged := buf.String()
	if !strings.Contains(logged, "crowdsec decision store started") {
		t.Fatalf("missing started:\n%s", logged)
	}
	if !strings.Contains(logged, `"storeKey":"decisionstore:open-started"`) {
		t.Fatalf("missing storeKey:\n%s", logged)
	}
	if strings.Contains(logged, "reclaim_put") {
		t.Fatalf("reclaim_put must stay DEBUG:\n%s", logged)
	}
}
