package bouncer

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

func TestNew_BouncerInitializedTrustedIPs(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	log, sink := newTestLogSink(slog.LevelDebug)
	cfg := configuration.New()
	forwarded := []string{"10.0.0.0/8", "192.168.0.0/16", "192.0.2.1"}
	client := []string{"172.16.0.0/12", "203.0.113.0/24"}
	cfg.BouncerForwardedHeadersTrustedIPs = forwarded
	cfg.BouncerClientTrustedIPs = client
	if _, err := New(next, "test", cfg, false, false, false, log); err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logged := sink.String()
	rec := bouncerInitializedRecord(t, logged)
	assertStringSliceAttr(t, rec, "forwardedHeadersTrustedIPs", forwarded)
	assertStringSliceAttr(t, rec, "clientTrustedIPs", client)
}

func TestNew_BouncerInitializedEmptyTrustedIPs(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	log, sink := newTestLogSink(slog.LevelDebug)
	cfg := configuration.New()
	cfg.BouncerForwardedHeadersTrustedIPs = []string{}
	cfg.BouncerClientTrustedIPs = []string{}
	if _, err := New(next, "test", cfg, false, false, false, log); err != nil {
		t.Fatalf("New() error = %v", err)
	}
	logged := sink.String()
	rec := bouncerInitializedRecord(t, logged)
	assertStringSliceAttr(t, rec, "forwardedHeadersTrustedIPs", []string{})
	assertStringSliceAttr(t, rec, "clientTrustedIPs", []string{})
}

func TestNew_BouncerInitializedNilTrustedIPs(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	log, sink := newTestLogSink(slog.LevelDebug)
	cfg := configuration.New()
	cfg.BouncerForwardedHeadersTrustedIPs = nil
	cfg.BouncerClientTrustedIPs = nil
	if _, err := New(next, "test", cfg, false, false, false, log); err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rec := bouncerInitializedRecord(t, sink.String())
	assertStringSliceAttr(t, rec, "forwardedHeadersTrustedIPs", []string{})
	assertStringSliceAttr(t, rec, "clientTrustedIPs", []string{})
}

// bouncerInitializedRecord is the one DEBUG Bouncer initialized JSON object.
func bouncerInitializedRecord(t *testing.T, logged string) map[string]any {
	t.Helper()
	lines := jsonLinesWithMsg(logged, "Bouncer initialized")
	if len(lines) != 1 {
		t.Fatalf("want one Bouncer initialized record, got %d in %s", len(lines), logged)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("unmarshal Bouncer initialized: %v", err)
	}
	return rec
}

// assertStringSliceAttr checks a slog JSON string-slice attr equals want, including empty lists.
func assertStringSliceAttr(t *testing.T, rec map[string]any, key string, want []string) {
	t.Helper()
	raw, ok := rec[key]
	if !ok {
		t.Fatalf("missing %s on Bouncer initialized: %v", key, rec)
	}
	got, ok := jsonStringSlice(raw)
	if !ok {
		t.Fatalf("%s = %#v want []string %q", key, raw, want)
	}
	if len(got) != len(want) {
		t.Fatalf("%s = %q want %q", key, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %q want %q", key, got, want)
		}
	}
}

// jsonStringSlice is a JSON array of strings (empty list included).
func jsonStringSlice(raw any) ([]string, bool) {
	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}
