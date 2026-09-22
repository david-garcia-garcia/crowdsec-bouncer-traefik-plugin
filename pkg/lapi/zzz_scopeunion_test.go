package lapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func TestOpenStream_OpenerScopesOnly(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 1)
	cfg.CrowdsecLapiStreamScopes = []string{"country", "username"}
	cfg.DecisionScopeHeaders = map[string]string{"as": "X-ASN"}
	client, err := OpenStream(context.Background(), cfg, slog.Default(), "opener", "test")
	if err != nil {
		t.Fatal(err)
	}
	query := client.streamQuery()
	if !strings.Contains(query, "country") || !strings.Contains(query, "username") {
		t.Fatalf("opener scopes missing: %s", query)
	}
	if strings.Contains(query, "as") {
		t.Fatalf("decisionScopeHeaders must not union into stream poll: %s", query)
	}
}

func TestOpenStream_EmptyOpenerScopesOmitsCountry(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 1)
	cfg.DecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	client, err := OpenStream(context.Background(), cfg, slog.Default(), "empty", "test")
	if err != nil {
		t.Fatal(err)
	}
	query := client.streamQuery()
	if strings.Contains(query, "country") {
		t.Fatalf("empty opener list must omit country: %s", query)
	}
}

func TestOpenStream_FirstPollUsesOpenerScopes(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var firstQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "stream") && firstQuery == "" {
			firstQuery = req.URL.RawQuery
		}
		_ = json.NewEncoder(w).Encode(map[string][]Decision{
			"new":     {},
			"deleted": {},
		})
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 1)
	cfg.CrowdsecLapiStreamScopes = []string{"Country"}
	if _, err := OpenStream(context.Background(), cfg, slog.Default(), "country", "test"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && firstQuery == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(firstQuery, "country") {
		t.Fatalf("create-time first poll must include opener country: %s", firstQuery)
	}
}
