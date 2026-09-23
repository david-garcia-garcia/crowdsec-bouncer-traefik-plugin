package lapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// openStreamForTest opens a stream Client and cancels its bind ctx on cleanup.
func openStreamForTest(t *testing.T, cfg *configuration.Config, name string) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client, err := OpenStream(ctx, cfg, slog.Default(), name, "test")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestOpenStream_OpenerScopesOnly(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testStreamConfig(parsed.Host, 1)
	cfg.LapiStreamScopes = []string{"country", "username"}
	cfg.BouncerDecisionScopeHeaders = map[string]string{"as": "X-ASN"}
	client := openStreamForTest(t, cfg, "opener")
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
	cfg.BouncerDecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	client := openStreamForTest(t, cfg, "empty")
	query := client.streamQuery()
	if strings.Contains(query, "country") {
		t.Fatalf("empty opener list must omit country: %s", query)
	}
}

func TestOpenStream_FirstPollUsesOpenerScopes(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var firstQuery atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "stream") {
			firstQuery.CompareAndSwap(nil, req.URL.RawQuery)
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
	cfg.LapiStreamScopes = []string{"Country"}
	_ = openStreamForTest(t, cfg, "country")
	deadline := time.Now().Add(2 * time.Second)
	query, _ := firstQuery.Load().(string)
	for time.Now().Before(deadline) && query == "" {
		time.Sleep(10 * time.Millisecond)
		query, _ = firstQuery.Load().(string)
	}
	if !strings.Contains(query, "country") {
		t.Fatalf("create-time first poll must include opener country: %s", query)
	}
}
