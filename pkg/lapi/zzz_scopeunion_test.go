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

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func TestOpenStream_LiveRoutersUnionCountryAndUsername(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	countryCfg := testStreamConfig(parsed.Host, 1)
	countryCfg.DecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	userCfg := testStreamConfig(parsed.Host, 1)
	userCfg.DecisionScopeHeaders = map[string]string{"username": "X-User"}
	countryCtx, countryCancel := context.WithCancel(context.Background())
	t.Cleanup(countryCancel)
	userCtx, userCancel := context.WithCancel(context.Background())
	t.Cleanup(userCancel)

	countryClient, err := OpenStream(countryCtx, countryCfg, log, "country", "test")
	if err != nil {
		t.Fatal(err)
	}
	userClient, err := OpenStream(userCtx, userCfg, log, "user", "test")
	if err != nil {
		t.Fatal(err)
	}
	if countryClient != userClient {
		t.Fatal("header-map mismatch must share one Client")
	}
	query := countryClient.streamQuery()
	if !strings.Contains(query, "country") || !strings.Contains(query, "username") {
		t.Fatalf("union scopes: %s", query)
	}
	countryClient.decisionStore.BeginTick()
	countryClient.storeStreamDecision(Decision{Type: "ban", Scope: "Country", Value: "FR", Origin: "CAPI"}, 60)
	countryClient.storeStreamDecision(Decision{Type: "ban", Scope: "username", Value: "alice", Origin: "CAPI"}, 60)
	countryClient.decisionStore.PublishTick(0)
	if !testStreamHasDecision(countryClient, decisionscope.HeaderScopeKey(decisionscope.ScopeCountry, "FR")) {
		t.Fatal("Country decision must store")
	}
	if !testStreamHasDecision(countryClient, decisionscope.HeaderScopeKey("username", "alice")) {
		t.Fatal("username decision must store")
	}

	userCancel()
	waitScopeUnregistered(t, countryClient, "username")
	afterDrop := countryClient.streamQuery()
	if !strings.Contains(afterDrop, "country") {
		t.Fatalf("Country must remain: %s", afterDrop)
	}
	if strings.Contains(afterDrop, "username") {
		t.Fatalf("username must drop: %s", afterDrop)
	}
	if !testStreamHasDecision(countryClient, decisionscope.HeaderScopeKey(decisionscope.ScopeCountry, "FR")) {
		t.Fatal("unregister must not sweep Country key")
	}
}

func testStreamHasDecision(client *Client, key string) bool {
	if client.decisionStore == nil {
		return false
	}
	snap := client.decisionStore.PublishedMemoryMapForTest()
	if snap == nil {
		return false
	}
	_, ok := snap[key]
	return ok
}

func TestOpenStream_LateCountryJoinUsesStartupFalse(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.Default()
	firstCfg := testStreamConfig(parsed.Host, 1)
	first, err := OpenStream(context.Background(), firstCfg, log, "first", "test")
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&first.isCrowdsecStreamStartup) != 0 {
		t.Fatal("first poll must clear startup")
	}
	lateCfg := testStreamConfig(parsed.Host, 1)
	lateCfg.DecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	late, err := OpenStream(context.Background(), lateCfg, log, "late", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first != late {
		t.Fatal("late Country join must share the Client")
	}
	query := late.streamQuery()
	if !strings.Contains(query, "startup=false") {
		t.Fatalf("late join must not send startup=true: %s", query)
	}
	if !strings.Contains(query, "country") {
		t.Fatalf("late join must add country: %s", query)
	}
}

func TestOpenStream_FirstCountryPollIncludesCountryBeforeRegister(t *testing.T) {
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
	countryCfg := testStreamConfig(parsed.Host, 1)
	countryCfg.DecisionScopeHeaders = map[string]string{"Country": "CF-IPCountry"}
	if _, err := OpenStream(context.Background(), countryCfg, slog.Default(), "country", "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(firstQuery, "country") {
		t.Fatalf("create-time first poll must include country from write-once headers: %s", firstQuery)
	}
}

func TestOpenStream_EmptyUnionOmitsCountry(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	server, _ := testStreamLAPI(t)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := OpenStream(context.Background(), testStreamConfig(parsed.Host, 1), slog.Default(), "empty", "test")
	if err != nil {
		t.Fatal(err)
	}
	query := client.streamQuery()
	if strings.Contains(query, "country") {
		t.Fatalf("empty union must omit country: %s", query)
	}
}

func waitScopeUnregistered(t *testing.T, client *Client, scope string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := client.snapshotLiveHeaderScopes()[scope]; !ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("scope %s still registered", scope)
}
