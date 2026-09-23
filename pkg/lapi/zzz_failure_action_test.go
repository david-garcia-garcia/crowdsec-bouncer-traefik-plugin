package lapi

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// newTestLiveClient builds a live-mode Client that queries the mock LAPI behind server.
func newTestLiveClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := NewTestClient(logger.New("ERROR", ""))
	client.crowdsecScheme = serverURL.Scheme
	client.crowdsecHost = serverURL.Host
	client.crowdsecPath = "/"
	client.crowdsecMode = configuration.LiveMode
	attachTestTransport(client, server.Client(), "")
	return client
}

// testLiveScopeLAPI answers ip= with ipBody and each scope= with scopeBodies[scope].
// A body of "" answers HTTP 500 so that query fails. A missing scope key answers "null".
func testLiveScopeLAPI(t *testing.T, ipBody string, scopeBodies map[string]string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		query := req.URL.Query()
		body, isScopeQuery := ipBody, false
		if scope := query.Get("scope"); scope != "" {
			isScopeQuery = true
			body = "null"
			if scopeBody, ok := scopeBodies[scope]; ok {
				body = scopeBody
			}
		}
		if body == "" {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !isScopeQuery && query.Get("ip") == "" {
			t.Errorf("live query had neither ip= nor scope=: %s", req.URL.RawQuery)
		}
		if _, err := rw.Write([]byte(body)); err != nil {
			t.Errorf("live LAPI stub write: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// testLiveBanBody is a one-decision LAPI answer for scope with an active ban on value.
func testLiveBanBody(scope, value string) string {
	return `[{"id":1,"origin":"CAPI","type":"ban","scope":"` + scope + `","value":"` + value + `","duration":"1h","scenario":"test"}]`
}

func Test_liveLookup_lapiErrorIsNotABan(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer lapi.Close()
	client := newTestLiveClient(t, lapi)
	value, _, err := client.LiveLookup("1.2.3.4", nil, 0)
	if err == nil {
		t.Fatal("live LAPI 500 expected an error")
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("live LAPI error must not look like a ban, got %q", value)
	}
}

func TestLiveLookup_PerRouterTTLLastWrites(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("[]"))
	}))
	defer lapi.Close()
	client := newTestLiveClient(t, lapi)
	if _, _, err := client.LiveLookup("1.2.3.4", nil, 60); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.LiveLookup("1.2.3.4", nil, 1); err != nil {
		t.Fatal(err)
	}
	kind, _, _, err := client.LookupRemediation("1.2.3.4", net.ParseIP("1.2.3.4"), nil)
	if err != nil || kind == "" {
		t.Fatal("last write must still be cached immediately")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		kind, _, originID, err := client.LookupRemediation("1.2.3.4", net.ParseIP("1.2.3.4"), nil)
		_ = originID
		if err != nil {
			t.Fatalf("lookup while waiting for live TTL: %v", err)
		}
		if kind == "" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("last-written 1s live TTL did not expire")
}

// TestLiveLookup_CleanIPAndCleanScopesAllows is matrix row 1: nothing decided, nothing failed.
func TestLiveLookup_CleanIPAndCleanScopesAllows(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, "null", map[string]string{
		"country":  "null",
		"username": "null",
	}))
	value, _, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR", "username": "alice"}, 60)
	if err != nil {
		t.Fatalf("clean IP and clean scopes must not error: %v", err)
	}
	if value != decisionscope.NoBannedValue {
		t.Fatalf("clean lookup value %q, want %q", value, decisionscope.NoBannedValue)
	}
}

// TestLiveLookup_ScopeErrorFailsClosed is matrix row 2: the failure must reach the caller with a
// non-active kind so pkg/bouncer applies BouncerLapiFailureAction instead of allowing.
func TestLiveLookup_ScopeErrorFailsClosed(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, "null", map[string]string{"country": ""}))
	value, _, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
	if err == nil {
		t.Fatalf("a failed scope query must not be reported as no decision, got value %q", value)
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("scope failure must come back non-active so the failure action applies, got %q", value)
	}
	kind, _, originID, lookupErr := client.LookupRemediation("1.2.3.4", net.ParseIP("1.2.3.4"), nil)
	_ = originID
	if lookupErr != nil {
		t.Fatalf("scope-failure store lookup: %v", lookupErr)
	}
	if kind == decisionscope.NoBannedValue {
		t.Fatal("scope failure must not cache the unverified allow for the client address")
	}
}

// TestLiveLookup_ScopeBanWins is matrix row 3: a clean IP plus a banned scope is a ban.
func TestLiveLookup_ScopeBanWins(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, "null", map[string]string{
		"country": testLiveBanBody("country", "FR"),
	}))
	kind, origin, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
	if err == nil {
		t.Fatal("a ban is reported with the overloaded banned error")
	}
	if kind != decisionscope.BannedValue || origin != "CAPI" {
		t.Fatalf("scope ban kind %q origin %q, want ban CAPI", kind, origin)
	}
}

// TestLiveLookup_IPSlotKeepsIPQueryResult is the header-only-ban write: the IP key stays the
// clean ?ip= result so a later Country DE lookup does not inherit the FR ban.
func TestLiveLookup_IPSlotKeepsIPQueryResult(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, "null", map[string]string{
		"country": testLiveBanBody("country", "FR"),
	}))
	value, _, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
	if err == nil {
		t.Fatal("a ban is reported with the overloaded banned error")
	}
	if !decisionscope.IsActiveRemediation(value) {
		t.Fatalf("merged lookup value %q, want an active remediation", value)
	}
	ipKind, _, _, ipErr := client.LookupRemediation("1.2.3.4", net.ParseIP("1.2.3.4"), nil)
	if ipErr != nil {
		t.Fatalf("clean IP query must write the none payload on the IP key: %v", ipErr)
	}
	if ipKind != decisionscope.NoBannedValue {
		t.Fatalf("IP key %q, want %q", ipKind, decisionscope.NoBannedValue)
	}
	headerKind, _, _, headerErr := client.LookupRemediation("203.0.113.99", net.ParseIP("203.0.113.99"), map[string]string{decisionscope.ScopeCountry: "FR"})
	if headerErr != nil {
		t.Fatalf("Country FR must stay on HeaderScopeKey: %v", headerErr)
	}
	if !decisionscope.IsActiveRemediation(headerKind) {
		t.Fatalf("Country header key %q, want an active remediation", headerKind)
	}
	kind, _, _, lookupErr := client.LookupRemediation("1.2.3.4", net.ParseIP("1.2.3.4"), map[string]string{decisionscope.ScopeCountry: "DE"})
	if lookupErr != nil {
		t.Fatalf("later Country DE lookup: %v", lookupErr)
	}
	if decisionscope.IsActiveRemediation(kind) {
		t.Fatalf("later Country DE inherited an active remediation %q", kind)
	}
}

// TestLiveLookup_ActiveBanOutranksScopeError is matrix row 4: the ban must not be downgraded or
// masked, and the request must not be diverted to BouncerLapiFailureAction.
func TestLiveLookup_ActiveBanOutranksScopeError(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, testLiveBanBody("ip", "1.2.3.4"), map[string]string{"country": ""}))
	value, _, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
	if err == nil {
		t.Fatal("a ban is reported with the overloaded banned error")
	}
	if !decisionscope.IsActiveRemediation(value) {
		t.Fatalf("an active ban must survive a scope failure, got %q", value)
	}
	if !strings.Contains(err.Error(), "handleNoStreamCache:banned") {
		t.Fatalf("ban error %q must stay the banned signal, not the scope error", err)
	}
}

// TestLiveLookup_IPErrorStillPropagates is matrix row 5: unchanged behavior on an IP-query failure.
func TestLiveLookup_IPErrorStillPropagates(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, "", map[string]string{
		"country": testLiveBanBody("country", "FR"),
	}))
	value, _, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
	if err == nil {
		t.Fatal("IP query 500 expected an error")
	}
	if decisionscope.IsActiveRemediation(value) {
		t.Fatalf("IP query failure must come back non-active, got %q", value)
	}
}

// TestLiveLookup_ScopeBanWinsOverAnotherScopeError is matrix row 6: one scope errors, another bans.
func TestLiveLookup_ScopeBanWinsOverAnotherScopeError(t *testing.T) {
	client := newTestLiveClient(t, testLiveScopeLAPI(t, "null", map[string]string{
		"country":  "",
		"username": testLiveBanBody("username", "alice"),
	}))
	value, _, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR", "username": "alice"}, 60)
	if err == nil {
		t.Fatal("a ban is reported with the overloaded banned error")
	}
	if !decisionscope.IsActiveRemediation(value) {
		t.Fatalf("a scope ban must outrank another scope's failure, got %q", value)
	}
	if !strings.Contains(err.Error(), "handleNoStreamCache:banned") {
		t.Fatalf("ban error %q must stay the banned signal, not the scope error", err)
	}
}

// TestLiveLookup_ScopeErrorLogsAtWarn proves the swallowed DEBUG line is now WARN, so it shows at
// the plugin's default INFO level and is absent only when the operator raised the level to ERROR.
func TestLiveLookup_ScopeErrorLogsAtWarn(t *testing.T) {
	server := testLiveScopeLAPI(t, "null", map[string]string{"country": ""})
	for _, tc := range []struct {
		level slog.Level
		want  bool
	}{
		{slog.LevelError, false},
		{slog.LevelInfo, true},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			logged := captureTestStreamTickLog(t, tc.level, func(log *slog.Logger) {
				client := newTestLiveClient(t, server)
				client.log = log
				kind, origin, err := client.LiveLookup("1.2.3.4", map[string]string{"country": "FR"}, 60)
				_ = kind
				_ = origin
				_ = err
			})
			if got := strings.Contains(logged, "handleNoStreamCache:scopeQuery"); got != tc.want {
				t.Fatalf("scopeQuery at %s: got %v want %v\n%s", tc.level, got, tc.want, logged)
			}
		})
	}
}
