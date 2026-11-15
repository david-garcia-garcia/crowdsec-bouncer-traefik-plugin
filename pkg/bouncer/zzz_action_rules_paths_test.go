package bouncer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestFoldActionRulesChallengePathKeepsAppsec proves a bypass rule that also matches the
// challenge prefix (here a static-asset rule) keeps its LAPI skip but not its AppSec skip there.
func TestFoldActionRulesChallengePathKeepsAppsec(t *testing.T) {
	b := &Bouncer{log: logger.New("ERROR", "")}
	b.actionRules = mustPathAction(t, "static", `\.js$`, httprule.ActionBypass)

	challenge := b.foldActionRules(testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/crowdsec-internal/challenge/fpscanner.js", nil), "192.0.2.10"))
	if challenge.SkipAppsec || !challenge.SkipLapi {
		t.Fatalf("challenge path match=%+v, want SkipAppsec=false SkipLapi=true", challenge)
	}
	asset := b.foldActionRules(testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/static/app.js", nil), "192.0.2.10"))
	if !asset.SkipAppsec || !asset.SkipLapi {
		t.Fatalf("static asset match=%+v, want both legs skipped", asset)
	}
}

// TestServeAppSecAmbiguousPathStillQueriesAppsec proves a bypassAppsec path rule does not skip
// AppSec when the path has more than one reading (a Java backend reads /healthz/..;/admin as /admin).
func TestServeAppSecAmbiguousPathStillQueriesAppsec(t *testing.T) {
	var queries atomic.Int32
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		log:  logger.New("ERROR", ""),
	}
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.actionRules = mustPathAction(t, "healthz", "^/healthz(/|$)", httprule.ActionBypassAppsec)

	for _, tc := range []struct {
		target      string
		wantQueries int32
	}{
		{"/healthz", 0},
		{"/healthz/live", 0},
		{"/healthz/..;/admin", 1},
		{"/healthz/%2E%2E;/admin", 1},
		{"/healthz/..%5Cadmin", 1},
		{"/healthz%2Fadmin", 1},
		{"/healthz/%252e%252e/admin", 1},
	} {
		queries.Store(0)
		continueAfterLAPIForTest(b, httptest.NewRecorder(), testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com"+tc.target, nil), "192.0.2.10"))
		if got := queries.Load(); got != tc.wantQueries {
			t.Errorf("%s: AppSec queries=%d want %d", tc.target, got, tc.wantQueries)
		}
	}
}
