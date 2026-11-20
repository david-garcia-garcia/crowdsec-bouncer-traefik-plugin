package bouncer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
)

// These tests give the ModSec leg the cases the AppSec leg already has, so both WAFs are held to one rule.

// countingModsec binds a sidecar that counts its calls and blocks a query with ../etc.
func countingModsec(t *testing.T, hits *atomic.Int32) *modsecurity.Client {
	t.Helper()
	return modsecWithSidecar(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.URL.RawQuery, "../etc") {
			http.Error(w, "crs-page", http.StatusForbidden)
		}
	}, 0)
}

// countingAppsec returns an AppSec client that counts its calls and allows every request.
func countingAppsec(t *testing.T, hits *atomic.Int32) *appsec.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return appsec.NewTestClient(u, srv.Client(), logger.New("ERROR", ""))
}

// withTestMetrics binds a LAPI client that only counts drops. continueAfterLAPIForTest never queries it.
func withTestMetrics(b *Bouncer) *lapi.Client {
	lapiClient, _ := lapi.NewTestClient(logger.New("ERROR", ""))
	lapi.AttachTestMetricsReporter(lapiClient)
	bindTestLAPI(b, lapiClient)
	return lapiClient
}

func serveModsecAfterLAPI(b *Bouncer, target string) *httptest.ResponseRecorder {
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(testModsecRequest(target), "203.0.113.40"))
	return rw
}

// TestServeHTTP_modsecDropsCountUnderTheirOrigins proves a sidecar block counts under modsec, and a
// failure action under plugin:modsec_failure with its remediation, as AppSec counts appsec and
// plugin:appsec_failure.
func TestServeHTTP_modsecDropsCountUnderTheirOrigins(t *testing.T) {
	var hits atomic.Int32
	b, _ := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	bindTestModSec(b, countingModsec(t, &hits))
	lapiClient := withTestMetrics(b)
	if rw := serveModsecAfterLAPI(b, "/?test=../etc"); rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
	if got := lapiClient.TestDroppedCount("modsec", "ipv4", "ban"); got != 1 {
		t.Fatalf("modsec ban count=%d want 1", got)
	}

	failHits := 0
	for _, tc := range []struct{ action, remediation string }{
		{configuration.FailureActionBan, "ban"},
		{configuration.FailureActionCaptcha, "captcha"},
	} {
		b, _ := testModsecBouncer(t, tc.action, nil)
		bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
		bindTestModSec(b, failingModsec(t, 0, &failHits))
		lapiClient := withTestMetrics(b)
		serveModsecAfterLAPI(b, "/")
		if got := lapiClient.TestDroppedCount(lapi.OriginPluginModsecFailure, "ipv4", tc.remediation); got != 1 {
			t.Fatalf("%s: %s %s count=%d want 1", tc.action, lapi.OriginPluginModsecFailure, tc.remediation, got)
		}
	}
}

// TestServeHTTP_appsecFailureDropCountsUnderFailureOrigin is the AppSec half of the test above.
func TestServeHTTP_appsecFailureDropCountsUnderFailureOrigin(t *testing.T) {
	b, _ := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	b.appsecFailureAction = configuration.FailureActionBan
	bindTestAppSec(b, nil)
	b.subscribeAppSec = true
	lapiClient := withTestMetrics(b)
	rw := serveModsecAfterLAPI(b, "/")
	if rw.Header().Get("X-Remediation") != "ban:appsec-failure" {
		t.Fatalf("header=%q want ban:appsec-failure", rw.Header().Get("X-Remediation"))
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginAppsecFailure, "ipv4", "ban"); got != 1 {
		t.Fatalf("%s ban count=%d want 1", lapi.OriginPluginAppsecFailure, got)
	}
}

// TestServeModSecAmbiguousPathStillInspects mirrors TestServeAppSecAmbiguousPathStillQueriesAppsec:
// a bypassModsec path rule skips nothing on a path with more than one reading.
func TestServeModSecAmbiguousPathStillInspects(t *testing.T) {
	var hits atomic.Int32
	b, _ := testModsecBouncer(t, configuration.FailureActionPassthrough, nil)
	bindTestModSec(b, countingModsec(t, &hits))
	b.actionRules = mustPathAction(t, "healthz", "^/healthz(/|$)", httprule.ActionBypassModsec)
	for _, tc := range []struct {
		target   string
		wantHits int32
	}{
		{"/healthz", 0},
		{"/healthz/live", 0},
		{"/healthz/..;/admin", 1},
		{"/healthz/..%5Cadmin", 1},
		{"/healthz%2Fadmin", 1},
	} {
		hits.Store(0)
		serveModsecAfterLAPI(b, tc.target)
		if got := hits.Load(); got != tc.wantHits {
			t.Errorf("%s: sidecar calls=%d want %d", tc.target, got, tc.wantHits)
		}
	}
}

// TestServeHTTP_bypassSkipsModsec proves the bypass token skips ModSec as well as LAPI and AppSec.
func TestServeHTTP_bypassSkipsModsec(t *testing.T) {
	var hits atomic.Int32
	b, passed := testModsecBouncer(t, configuration.FailureActionBan, []httprule.ActionRule{{
		Name: "all", Action: []string{httprule.ActionBypass}, Rule: httprule.Rule{Path: "^/skip$"},
	}})
	bindTestModSec(b, countingModsec(t, &hits))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/skip?test=../etc"))
	if !*passed || hits.Load() != 0 || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("bypass must skip the sidecar: passed=%v hits=%d header=%q", *passed, hits.Load(), rw.Header().Get("X-Remediation"))
	}
}

// TestServeHTTP_trustedIPSkipsBothWafs proves a trusted client reaches the origin with no AppSec query
// and no sidecar call, even on a request either WAF would block.
func TestServeHTTP_trustedIPSkipsBothWafs(t *testing.T) {
	var appsecHits, modsecHits atomic.Int32
	b, passed := testModsecBouncer(t, configuration.FailureActionBan, nil)
	trusted, err := ip.NewChecker(b.log, []string{"203.0.113.40"})
	if err != nil {
		t.Fatal(err)
	}
	b.trustedClients = &ip.PoolStrategy{Checker: trusted}
	bindTestAppSec(b, countingAppsec(t, &appsecHits))
	bindTestModSec(b, countingModsec(t, &modsecHits))
	b.ServeHTTP(httptest.NewRecorder(), testModsecRequest("/?test=../etc"))
	if !*passed || appsecHits.Load() != 0 || modsecHits.Load() != 0 {
		t.Fatalf("trusted client: passed=%v appsec=%d modsec=%d", *passed, appsecHits.Load(), modsecHits.Load())
	}
}

// TestServeHTTP_unsolvedCaptchaRuleDoesNotCallModsec proves the captcha gate answers before the sidecar.
func TestServeHTTP_unsolvedCaptchaRuleDoesNotCallModsec(t *testing.T) {
	var hits atomic.Int32
	b, passed := testModsecBouncer(t, configuration.FailureActionPassthrough, []httprule.ActionRule{{
		Name: "gate", Action: []string{httprule.ActionCaptcha}, Rule: httprule.Rule{Path: "^/"},
	}})
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	bindTestModSec(b, countingModsec(t, &hits))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testModsecRequest("/?test=../etc"))
	if *passed || hits.Load() != 0 || rw.Header().Get("X-Remediation") != "captcha:rules" {
		t.Fatalf("unsolved captcha: passed=%v sidecar=%d header=%q", *passed, hits.Load(), rw.Header().Get("X-Remediation"))
	}
}

// TestServeModSec_clientBodyErrorsAreNotBans mirrors TestHandleNextServeHTTP_clientBodyRead and
// TestHandleNextServeHTTP_clientDisconnected: whatever the failure action, a body the client did not
// send whole is a 400 or a silent drop, never a sidecar call, a ban, or a dropped count.
func TestServeModSec_clientBodyErrorsAreNotBans(t *testing.T) {
	for _, failureAction := range []string{configuration.FailureActionBan, configuration.FailureActionPassthrough, configuration.FailureActionCaptcha} {
		for _, tc := range []struct {
			name       string
			readErr    error
			wantHeader string
		}{
			{"body-read", errors.New("i/o timeout"), "error:client-body-read"},
			{"disconnect", context.Canceled, "error:client-disconnected"},
		} {
			t.Run(failureAction+"/"+tc.name, func(t *testing.T) {
				var hits atomic.Int32
				b, passed := testModsecBouncer(t, failureAction, nil)
				bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
				bindTestModSec(b, countingModsec(t, &hits))
				lapiClient := withTestMetrics(b)
				req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", failingBodyForDisconnectTest{err: tc.readErr})
				req.ContentLength = 100
				rw := &statusWatchRecorder{ResponseRecorder: httptest.NewRecorder()}
				continueAfterLAPIForTest(b, rw, testClientRequest(req, "203.0.113.40"))
				if *passed || hits.Load() != 0 {
					t.Fatalf("passed=%v sidecar=%d want neither", *passed, hits.Load())
				}
				assertClientBodyErrorAnswer(t, rw, tc.wantHeader, tc.name == "disconnect")
				for _, remediation := range []string{"ban", "captcha"} {
					if got := lapiClient.TestDroppedCount(lapi.OriginPluginModsecFailure, "ipv4", remediation); got != 0 {
						t.Fatalf("%s count=%d want 0", remediation, got)
					}
				}
			})
		}
	}
}

// assertClientBodyErrorAnswer checks the header, then a 400 for a body-read error or no status for a disconnect.
func assertClientBodyErrorAnswer(t *testing.T, rw *statusWatchRecorder, wantHeader string, disconnect bool) {
	t.Helper()
	if got := rw.Header().Get("X-Remediation"); got != wantHeader {
		t.Fatalf("header=%q want %q", got, wantHeader)
	}
	if disconnect && rw.wroteStatus {
		t.Fatalf("disconnect must not WriteHeader, got %d", rw.Code)
	}
	if !disconnect && rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rw.Code)
	}
}
