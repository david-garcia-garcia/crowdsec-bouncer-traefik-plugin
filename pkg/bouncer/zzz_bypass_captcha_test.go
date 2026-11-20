package bouncer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// testBypassCaptchaClientIP is the client address the LAPI decisions of these tests are stored for.
const testBypassCaptchaClientIP = "203.0.113.10"

// apiBypassCaptchaRules is the rule under test: requests under /api/ get no captcha.
func apiBypassCaptchaRules(t *testing.T) *httprule.ActionSet {
	t.Helper()
	return mustPathAction(t, "api", "^/api/", httprule.ActionBypassCaptcha)
}

// testBypassCaptchaLapiBouncer is a stream-mode router with the /api/ bypassCaptcha rule, an optional
// captcha client, an optional origin remap, and one stored decision for testBypassCaptchaClientIP.
func testBypassCaptchaLapiBouncer(t *testing.T, captchaClient *captcha.Client, remap map[string]map[string]string, kind, origin string) (*Bouncer, *bool, *lapi.Client) {
	t.Helper()
	lapiClient, store := lapi.NewTestClient(logger.New("ERROR", ""))
	lapi.AttachTestMetricsReporter(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	b, passed := testRemapStreamBouncer(t, lapiClient, remap)
	b.remediationCustomHeader = "X-Remediation"
	b.actionRules = apiBypassCaptchaRules(t)
	bindTestCaptcha(b, captchaClient)
	lapi.SeedLiveSnapshotForTest(store, testBypassCaptchaClientIP, kind, origin, 60)
	return b, passed, lapiClient
}

// serveBypassCaptchaRequest runs the whole ServeHTTP for a GET to target from testBypassCaptchaClientIP.
func serveBypassCaptchaRequest(b *Bouncer, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://example.com"+target, nil)
	req.RemoteAddr = testBypassCaptchaClientIP + ":1"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	return rw
}

// TestBypassCaptcha_lapiCaptchaDecisionReachesOrigin proves a CrowdSec captcha decision lets a /api/
// request through, with no header and no dropped count, while a request outside the rule still gets the captcha.
func TestBypassCaptcha_lapiCaptchaDecisionReachesOrigin(t *testing.T) {
	b, passed, lapiClient := testBypassCaptchaLapiBouncer(t, testCaptchaClient(t, "/fast.js", "", "", nil), nil, decisionscope.CaptchaValue, "crowdsec")

	rw := serveBypassCaptchaRequest(b, "/api/items")
	if !*passed {
		t.Fatalf("a captcha decision on a bypassCaptcha request must reach the backend, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "" {
		t.Fatalf("a bypassed captcha must not set X-Remediation, got %q", got)
	}
	if got := lapiClient.TestDroppedCount("crowdsec", "ipv4", "captcha"); got != 0 {
		t.Fatalf("dropped crowdsec/captcha=%d want 0", got)
	}

	*passed = false
	rw = serveBypassCaptchaRequest(b, "/catalog")
	if *passed {
		t.Fatal("a request outside the rule must not reach the backend")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want the captcha page outside the rule, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:lapi:crowdsec" {
		t.Fatalf("X-Remediation=%q want captcha:lapi:crowdsec", got)
	}
}

// TestBypassCaptcha_lapiBanStillBans proves the rule weakens only the captcha: a ban decision bans on /api/.
func TestBypassCaptcha_lapiBanStillBans(t *testing.T) {
	b, passed, _ := testBypassCaptchaLapiBouncer(t, testCaptchaClient(t, "/fast.js", "", "", nil), nil, decisionscope.BannedValue, "crowdsec")

	rw := serveBypassCaptchaRequest(b, "/api/items")
	if *passed {
		t.Fatal("a ban decision must not reach the backend")
	}
	if rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:lapi:crowdsec" {
		t.Fatalf("want 403 ban:lapi:crowdsec, got %d %q", rw.Code, rw.Header().Get("X-Remediation"))
	}
}

// TestBypassCaptcha_routerWithoutCaptchaIsNotBanned proves the bypass comes before the downgrade ban:
// a router with no captcha lets the /api/ request through and does not warn, and still bans outside the rule.
func TestBypassCaptcha_routerWithoutCaptchaIsNotBanned(t *testing.T) {
	b, passed, _ := testBypassCaptchaLapiBouncer(t, nil, nil, decisionscope.CaptchaValue, "crowdsec")
	log, sink := newTestLogSink(logger.LevelTrace)
	b.log = log

	serveBypassCaptchaRequest(b, "/api/items")
	if !*passed {
		t.Fatal("a bypassed captcha on a router without a captcha must reach the backend")
	}
	logged := sink.String()
	if strings.Contains(logged, msgCaptchaUnsubscribed) {
		t.Fatalf("a bypassed captcha must not warn %q, got %s", msgCaptchaUnsubscribed, logged)
	}
	if !strings.Contains(logged, `"msg":"bypassCaptcha"`) || !strings.Contains(logged, `"name":"api"`) {
		t.Fatalf("want TRACE bypassCaptcha naming the rule, got %s", logged)
	}

	*passed = false
	rw := serveBypassCaptchaRequest(b, "/catalog")
	if *passed || rw.Code != http.StatusForbidden {
		t.Fatalf("outside the rule a captcha without a captcha client stays a ban, got %d passed=%v", rw.Code, *passed)
	}
}

// TestBypassCaptcha_remappedBanStaysBan proves a ban the origin remap softens to a captcha is not
// bypassed into a pass, that the same decision is a captcha outside the rule, and that ban-to-pass still passes.
func TestBypassCaptcha_remappedBanStaysBan(t *testing.T) {
	softened := map[string]map[string]string{"CAPI": {"ban": "captcha"}}
	b, passed, _ := testBypassCaptchaLapiBouncer(t, testCaptchaClient(t, "/fast.js", "", "", nil), softened, decisionscope.BannedValue, "CAPI")

	rw := serveBypassCaptchaRequest(b, "/api/items")
	if *passed {
		t.Fatal("a ban softened to a captcha must not pass on a bypassCaptcha request")
	}
	if rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:lapi:CAPI" {
		t.Fatalf("want 403 ban:lapi:CAPI, got %d %q", rw.Code, rw.Header().Get("X-Remediation"))
	}

	rw = serveBypassCaptchaRequest(b, "/catalog")
	if *passed || rw.Header().Get("X-Remediation") != "captcha:lapi:CAPI" {
		t.Fatalf("outside the rule the remap still applies, got %d %q passed=%v", rw.Code, rw.Header().Get("X-Remediation"), *passed)
	}

	passRemap := map[string]map[string]string{"CAPI": {"ban": "pass"}}
	b, passed, _ = testBypassCaptchaLapiBouncer(t, testCaptchaClient(t, "/fast.js", "", "", nil), passRemap, decisionscope.BannedValue, "CAPI")
	serveBypassCaptchaRequest(b, "/api/items")
	if !*passed {
		t.Fatal("a ban-to-pass remap must still pass on a bypassCaptcha request")
	}
}

// TestBypassCaptcha_lapiFailureActionCaptchaReachesOrigin proves the LAPI failure action captcha
// (subscribed, no client published) lets a /api/ request through and still serves the captcha outside the rule.
func TestBypassCaptcha_lapiFailureActionCaptchaReachesOrigin(t *testing.T) {
	b, passed, _ := testBypassCaptchaLapiBouncer(t, testCaptchaClient(t, "/fast.js", "", "", nil), nil, decisionscope.CaptchaValue, "crowdsec")
	bindTestLAPI(b, nil)
	b.subscribeLAPI = true
	b.lapiFailureAction = configuration.FailureActionCaptcha

	serveBypassCaptchaRequest(b, "/api/items")
	if !*passed {
		t.Fatal("the LAPI failure action captcha must reach the backend on a bypassCaptcha request")
	}

	*passed = false
	rw := serveBypassCaptchaRequest(b, "/catalog")
	if *passed || rw.Header().Get("X-Remediation") != "captcha:lapi-failure" {
		t.Fatalf("outside the rule want captcha:lapi-failure, got %d %q passed=%v", rw.Code, rw.Header().Get("X-Remediation"), *passed)
	}
}

// TestBypassCaptcha_appsecVerdicts proves an AppSec captcha verdict lets a /api/ request through,
// while a ban verdict still bans and a challenge page is still relayed.
func TestBypassCaptcha_appsecVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		verdict    string
		wantNext   bool
		wantStatus int
		wantHeader string
		wantBody   string
	}{
		{name: "captcha continues", verdict: appsecCaptchaEnvelope, wantNext: true, wantStatus: http.StatusOK},
		{name: "ban still bans", verdict: `{"action":"ban","http_status":403}`, wantStatus: http.StatusForbidden, wantHeader: "ban:appsec"},
		{name: "challenge still relayed", verdict: `{"action":"challenge","http_status":200,"user_body_content":"<html>challenge</html>"}`, wantStatus: http.StatusOK, wantHeader: "captcha:challenge", wantBody: "<html>challenge</html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, next, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, tc.verdict), testCaptchaClient(t, "/fast.js", "", "", nil))
			b.actionRules = apiBypassCaptchaRules(t)

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://example.com/api/items", nil)
			continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

			if next.called != tc.wantNext {
				t.Fatalf("next called=%v want %v (status %d body %q)", next.called, tc.wantNext, rw.Code, rw.Body.String())
			}
			if rw.Code != tc.wantStatus || rw.Header().Get("X-Remediation") != tc.wantHeader {
				t.Fatalf("got %d %q want %d %q", rw.Code, rw.Header().Get("X-Remediation"), tc.wantStatus, tc.wantHeader)
			}
			if tc.wantBody != "" && rw.Body.String() != tc.wantBody {
				t.Fatalf("body=%q want %q", rw.Body.String(), tc.wantBody)
			}
			if got := lapiClient.TestDroppedCount("appsec", "ipv4", "captcha"); got != 0 {
				t.Fatalf("dropped appsec/captcha=%d want 0", got)
			}
		})
	}
}

// TestBypassCaptcha_appsecFailureActionCaptchaReachesOrigin proves the AppSec failure action captcha
// (subscribed, no client published) lets a /api/ request through and still serves the captcha outside the rule.
func TestBypassCaptcha_appsecFailureActionCaptchaReachesOrigin(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testCaptchaClient(t, "/fast.js", "", "", nil))
	bindTestAppSec(b, nil)
	b.subscribeAppSec = true
	b.appsecFailureAction = configuration.FailureActionCaptcha
	b.actionRules = apiBypassCaptchaRules(t)

	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/api/items", nil), testCaptchaRemoteIP))
	if !next.called {
		t.Fatalf("the AppSec failure action captcha must reach the backend on a bypassCaptcha request, got %d", rw.Code)
	}

	next.called = false
	rw = httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/catalog", nil), testCaptchaRemoteIP))
	if next.called || rw.Header().Get("X-Remediation") != "captcha:appsec-failure" {
		t.Fatalf("outside the rule want captcha:appsec-failure, got %d %q next=%v", rw.Code, rw.Header().Get("X-Remediation"), next.called)
	}
}

// TestBypassCaptcha_winsOverCaptchaRule proves a captcha rule on another matching row does not apply,
// and that with no captcha rule left an AppSec challenge page is relayed instead of being dropped.
func TestBypassCaptcha_winsOverCaptchaRule(t *testing.T) {
	rules := []httprule.ActionRule{
		{Name: "site-captcha", Action: []string{httprule.ActionCaptcha}, Rule: httprule.Rule{Host: `^example\.com$`}},
		{Name: "api", Action: []string{httprule.ActionBypassCaptcha}, Rule: httprule.Rule{Path: "^/api/"}},
	}

	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testCaptchaClient(t, "/fast.js", "", "", nil))
	b.actionRules = mustCompileActions(t, rules)
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/api/items", nil), testCaptchaRemoteIP))
	if !next.called {
		t.Fatalf("bypassCaptcha must win over a captcha rule, got %d %q", rw.Code, rw.Body.String())
	}
	next.called = false
	rw = httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/catalog", nil), testCaptchaRemoteIP))
	if next.called || rw.Header().Get("X-Remediation") != "captcha:rules" {
		t.Fatalf("outside the bypass the captcha rule still applies, got %d %q next=%v", rw.Code, rw.Header().Get("X-Remediation"), next.called)
	}

	challenge := `{"action":"challenge","http_status":200,"user_body_content":"<html>challenge</html>"}`
	b, next, _ = testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, challenge), testCaptchaClient(t, "/fast.js", "", "", nil))
	b.actionRules = mustCompileActions(t, rules)
	rw = httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/api/items", nil), testCaptchaRemoteIP))
	if next.called || rw.Body.String() != "<html>challenge</html>" {
		t.Fatalf("an AppSec challenge must be relayed when the captcha rule is bypassed, got %d %q next=%v", rw.Code, rw.Body.String(), next.called)
	}
}

// TestBypassCaptcha_captchaFormPostReachesOrigin proves a challenge-form POST on a bypassCaptcha request
// is not taken by the captcha gate: the backend gets it with its body.
func TestBypassCaptcha_captchaFormPostReachesOrigin(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))
	b.actionRules = apiBypassCaptchaRules(t)

	fields := url.Values{"crowdsec_captcha_challenge": {"v1"}, "dummy-captcha-response": {"token"}}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/items", strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if !next.called || next.body != fields.Encode() {
		t.Fatalf("the form POST must reach the backend unchanged, called=%v body=%q status=%d", next.called, next.body, rw.Code)
	}
	if hasGateCookie(rw) {
		t.Fatal("a bypassed captcha form POST must not set the gate cookie")
	}
}

// TestBypassCaptcha_pathRegexAppliesAsWritten proves a bypassCaptcha path rule does not use the
// single-reading path check: every path its regex matches bypasses the captcha.
func TestBypassCaptcha_pathRegexAppliesAsWritten(t *testing.T) {
	for _, target := range []string{"/api/items%20x", "/api/..;/admin", "/api/..%2Fadmin", "/api/..%5Cadmin", "/api/%252e%252e/admin"} {
		b, passed, _ := testBypassCaptchaLapiBouncer(t, testCaptchaClient(t, "/fast.js", "", "", nil), nil, decisionscope.CaptchaValue, "crowdsec")
		rw := serveBypassCaptchaRequest(b, target)
		if !*passed {
			t.Errorf("%s: the path regex matched, so the captcha must be bypassed, got %d %q", target, rw.Code, rw.Body.String())
		}
	}
}

// testBypassCaptchaLiveBouncer is a live-mode router with the /api/ bypassCaptcha rule. Its LAPI answers
// every per-IP query with one decision of decisionType and origin, so the first request takes the live lookup.
func testBypassCaptchaLiveBouncer(t *testing.T, remap map[string]map[string]string, decisionType, origin string) (*Bouncer, *bool) {
	t.Helper()
	log := logger.New("ERROR", "")
	lapiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") == "" {
			_, _ = w.Write([]byte("null"))
			return
		}
		_ = json.NewEncoder(w).Encode([]lapi.Decision{{
			Value: r.URL.Query().Get("ip"), Type: decisionType, Duration: "1h", Origin: origin, Scope: "ip",
		}})
	}))
	t.Cleanup(lapiServer.Close)
	lapiURL, err := url.Parse(lapiServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	lapiClient, err := lapi.New(&configuration.Config{
		LapiHTTPTimeoutSeconds: 10,
		LapiHost:               lapiURL.Host,
		LapiKey:                "test-key",
		LapiMode:               configuration.LiveMode,
		LapiPath:               "/",
		LapiScheme:             lapiURL.Scheme,
		LapiTLSInsecureVerify:  true,
	}, log, "test", decisionstore.NewMemory(log), "bypass-captcha-live", "bypass-captcha-live")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lapiClient.Close)
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	b := &Bouncer{
		enabled:                  true,
		trustedClients:           &ip.PoolStrategy{Checker: clientChecker},
		log:                      log,
		remediationStatusCode:    http.StatusForbidden,
		remediationCustomHeader:  "X-Remediation",
		banTemplateContentType:   "text/html; charset=utf-8",
		originBasedDecisionRemap: copyOriginBasedDecisionRemap(remap),
		actionRules:              apiBypassCaptchaRules(t),
		subscribeLAPI:            true,
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	b.lapiBound.Store(lapiClient)
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	return b, &passed
}

// TestBypassCaptcha_liveLookup proves the live lookup behaves as the cache lookup: a captcha decision
// lets a /api/ request through, a ban the remap softens to a captcha stays a ban there, and the same
// softened ban is a captcha outside the rule.
func TestBypassCaptcha_liveLookup(t *testing.T) {
	softened := map[string]map[string]string{"CAPI": {"ban": "captcha"}}
	for _, tc := range []struct {
		name         string
		remap        map[string]map[string]string
		decisionType string
		origin       string
		target       string
		wantPassed   bool
		wantHeader   string
	}{
		{name: "captcha decision continues", decisionType: "captcha", origin: "crowdsec", target: "/api/items", wantPassed: true},
		{name: "captcha decision outside the rule", decisionType: "captcha", origin: "crowdsec", target: "/catalog", wantHeader: "captcha:lapi:crowdsec"},
		{name: "softened ban stays a ban", remap: softened, decisionType: "ban", origin: "CAPI", target: "/api/items", wantHeader: "ban:lapi:CAPI"},
		{name: "softened ban outside the rule", remap: softened, decisionType: "ban", origin: "CAPI", target: "/catalog", wantHeader: "captcha:lapi:CAPI"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, passed := testBypassCaptchaLiveBouncer(t, tc.remap, tc.decisionType, tc.origin)
			rw := serveBypassCaptchaRequest(b, tc.target)
			if *passed != tc.wantPassed || rw.Header().Get("X-Remediation") != tc.wantHeader {
				t.Fatalf("passed=%v header=%q status=%d, want passed=%v header=%q", *passed, rw.Header().Get("X-Remediation"), rw.Code, tc.wantPassed, tc.wantHeader)
			}
		})
	}
}
