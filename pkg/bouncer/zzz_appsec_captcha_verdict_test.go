package bouncer

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// appsecCaptchaEnvelope is what CrowdSec sends for SetRemediation("captcha"): no page, no cookies, no headers.
const appsecCaptchaEnvelope = `{"action":"captcha","http_status":403}`

// recordedNextRequest records what reached next (the backend).
type recordedNextRequest struct {
	called bool
	body   string
}

// testAppsecVerdictBouncer wires AppSec (answering with verdict), an optional captcha client, and a metrics-counting LAPI client.
func testAppsecVerdictBouncer(t *testing.T, verdict http.HandlerFunc, captchaClient *captcha.Client) (*Bouncer, *recordedNextRequest, *lapi.Client) {
	t.Helper()
	appsecServer := httptest.NewServer(verdict)
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned reason={{.RemediationReason}}")
	if err != nil {
		t.Fatal(err)
	}
	next := &recordedNextRequest{}
	b := &Bouncer{
		next: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			next.called = true
			if r.Body != nil {
				body, _ := io.ReadAll(r.Body)
				next.body = string(body)
			}
		}),
		log:                     logger.New("ERROR"),
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		banTemplate:             banTemplate,
		banTemplateContentType:  "text/html; charset=utf-8",
	}
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR")))
	bindTestCaptcha(b, captchaClient)
	lapiClient, _ := lapi.NewTestClient(b.log)
	lapi.AttachTestMetricsReporter(lapiClient)
	bindTestLAPI(b, lapiClient)
	return b, next, lapiClient
}

// appsecAnswers is an AppSec stand-in that answers every query with status and body.
func appsecAnswers(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// testSiteverifyCaptchaClient is a captcha client whose provider accepts every token.
func testSiteverifyCaptchaClient(t *testing.T) *captcha.Client {
	t.Helper()
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)
	return testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
}

// captchaFormPost builds a form-encoded POST to /protected, with the gate cookie when gateCookie is set.
func captchaFormPost(t *testing.T, fields url.Values, gateCookie string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if gateCookie != "" {
		req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: gateCookie})
	}
	return req
}

func hasGateCookie(rw *httptest.ResponseRecorder) bool {
	cookie := cookieNamed(rw.Result().Cookies(), "crowdsec_captcha_gate")
	return cookie != nil && cookie.Value != ""
}

func TestAppsecCaptchaVerdict_servesRouterCaptcha(t *testing.T) {
	b, next, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), testCaptchaClient(t, "/fast.js", "", "", nil))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if next.called {
		t.Fatal("an unsolved AppSec captcha must not reach the backend")
	}
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want the router captcha page, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:appsec" {
		t.Fatalf("X-Remediation=%q want captcha:appsec", got)
	}
	if got := lapiClient.TestDroppedCount("appsec", "ipv4", "captcha"); got != 1 {
		t.Fatalf("dropped appsec/captcha=%d want 1", got)
	}
}

func TestAppsecCaptchaVerdict_solvedGateReachesOrigin(t *testing.T) {
	client := testSiteverifyCaptchaClient(t)
	cookieValue := solveTestGateCookie(t, client)
	b, next, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), client)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if !next.called {
		t.Fatalf("a solved visitor must reach the backend, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "" {
		t.Fatalf("pass must not set X-Remediation, got %q", got)
	}
	if got := lapiClient.TestDroppedCount("appsec", "ipv4", "captcha"); got != 0 {
		t.Fatalf("dropped appsec/captcha=%d want 0", got)
	}
}

func TestAppsecCaptchaVerdict_routerWithoutCaptchaBans(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if next.called {
		t.Fatal("AppSec captcha without a router captcha must not reach the backend")
	}
	if rw.Code != http.StatusForbidden || rw.Body.String() != "banned reason=APPSEC" {
		t.Fatalf("want ban page with reason APPSEC, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:captcha-downgrade" {
		t.Fatalf("X-Remediation=%q want ban:captcha-downgrade", got)
	}
}

func TestAppsecCaptchaVerdict_captchaRuleServesItsOwnGate(t *testing.T) {
	b, next, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), testCaptchaClient(t, "/fast.js", "", "", nil))
	b.actionRules = mustPathAction(t, "login", "^/protected$", httprule.ActionCaptcha)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if next.called {
		t.Fatal("captcha rule plus AppSec captcha must not reach the backend")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want captcha page, got %q", rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:rules" {
		t.Fatalf("X-Remediation=%q want captcha:rules", got)
	}
	if got := lapiClient.TestDroppedCount("appsec", "ipv4", "captcha"); got != 0 {
		t.Fatalf("dropped appsec/captcha=%d want 0 (the rule served the gate)", got)
	}
}

func TestAppsecCaptchaVerdict_headServesCaptchaPage(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), testCaptchaClient(t, "/fast.js", "", "", nil))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if next.called {
		t.Fatal("HEAD under an AppSec captcha must not reach the backend")
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:appsec" {
		t.Fatalf("X-Remediation=%q want captcha:appsec", got)
	}
}

func TestAppsecCaptchaVerdict_markerPostAllowedByAppsecIsValidated(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	fields.Set("dummy-captcha-response", "ok")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if next.called {
		t.Fatal("the captcha solve POST must not reach the backend")
	}
	if rw.Code != http.StatusFound || !hasGateCookie(rw) {
		t.Fatalf("want 302 with a gate cookie, got %d cookies=%v", rw.Code, rw.Result().Cookies())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:solved" {
		t.Fatalf("X-Remediation=%q want captcha:solved", got)
	}
}

func TestAppsecCaptchaVerdict_markerPostWithoutTokenServesChallenge(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if next.called {
		t.Fatal("a challenge-marker POST must not reach the backend when captcha is usable")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want the captcha page again, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:appsec" {
		t.Fatalf("X-Remediation=%q want captcha:appsec", got)
	}
}

func TestAppsecCaptchaVerdict_leftoverMarkerPostRedirects(t *testing.T) {
	client := testSiteverifyCaptchaClient(t)
	cookieValue := solveTestGateCookie(t, client)
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), client)

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, cookieValue), testCaptchaRemoteIP))

	if next.called {
		t.Fatal("a leftover challenge form must not reach the backend")
	}
	if rw.Code != http.StatusFound || hasGateCookie(rw) {
		t.Fatalf("want 302 without a new gate cookie, got %d cookies=%v", rw.Code, rw.Result().Cookies())
	}
}

func TestAppsecCaptchaVerdict_ordinaryPostAllowedReachesOriginIntact(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))

	fields := url.Values{}
	fields.Set("username", "alice")
	fields.Set("dummy-captcha-response", "app-widget-token")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if !next.called {
		t.Fatalf("an application POST must reach the backend, got %d %q", rw.Code, rw.Body.String())
	}
	if next.body != fields.Encode() {
		t.Fatalf("backend body=%q want %q", next.body, fields.Encode())
	}
}

func TestAppsecCaptchaVerdict_markerPostWithoutRouterCaptchaReachesOrigin(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), nil)

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if !next.called {
		t.Fatalf("without a router captcha the POST must reach the backend, got %d %q", rw.Code, rw.Body.String())
	}
	if next.body != fields.Encode() {
		t.Fatalf("backend body=%q want %q", next.body, fields.Encode())
	}
}

func TestAppsecUnknownAction_withoutBodyBans(t *testing.T) {
	b, next, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, `{"action":"tarpit","http_status":403}`), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if next.called {
		t.Fatal("a bodyless AppSec action must not reach the backend")
	}
	if rw.Code != http.StatusForbidden || rw.Body.String() != "banned reason=APPSEC" {
		t.Fatalf("want ban page, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:appsec-action-empty" {
		t.Fatalf("X-Remediation=%q want ban:appsec-action-empty", got)
	}
	if got := lapiClient.TestDroppedCount("appsec", "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped appsec/ban=%d want 1", got)
	}
}

func TestAppsecUnknownAction_withBodyIsRelayed(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, `{"action":"tarpit","http_status":403,"user_body_content":"<html>slow down</html>"}`), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if next.called {
		t.Fatal("a relayed AppSec action must not reach the backend")
	}
	if rw.Code != http.StatusForbidden || rw.Body.String() != "<html>slow down</html>" {
		t.Fatalf("want the relayed body, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "tarpit:appsec" {
		t.Fatalf("X-Remediation=%q want tarpit:appsec", got)
	}
}

func TestAppsecCaptchaVerdict_markerPostWithUnusableCaptchaReachesOrigin(t *testing.T) {
	tests := []struct {
		name string
		bind func(b *Bouncer)
	}{
		{name: "subscribed but unpublished", bind: func(b *Bouncer) {
			bindTestCaptcha(b, nil)
			b.captchaLeg.subscribed = true
		}},
		{name: "subscribed but not Valid", bind: func(b *Bouncer) {
			bindTestCaptcha(b, &captcha.Client{})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), nil)
			tt.bind(b)

			fields := url.Values{}
			fields.Set("crowdsec_captcha_challenge", "v1")
			rw := httptest.NewRecorder()
			continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

			if !next.called {
				t.Fatalf("without a usable captcha the POST must reach the backend, got %d %q", rw.Code, rw.Body.String())
			}
			if next.body != fields.Encode() {
				t.Fatalf("backend body=%q want %q", next.body, fields.Encode())
			}
			if got := rw.Header().Get("X-Remediation"); got != "" {
				t.Fatalf("no remediation expected, got X-Remediation=%q", got)
			}
		})
	}
}

// TestLapiCaptchaDowngrade_keepsLapiBanReason guards the reason order handleRemediationServeHTTP passes to the captcha gate.
func TestLapiCaptchaDowngrade_keepsLapiBanReason(t *testing.T) {
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	if !b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), "captcha", "crowdsec") {
		t.Fatal("a downgrade ban must write the response")
	}

	if next.called {
		t.Fatal("a downgrade ban must not reach the backend")
	}
	if rw.Body.String() != "banned reason=LAPI" {
		t.Fatalf("want ban page with reason LAPI, got %q", rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:captcha-downgrade" {
		t.Fatalf("X-Remediation=%q want ban:captcha-downgrade", got)
	}
}

// TestAppsecCaptchaVerdict_markerPostOnChallengePathNeverReachesOrigin proves the
// challenge-prefix 404 still applies after the captcha-form gate declined to write.
func TestAppsecCaptchaVerdict_markerPostOnChallengePathNeverReachesOrigin(t *testing.T) {
	const challengeAsset = "/crowdsec-internal/challenge/fast.js"
	cases := map[string]*captcha.Client{
		"no router captcha":          nil,
		"gate passes a widget asset": testCaptchaClient(t, challengeAsset, "", "", nil),
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), client)
			fields := url.Values{}
			fields.Set("crowdsec_captcha_challenge", "v1")
			req := httptest.NewRequest(http.MethodPost, "http://example.com"+challengeAsset, strings.NewReader(fields.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rw := httptest.NewRecorder()
			continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

			if next.called {
				t.Fatal("a challenge-prefix path must not reach the backend")
			}
			if rw.Code != http.StatusNotFound {
				t.Fatalf("status=%d want 404", rw.Code)
			}
		})
	}
}

// TestAppsecChallengePath_solvedCaptchaRuleNeverReachesOrigin proves a captcha action rule
// whose gate is already solved does not reopen the challenge prefix to origin.
func TestAppsecChallengePath_solvedCaptchaRuleNeverReachesOrigin(t *testing.T) {
	client := testSiteverifyCaptchaClient(t)
	cookieValue := solveTestGateCookie(t, client)
	b, next, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), client)
	b.actionRules = mustPathAction(t, "site", "^/", httprule.ActionCaptcha)

	for _, target := range []string{"/crowdsec-internal/challenge/custom.js", "/protected"} {
		next.called = false
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+target, nil)
		req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
		rw := httptest.NewRecorder()
		continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

		onChallengePath := strings.HasPrefix(target, "/crowdsec-internal/challenge/")
		if next.called == onChallengePath {
			t.Fatalf("%s: next called=%v, want %v", target, next.called, !onChallengePath)
		}
		if onChallengePath && rw.Code != http.StatusNotFound {
			t.Fatalf("%s: status=%d want 404", target, rw.Code)
		}
	}
}
