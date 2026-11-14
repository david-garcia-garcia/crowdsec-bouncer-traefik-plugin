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

// appsecVerdictOrigin records what reached the backend.
type appsecVerdictOrigin struct {
	called bool
	body   string
}

// testAppsecVerdictBouncer wires AppSec (answering with verdict), an optional captcha client, and a metrics-counting LAPI client.
func testAppsecVerdictBouncer(t *testing.T, verdict http.HandlerFunc, captchaClient *captcha.Client) (*Bouncer, *appsecVerdictOrigin, *lapi.Client) {
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
	origin := &appsecVerdictOrigin{}
	b := &Bouncer{
		next: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			origin.called = true
			if r.Body != nil {
				body, _ := io.ReadAll(r.Body)
				origin.body = string(body)
			}
		}),
		log:                     logger.New("ERROR", ""),
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		banTemplate:             banTemplate,
		banTemplateContentType:  "text/html; charset=utf-8",
	}
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	bindTestCaptcha(b, captchaClient)
	lapiClient, _ := lapi.NewTestClient(b.log)
	lapi.AttachTestMetricsReporter(lapiClient)
	bindTestLAPI(b, lapiClient)
	return b, origin, lapiClient
}

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
	for _, cookie := range rw.Result().Cookies() {
		if cookie.Name == "crowdsec_captcha_gate" && cookie.Value != "" {
			return true
		}
	}
	return false
}

func TestAppsecCaptchaVerdict_servesRouterCaptcha(t *testing.T) {
	b, origin, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), testCaptchaClient(t, "/fast.js", "", "", nil))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("an unsolved AppSec captcha must not reach origin")
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
	b, origin, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), client)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if !origin.called {
		t.Fatalf("a solved visitor must reach origin, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "" {
		t.Fatalf("pass must not set X-Remediation, got %q", got)
	}
	if got := lapiClient.TestDroppedCount("appsec", "ipv4", "captcha"); got != 0 {
		t.Fatalf("dropped appsec/captcha=%d want 0", got)
	}
}

func TestAppsecCaptchaVerdict_routerWithoutCaptchaBans(t *testing.T) {
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("AppSec captcha without a router captcha must not reach origin")
	}
	if rw.Code != http.StatusForbidden || rw.Body.String() != "banned reason=APPSEC" {
		t.Fatalf("want ban page with reason APPSEC, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:captcha-downgrade" {
		t.Fatalf("X-Remediation=%q want ban:captcha-downgrade", got)
	}
}

func TestAppsecCaptchaVerdict_captchaRuleServesItsOwnGate(t *testing.T) {
	b, origin, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), testCaptchaClient(t, "/fast.js", "", "", nil))
	b.actionRules = mustPathAction(t, "login", "^/protected$", httprule.ActionCaptcha)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("captcha rule plus AppSec captcha must not reach origin")
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
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, appsecCaptchaEnvelope), testCaptchaClient(t, "/fast.js", "", "", nil))

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("HEAD under an AppSec captcha must not reach origin")
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:appsec" {
		t.Fatalf("X-Remediation=%q want captcha:appsec", got)
	}
}

func TestAppsecCaptchaVerdict_markerPostAllowedByAppsecIsValidated(t *testing.T) {
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	fields.Set("dummy-captcha-response", "ok")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("the captcha solve POST must not reach origin")
	}
	if rw.Code != http.StatusFound || !hasGateCookie(rw) {
		t.Fatalf("want 302 with a gate cookie, got %d cookies=%v", rw.Code, rw.Result().Cookies())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:solved" {
		t.Fatalf("X-Remediation=%q want captcha:solved", got)
	}
}

func TestAppsecCaptchaVerdict_markerPostWithoutTokenServesChallenge(t *testing.T) {
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("a challenge-marker POST must not reach origin when captcha is usable")
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
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), client)

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, cookieValue), testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("a leftover challenge form must not reach origin")
	}
	if rw.Code != http.StatusFound || hasGateCookie(rw) {
		t.Fatalf("want 302 without a new gate cookie, got %d cookies=%v", rw.Code, rw.Result().Cookies())
	}
}

func TestAppsecCaptchaVerdict_ordinaryPostAllowedReachesOriginIntact(t *testing.T) {
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), testSiteverifyCaptchaClient(t))

	fields := url.Values{}
	fields.Set("username", "alice")
	fields.Set("dummy-captcha-response", "app-widget-token")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if !origin.called {
		t.Fatalf("an application POST must reach origin, got %d %q", rw.Code, rw.Body.String())
	}
	if origin.body != fields.Encode() {
		t.Fatalf("origin body=%q want %q", origin.body, fields.Encode())
	}
}

func TestAppsecCaptchaVerdict_markerPostWithoutRouterCaptchaReachesOrigin(t *testing.T) {
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusOK, `{"action":"allow"}`), nil)

	fields := url.Values{}
	fields.Set("crowdsec_captcha_challenge", "v1")
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(captchaFormPost(t, fields, ""), testCaptchaRemoteIP))

	if !origin.called {
		t.Fatalf("without a router captcha the POST must reach origin, got %d %q", rw.Code, rw.Body.String())
	}
	if origin.body != fields.Encode() {
		t.Fatalf("origin body=%q want %q", origin.body, fields.Encode())
	}
}

func TestAppsecUnknownAction_withoutBodyBans(t *testing.T) {
	b, origin, lapiClient := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, `{"action":"tarpit","http_status":403}`), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("a bodyless AppSec action must not reach origin")
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
	b, origin, _ := testAppsecVerdictBouncer(t, appsecAnswers(http.StatusForbidden, `{"action":"tarpit","http_status":403,"user_body_content":"<html>slow down</html>"}`), nil)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	continueAfterLAPIForTest(b, rw, testClientRequest(req, testCaptchaRemoteIP))

	if origin.called {
		t.Fatal("a relayed AppSec action must not reach origin")
	}
	if rw.Code != http.StatusForbidden || rw.Body.String() != "<html>slow down</html>" {
		t.Fatalf("want the relayed body, got %d %q", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "tarpit:appsec" {
		t.Fatalf("X-Remediation=%q want tarpit:appsec", got)
	}
}
