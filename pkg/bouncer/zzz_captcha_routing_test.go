package bouncer

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testCaptchaClient(t *testing.T, jsURL, challengeURL, validateURL string, httpClient *http.Client) *captcha.Client {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("CAPTCHA_CHALLENGE_PAGE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if validateURL == "" {
		validateURL = "http://127.0.0.1/siteverify"
	}
	client := &captcha.Client{}
	err := client.New(
		logger.New("ERROR", ""),
		httpClient,
		configuration.CustomProvider,
		jsURL,
		challengeURL,
		"dummy-captcha",
		"dummy-captcha-response",
		validateURL,
		"",
		"site",
		"secret",
		"gate-secret",
		true,
		"X-Remediation",
		templatePath,
		3600,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testCaptchaRoutingBouncer(t *testing.T, client *captcha.Client) (*Bouncer, *bool) {
	t.Helper()
	originCalled := false
	return &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			originCalled = true
		}),
		captchaClient:           client,
		log:                     logger.New("ERROR", ""),
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		banTemplateContentType:  "text/html; charset=utf-8",
	}, &originCalled
}

// testCaptchaRemoteIP is the one client address these routing tests solve captcha for.
const testCaptchaRemoteIP = "192.0.2.10"

func solveTestGateCookie(t *testing.T, client *captcha.Client) string {
	t.Helper()
	form := url.Values{}
	form.Set("dummy-captcha-response", "ok")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, req, testCaptchaRemoteIP)
	if rw.Code != http.StatusFound {
		body, _ := io.ReadAll(rw.Result().Body)
		t.Fatalf("solve want 302, got %d %s", rw.Code, body)
	}
	for _, cookie := range rw.Result().Cookies() {
		if cookie.Name == "crowdsec_captcha_gate" {
			return cookie.Value
		}
	}
	t.Fatal("solve missing gate cookie")
	return ""
}

func TestHandleRemediationServeHTTP_solvedFormPostRedirects(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
	cookieValue := solveTestGateCookie(t, client)
	b, originCalled := testCaptchaRoutingBouncer(t, client)

	form := url.Values{}
	form.Set("dummy-captcha-response", "again")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")

	if rw.Code != http.StatusFound {
		t.Fatalf("Check-true form POST want 302, got %d", rw.Code)
	}
	if *originCalled {
		t.Fatal("origin must not receive the captcha-form POST")
	}
	if got := rw.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("Check-true form POST must not remint cookie, got %q", got)
	}
}

func TestHandleRemediationServeHTTP_ordinaryPostAfterSolveReachesOrigin(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
	cookieValue := solveTestGateCookie(t, client)
	b, originCalled := testCaptchaRoutingBouncer(t, client)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", strings.NewReader("comment=hi"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")

	if !*originCalled {
		t.Fatal("ordinary POST after solve must reach origin")
	}
	if rw.Code == http.StatusFound {
		t.Fatal("ordinary POST after solve must not 302")
	}
}

// TestHandleRemediationServeHTTP_overMaxPostAfterSolveReachesOriginIntact proves a large
// upload is not sacrificed to captcha-form detection: it reaches origin byte for byte even
// though it happens to contain the provider response field name.
func TestHandleRemediationServeHTTP_overMaxPostAfterSolveReachesOriginIntact(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
	cookieValue := solveTestGateCookie(t, client)

	var originBody string
	b := &Bouncer{
		next: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			originBody = string(raw)
		}),
		captchaClient:           client,
		log:                     logger.New("ERROR", ""),
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		banTemplateContentType:  "text/html; charset=utf-8",
	}

	payload := "dummy-captcha-response=token&blob=" + strings.Repeat("a", 64<<10)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")

	if rw.Code == http.StatusFound {
		t.Fatal("an upload over the captcha-form cap must not be redirected as a duplicate solve")
	}
	if originBody != payload {
		t.Fatalf("origin body want %d bytes unchanged, got %d", len(payload), len(originBody))
	}
}

func TestHandleRemediationServeHTTP_queryTokenGetIsNotFormPost(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
	cookieValue := solveTestGateCookie(t, client)
	b, originCalled := testCaptchaRoutingBouncer(t, client)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected?dummy-captcha-response=token", nil)
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	b.handleRemediationServeHTTP(httptest.NewRecorder(), testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if !*originCalled {
		t.Fatal("GET with query token after solve must reach origin")
	}
}

func TestHandleRemediationServeHTTP_customResourcePassthrough(t *testing.T) {
	client := testCaptchaClient(t, "https://widget.example/assets/fast.js", "https://widget.example/v0/challenge", "", nil)
	b, originCalled := testCaptchaRoutingBouncer(t, client)

	jsReq := httptest.NewRequest(http.MethodGet, "http://app.example/assets/fast.js", nil)
	b.handleRemediationServeHTTP(httptest.NewRecorder(), testClientRequest(jsReq, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if !*originCalled {
		t.Fatal("custom JS path under captcha must reach origin")
	}

	*originCalled = false
	challengeReq := httptest.NewRequest(http.MethodGet, "http://app.example/v0/challenge", nil)
	b.handleRemediationServeHTTP(httptest.NewRecorder(), testClientRequest(challengeReq, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if !*originCalled {
		t.Fatal("challenge path under captcha must reach origin")
	}

	*originCalled = false
	prefixReq := httptest.NewRequest(http.MethodGet, "http://app.example/assets", nil)
	prefixRW := httptest.NewRecorder()
	b.handleRemediationServeHTTP(prefixRW, testClientRequest(prefixReq, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if *originCalled {
		t.Fatal("prefix of the JS path must not pass")
	}
	if !strings.Contains(prefixRW.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("prefix miss must serve captcha HTML, got %q", prefixRW.Body.String())
	}

	*originCalled = false
	validateReq := httptest.NewRequest(http.MethodGet, "http://app.example/v0/siteverify", nil)
	b.handleRemediationServeHTTP(httptest.NewRecorder(), testClientRequest(validateReq, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if *originCalled {
		t.Fatal("ValidateURL path must not pass")
	}
}

func TestHandleRemediationServeHTTP_banDoesNotPassthroughCustomResource(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "/v0/challenge", "", nil)
	b, originCalled := testCaptchaRoutingBouncer(t, client)
	req := httptest.NewRequest(http.MethodGet, "http://app.example/fast.js", nil)
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.BannedValue, "cscli")
	if *originCalled {
		t.Fatal("ban must not passthrough a custom-resource path")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("ban want 403, got %d", rw.Code)
	}
}

// TestHandleRemediationServeHTTP_captchaHEADServesChallengePage pins the ratified rule that
// replaced the old TestCaptchaMethodBasedLogic expectation: a HEAD request from a client
// carrying a captcha remediation gets the captcha challenge page, not the ban page. Only a
// ban remediation makes HEAD a ban.
func TestHandleRemediationServeHTTP_captchaHEADServesChallengePage(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, originCalled := testCaptchaRoutingBouncer(t, client)

	headReq := httptest.NewRequest(http.MethodHead, "http://example.com/protected", nil)
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(headReq, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if *originCalled {
		t.Fatal("unsolved captcha HEAD must not reach origin")
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("captcha HEAD want challenge 200, got %d", rw.Code)
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha" {
		t.Fatalf("captcha HEAD want captcha header, got %q", got)
	}
	if got := rw.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("captcha HEAD want the captcha template content type, got %q", got)
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("captcha HEAD want the challenge page, got %q", rw.Body.String())
	}

	banRW := httptest.NewRecorder()
	b.handleRemediationServeHTTP(banRW, testClientRequest(httptest.NewRequest(http.MethodHead, "http://example.com/protected", nil), testCaptchaRemoteIP), decisionscope.BannedValue, "cscli")
	if banRW.Code != http.StatusForbidden {
		t.Fatalf("ban HEAD want 403, got %d", banRW.Code)
	}
	if got := banRW.Header().Get("X-Remediation"); got != "ban" {
		t.Fatalf("ban HEAD want ban header, got %q", got)
	}
}

func TestHandleRemediationServeHTTP_customResourceHEADReachesOrigin(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, originCalled := testCaptchaRoutingBouncer(t, client)
	req := httptest.NewRequest(http.MethodHead, "http://app.example/fast.js", nil)
	b.handleRemediationServeHTTP(httptest.NewRecorder(), testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if !*originCalled {
		t.Fatal("custom-resource HEAD under captcha must reach origin")
	}
}

func TestHandleRemediationServeHTTP_staleCacheGraceDoesNotPass(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, originCalled := testCaptchaRoutingBouncer(t, client)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	if *originCalled {
		t.Fatal("no gate cookie must not be treated as past-captcha")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want captcha challenge, got %q", rw.Body.String())
	}
}
