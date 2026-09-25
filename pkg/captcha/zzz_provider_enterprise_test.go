package captcha

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const enterpriseChallengePage = "BOOT={{ .BootScript }} JS={{ .FrontendJS }} CLASS={{ .FrontendKey }} DRAW={{ .DrawCheckbox }} ACTION={{ .Action }}"

// enterpriseTrip records the reCAPTCHA Enterprise assessments request and returns a canned body.
type enterpriseTrip struct {
	status   int
	body     string
	lastReq  *http.Request
	lastBody []byte
	calls    int
}

func (t *enterpriseTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.lastReq = req
	if req.Body != nil {
		t.lastBody, _ = io.ReadAll(req.Body)
	}
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: t.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Request:    req,
	}, nil
}

func newTestEnterpriseClient(t *testing.T, keyType string, enterprise Enterprise, httpClient *http.Client) *Client {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte(enterpriseChallengePage), 0o600); err != nil {
		t.Fatal(err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	enterprise.KeyType = keyType
	if enterprise.ProjectID == "" {
		enterprise.ProjectID = "my-project"
	}
	if enterprise.APIKey == "" {
		enterprise.APIKey = "cloud-api-key"
	}
	client := &Client{}
	err := client.New(
		slog.Default(),
		httpClient,
		configuration.RecaptchaEnterpriseProvider,
		"", "", "", "", "", "",
		"site-key",
		"",
		"gate-secret",
		true,
		templatePath,
		3600,
		enterprise,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func enterpriseSolverPOST() *http.Request {
	form := url.Values{}
	form.Set("g-recaptcha-response", "ok-token")
	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func Test_New_enterpriseCheckboxAndScoreWidgets(t *testing.T) {
	checkbox := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, nil)
	if checkbox.widget.ScriptURL != enterpriseScriptURL {
		t.Fatalf("checkbox script %q", checkbox.widget.ScriptURL)
	}
	if checkbox.widget.Class != enterpriseCheckboxClass || checkbox.widget.TokenField != recaptchaResponseField {
		t.Fatalf("checkbox class/field %+v", checkbox.widget)
	}
	if !checkbox.widget.RetryAfterReject || checkbox.widget.BootScript != "" {
		t.Fatal("checkbox must retry and have no score boot")
	}

	score := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, nil)
	if score.widget.ScriptURL != enterpriseScriptURL+"?render=site-key" {
		t.Fatalf("score script %q", score.widget.ScriptURL)
	}
	if score.widget.Class != "" || score.widget.TokenField != recaptchaResponseField {
		t.Fatalf("score class/field %+v", score.widget)
	}
	if score.widget.RetryAfterReject {
		t.Fatal("score must not retry after reject")
	}
	if !strings.Contains(score.widget.BootScript, "window.grecaptcha") || !strings.Contains(score.widget.BootScript, "grecaptcha.enterprise.ready") || !strings.Contains(score.widget.BootScript, "execute") || !strings.Contains(score.widget.BootScript, ",2000)") {
		t.Fatalf("score boot %q", score.widget.BootScript)
	}
}

func Test_Validate_enterpriseURLAndHeader(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
	outcome, err := client.Validate(enterpriseSolverPOST(), "")
	if err != nil || outcome != Pass {
		t.Fatalf("want Pass, got outcome=%v err=%v", outcome, err)
	}
	if trip.lastReq == nil {
		t.Fatal("enterprise assessments was not called")
	}
	if got := trip.lastReq.URL.String(); got != "https://recaptchaenterprise.googleapis.com/v1/projects/my-project/assessments" {
		t.Fatalf("URL %q", got)
	}
	if trip.lastReq.URL.Query().Get("key") != "" || trip.lastReq.URL.RawQuery != "" {
		t.Fatalf("API key must not be in the query string: %q", trip.lastReq.URL.RawQuery)
	}
	if trip.lastReq.Header.Get("X-Goog-Api-Key") != "cloud-api-key" {
		t.Fatalf("X-Goog-Api-Key=%q", trip.lastReq.Header.Get("X-Goog-Api-Key"))
	}
}

func Test_Validate_enterpriseEventFields(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
	if _, err := client.Validate(enterpriseSolverPOST(), "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	var payload enterpriseAssessmentRequest
	if err := json.Unmarshal(trip.lastBody, &payload); err != nil {
		t.Fatalf("body %s: %v", trip.lastBody, err)
	}
	if payload.Event.Token != "ok-token" || payload.Event.SiteKey != "site-key" {
		t.Fatalf("event %+v", payload.Event)
	}
	if payload.Event.UserIPAddress != "203.0.113.9" {
		t.Fatalf("userIpAddress=%q", payload.Event.UserIPAddress)
	}

	actionTrip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"login"},"riskAnalysis":{"score":0.9}}`}
	score := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: actionTrip})
	if _, err := score.Validate(enterpriseSolverPOST(), ""); err != nil {
		t.Fatal(err)
	}
	var scorePayload enterpriseAssessmentRequest
	if err := json.Unmarshal(actionTrip.lastBody, &scorePayload); err != nil {
		t.Fatal(err)
	}
	if scorePayload.Event.ExpectedAction != "login" {
		t.Fatalf("expectedAction=%q", scorePayload.Event.ExpectedAction)
	}
}

func Test_Validate_enterpriseOmitsEmptyRemoteIPAndAction(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
	req := enterpriseSolverPOST()
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Real-Ip", "198.51.100.2")
	if _, err := client.Validate(req, ""); err != nil {
		t.Fatal(err)
	}
	body := string(trip.lastBody)
	if strings.Contains(body, "userIpAddress") {
		t.Fatalf("empty remoteIP must omit userIpAddress: %s", body)
	}
	if strings.Contains(body, "expectedAction") {
		t.Fatalf("empty action must omit expectedAction: %s", body)
	}
}

func Test_Validate_enterprisePassOrder(t *testing.T) {
	t.Run("valid checkbox passes", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Pass {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("action case-insensitive", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"login"},"riskAnalysis":{"score":0.9}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "LOGIN", MinScore: "0.5"}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Pass {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("different action rejects", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"checkout"},"riskAnalysis":{"score":0.9}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Reject {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("score below minimum rejects", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"login"},"riskAnalysis":{"score":0.3}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Reject {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("score at minimum passes", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"login"},"riskAnalysis":{"score":0.5}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Pass {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("missing riskAnalysis with minScore rejects", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"login"}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Reject {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
}

func Test_Validate_enterpriseErrorVersusReject(t *testing.T) {
	t.Run("valid false is reject", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":false}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err != nil || outcome != Reject {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("non-2xx is error", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusForbidden, body: `{"error":{"message":"denied"}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("empty body is error", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: ""}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("non-JSON body is error", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: "not-json"}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("error envelope without tokenProperties is error", func(t *testing.T) {
		trip := &enterpriseTrip{status: http.StatusOK, body: `{"error":{"code":400,"message":"denied"}}`}
		client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
		outcome, err := client.Validate(enterpriseSolverPOST(), "")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
}

func Test_Validate_emptyTokenDoesNotPostAssessments(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
	emptyPOST := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(""))
	emptyPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	outcome, err := client.Validate(emptyPOST, "192.0.2.10")
	if err != nil || outcome != None {
		t.Fatalf("got outcome=%v err=%v", outcome, err)
	}
	if trip.calls != 0 {
		t.Fatal("empty token must not POST enterprise assessments")
	}
}

func Test_ServeHTTP_enterprisePassMintsGateAnd302(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, enterpriseSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusFound {
		t.Fatalf("pass want 302, got %d", rw.Code)
	}
	cookie := rw.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("pass missing gate cookie: %s", cookie)
	}
}

func Test_ServeHTTP_scoreRejectOmitsBoot(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":true,"action":"login"},"riskAnalysis":{"score":0.1}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, enterpriseSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("score reject want 200, got %d", rw.Code)
	}
	body := rw.Body.String()
	if strings.Contains(body, "grecaptcha.enterprise.ready") || strings.Contains(body, "grecaptcha.enterprise.execute") {
		t.Fatalf("score reject must omit boot: %s", body)
	}
	if strings.Contains(rw.Result().Header.Get("Set-Cookie"), gateCookieName+"=") {
		t.Fatal("score reject must not mint the gate")
	}
}

func Test_ServeHTTP_checkboxRejectKeepsBoot(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusOK, body: `{"tokenProperties":{"valid":false}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{}, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, enterpriseSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("checkbox reject want 200, got %d", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, enterpriseScriptURL) || strings.Contains(body, "render=") {
		t.Fatalf("checkbox reject must keep enterprise.js without render=: %s", body)
	}
	if !strings.Contains(body, "CLASS="+enterpriseCheckboxClass) || !strings.Contains(body, "DRAW=1") {
		t.Fatalf("checkbox reject must draw g-recaptcha: %s", body)
	}
	if strings.Contains(rw.Result().Header.Get("Set-Cookie"), gateCookieName+"=") {
		t.Fatal("checkbox reject must not mint the gate")
	}
}

func Test_ServeHTTP_enterpriseErrorRendersWithBoot(t *testing.T) {
	trip := &enterpriseTrip{status: http.StatusInternalServerError, body: `{"error":{"message":"denied"}}`}
	client := newTestEnterpriseClient(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"}, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, enterpriseSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("error want 200, got %d", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "grecaptcha.enterprise.ready") {
		t.Fatalf("error must render with boot: %s", rw.Body.String())
	}
	if strings.Contains(rw.Result().Header.Get("Set-Cookie"), gateCookieName+"=") {
		t.Fatal("error must not mint the gate")
	}
}

func stockCaptchaTemplatePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "captcha.html")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestEnterpriseClientStock(t *testing.T, keyType string, enterprise Enterprise) *Client {
	t.Helper()
	enterprise.KeyType = keyType
	if enterprise.ProjectID == "" {
		enterprise.ProjectID = "my-project"
	}
	if enterprise.APIKey == "" {
		enterprise.APIKey = "cloud-api-key"
	}
	client := &Client{}
	err := client.New(
		slog.Default(),
		http.DefaultClient,
		configuration.RecaptchaEnterpriseProvider,
		"", "", "", "", "", "",
		"site-key",
		"",
		"gate-secret",
		true,
		stockCaptchaTemplatePath(t),
		3600,
		enterprise,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func Test_ServeHTTP_stockTemplateCheckboxAndScore(t *testing.T) {
	checkbox := newTestEnterpriseClientStock(t, configuration.CaptchaEnterpriseKeyTypeCheckbox, Enterprise{})
	checkboxRW := httptest.NewRecorder()
	checkbox.ServeHTTP(checkboxRW, httptest.NewRequest(http.MethodGet, "/foo", nil), "192.0.2.10", "")
	if checkboxRW.Code != http.StatusOK {
		t.Fatalf("checkbox GET want 200, got %d", checkboxRW.Code)
	}
	checkboxBody := checkboxRW.Body.String()
	if !strings.Contains(checkboxBody, "<em>example.com</em> needs to review the security of your connection") {
		t.Fatalf("checkbox stock page must name the request host: %s", checkboxBody)
	}
	if !strings.Contains(checkboxBody, `class="g-recaptcha"`) || !strings.Contains(checkboxBody, `data-sitekey="site-key"`) {
		t.Fatalf("checkbox stock page must draw g-recaptcha: %s", checkboxBody)
	}
	if strings.Contains(checkboxBody, `type="hidden" name="g-recaptcha-response"`) {
		t.Fatal("checkbox stock page must not render the score hidden field")
	}

	score := newTestEnterpriseClientStock(t, configuration.CaptchaEnterpriseKeyTypeScore, Enterprise{Action: "login", MinScore: "0.5"})
	scoreRW := httptest.NewRecorder()
	score.ServeHTTP(scoreRW, httptest.NewRequest(http.MethodGet, "/foo", nil), "192.0.2.10", "")
	if scoreRW.Code != http.StatusOK {
		t.Fatalf("score GET want 200, got %d", scoreRW.Code)
	}
	scoreBody := scoreRW.Body.String()
	if !strings.Contains(scoreBody, `type="hidden" name="g-recaptcha-response"`) {
		t.Fatalf("score stock page must render the hidden field: %s", scoreBody)
	}
	if strings.Contains(scoreBody, `class="g-recaptcha"`) {
		t.Fatal("score stock page must not draw the checkbox")
	}
	if !strings.Contains(scoreBody, "grecaptcha.enterprise.ready") || !strings.Contains(scoreBody, "grecaptcha.enterprise.execute") {
		t.Fatalf("score stock page must include the boot script: %s", scoreBody)
	}
}
