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

const eucaptchaChallengePage = "JS={{ .FrontendJS }} CLASS={{ .FrontendKey }} DRAW={{ .DrawCheckbox }}"

// eucaptchaTrip records the verify request and returns a canned body.
type eucaptchaTrip struct {
	status   int
	body     string
	lastReq  *http.Request
	lastBody []byte
	calls    int
}

func (t *eucaptchaTrip) RoundTrip(req *http.Request) (*http.Response, error) {
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

func newTestEucaptchaClient(t *testing.T, httpClient *http.Client) *Client {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte(eucaptchaChallengePage), 0o600); err != nil {
		t.Fatal(err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client := &Client{}
	err := client.New(
		slog.Default(),
		httpClient,
		configuration.EucaptchaProvider,
		"", "", "", "", "", "",
		"site-key",
		"site-secret",
		"gate-secret",
		true,
		templatePath,
		3600,
		Enterprise{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func eucaptchaSolverPOST() *http.Request {
	form := url.Values{}
	form.Set(eucaptchaResponseField, "ok-token")
	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func Test_New_eucaptchaWidgetAndVerifier(t *testing.T) {
	client := newTestEucaptchaClient(t, nil)
	if client.widget.ScriptURL != eucaptchaScriptURL {
		t.Fatalf("script %q", client.widget.ScriptURL)
	}
	if client.widget.Class != eucaptchaClass || client.widget.TokenField != eucaptchaResponseField {
		t.Fatalf("class/field %+v", client.widget)
	}
	if !client.widget.RetryAfterReject {
		t.Fatal("eucaptcha must retry after reject")
	}
	if _, ok := client.verifier.(*eucaptchaVerifier); !ok {
		t.Fatalf("verifier type %T, want *eucaptchaVerifier", client.verifier)
	}
	if _, inSiteverify := siteverifyBuiltins[configuration.EucaptchaProvider]; inSiteverify {
		t.Fatal("eucaptcha must not be a siteverify builtin")
	}
}

func Test_Validate_eucaptchaURLAndJSONFields(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusOK, body: `{"success": true, "train": false}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	req := eucaptchaSolverPOST()
	req.Header.Set("User-Agent", "TestAgent/1.0")
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Real-Ip", "198.51.100.2")
	req.Header.Set("X-Client-Ip", "198.51.100.3")
	outcome, err := client.Validate(req, "203.0.113.9")
	if err != nil || outcome != Pass {
		t.Fatalf("want Pass, got outcome=%v err=%v", outcome, err)
	}
	if trip.lastReq == nil {
		t.Fatal("verify was not called")
	}
	if got := trip.lastReq.URL.String(); got != "https://api.eu-captcha.eu/v1/verify" {
		t.Fatalf("URL %q", got)
	}
	if trip.lastReq.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type=%q", trip.lastReq.Header.Get("Content-Type"))
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(trip.lastBody, &raw); err != nil {
		t.Fatalf("body %s: %v", trip.lastBody, err)
	}
	wantKeys := []string{"sitekey", "secret", "client_ip", "client_token", "client_user_agent"}
	if len(raw) != len(wantKeys) {
		t.Fatalf("JSON keys %v", raw)
	}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing JSON key %q in %s", key, trip.lastBody)
		}
	}
	if string(raw["sitekey"]) != `"site-key"` || string(raw["secret"]) != `"site-secret"` {
		t.Fatalf("sitekey/secret %s", trip.lastBody)
	}
	if string(raw["client_token"]) != `"ok-token"` {
		t.Fatalf("client_token=%s", raw["client_token"])
	}
	if string(raw["client_ip"]) != `"203.0.113.9"` {
		t.Fatalf("client_ip=%s", raw["client_ip"])
	}
	if string(raw["client_user_agent"]) != `"TestAgent/1.0"` {
		t.Fatalf("client_user_agent=%s", raw["client_user_agent"])
	}
}

func Test_Validate_eucaptchaEmptyRemoteIPDoesNotPost(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusOK, body: `{"success": true, "train": false}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	outcome, err := client.Validate(eucaptchaSolverPOST(), "")
	if err != nil || outcome != Reject {
		t.Fatalf("got outcome=%v err=%v", outcome, err)
	}
	if trip.calls != 0 {
		t.Fatal("empty remoteIP must not POST verify")
	}
}

func Test_Validate_eucaptchaEmptyUserAgentIsSent(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusOK, body: `{"success": true, "train": false}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	req := eucaptchaSolverPOST()
	outcome, err := client.Validate(req, "203.0.113.9")
	if err != nil || outcome != Pass {
		t.Fatalf("got outcome=%v err=%v", outcome, err)
	}
	var payload eucaptchaVerifyRequest
	if err := json.Unmarshal(trip.lastBody, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ClientUserAgent != "" {
		t.Fatalf("empty User-Agent must still POST as empty string, got %q", payload.ClientUserAgent)
	}
	if trip.calls != 1 {
		t.Fatalf("empty User-Agent must still POST, calls=%d", trip.calls)
	}
}

func Test_Validate_eucaptchaSuccessTrainMatrix(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    Outcome
		wantErr bool
	}{
		{name: "success true train false passes", body: `{"success": true, "train": false}`, want: Pass},
		{name: "success true train null passes", body: `{"success": true, "train": null}`, want: Pass},
		{name: "success true omitted train passes", body: `{"success": true}`, want: Pass},
		{name: "train true rejects", body: `{"success": true, "train": true}`, want: Reject},
		{name: "success false rejects", body: `{"success": false, "train": false}`, want: Reject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trip := &eucaptchaTrip{status: http.StatusOK, body: tt.body}
			client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
			outcome, err := client.Validate(eucaptchaSolverPOST(), "203.0.113.9")
			if (err != nil) != tt.wantErr || outcome != tt.want {
				t.Fatalf("got outcome=%v err=%v", outcome, err)
			}
		})
	}
}

func Test_Validate_eucaptchaErrorVersusReject(t *testing.T) {
	t.Run("non-2xx is error", func(t *testing.T) {
		trip := &eucaptchaTrip{status: http.StatusBadRequest, body: `{"error":"missing_field"}`}
		client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
		outcome, err := client.Validate(eucaptchaSolverPOST(), "203.0.113.9")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("empty body is error", func(t *testing.T) {
		trip := &eucaptchaTrip{status: http.StatusOK, body: ""}
		client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
		outcome, err := client.Validate(eucaptchaSolverPOST(), "203.0.113.9")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("non-JSON body is error", func(t *testing.T) {
		trip := &eucaptchaTrip{status: http.StatusOK, body: "not-json"}
		client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
		outcome, err := client.Validate(eucaptchaSolverPOST(), "203.0.113.9")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
	t.Run("body larger than 64KiB is error", func(t *testing.T) {
		oversized := `{"success":true,"train":false,"pad":"` + strings.Repeat("x", 64<<10) + `"}`
		trip := &eucaptchaTrip{status: http.StatusOK, body: oversized}
		client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
		outcome, err := client.Validate(eucaptchaSolverPOST(), "203.0.113.9")
		if err == nil || outcome != None {
			t.Fatalf("got outcome=%v err=%v", outcome, err)
		}
	})
}

func Test_Validate_eucaptchaEmptyTokenDoesNotPost(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusOK, body: `{"success": true, "train": false}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	emptyPOST := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(""))
	emptyPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	outcome, err := client.Validate(emptyPOST, "203.0.113.9")
	if err != nil || outcome != None {
		t.Fatalf("got outcome=%v err=%v", outcome, err)
	}
	if trip.calls != 0 {
		t.Fatal("empty token must not POST verify")
	}
}

func Test_ServeHTTP_eucaptchaPassMintsGateAnd302(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusOK, body: `{"success": true, "train": false}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, eucaptchaSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusFound {
		t.Fatalf("pass want 302, got %d", rw.Code)
	}
	cookie := rw.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("pass missing gate cookie: %s", cookie)
	}
}

func Test_ServeHTTP_eucaptchaTrainTrueDoesNotMint(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusOK, body: `{"success": true, "train": true}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, eucaptchaSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("train true want 200, got %d", rw.Code)
	}
	if strings.Contains(rw.Result().Header.Get("Set-Cookie"), gateCookieName+"=") {
		t.Fatal("train true must not mint the gate")
	}
}

func Test_ServeHTTP_eucaptchaErrorRendersChallenge(t *testing.T) {
	trip := &eucaptchaTrip{status: http.StatusInternalServerError, body: `{"error":"server"}`}
	client := newTestEucaptchaClient(t, &http.Client{Transport: trip})
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, eucaptchaSolverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("error want 200, got %d", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), eucaptchaScriptURL) {
		t.Fatalf("error must render with boot: %s", rw.Body.String())
	}
	if strings.Contains(rw.Result().Header.Get("Set-Cookie"), gateCookieName+"=") {
		t.Fatal("error must not mint the gate")
	}
}

func Test_ServeHTTP_eucaptchaStockTemplate(t *testing.T) {
	client := &Client{}
	err := client.New(
		slog.Default(),
		http.DefaultClient,
		configuration.EucaptchaProvider,
		"", "", "", "", "", "",
		"site-key",
		"site-secret",
		"gate-secret",
		true,
		stockCaptchaTemplatePath(t),
		3600,
		Enterprise{},
	)
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/foo", nil), "192.0.2.10", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("GET want 200, got %d", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, eucaptchaScriptURL) {
		t.Fatalf("stock page must load verify.js: %s", body)
	}
	if !strings.Contains(body, `class="eu-captcha"`) {
		t.Fatalf("stock page must draw eu-captcha: %s", body)
	}
	if strings.Contains(body, `name="eu-captcha-response"`) {
		t.Fatal("stock page must not hardcode eu-captcha-response")
	}
}
