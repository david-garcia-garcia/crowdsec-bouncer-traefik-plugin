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

// newTestCaptchaClient builds a captcha Client for siteverify encoding tests.
func newTestCaptchaClient(t *testing.T, provider, validateBody, validateURL string, httpClient *http.Client) *Client {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("CAPTCHA_CHALLENGE_PAGE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	responseField := "dummy-captcha-response"
	if provider != configuration.CustomProvider {
		responseField = ""
	}
	client := &Client{}
	err := client.New(
		slog.Default(),
		httpClient,
		provider,
		"/dummy.js",
		"",
		"dummy-captcha",
		responseField,
		validateURL,
		validateBody,
		"site",
		"secret",
		"gate-secret",
		true,
		templatePath,
		3600,
		Enterprise{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if provider != configuration.CustomProvider {
		client.widget.TokenField = "dummy-captcha-response"
		if v, ok := client.verifier.(*siteverifyVerifier); ok {
			v.validateURL = validateURL
		}
	}
	return client
}

func solverPOST() *http.Request {
	form := url.Values{}
	form.Set("dummy-captcha-response", "ok-token")
	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func Test_Validate_customJSONPostsJSONSecretAndResponse(t *testing.T) {
	var gotType, gotBody string
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestCaptchaClient(t, configuration.CustomProvider, configuration.CaptchaCustomValidateBodyJSON, siteverify.URL+"/siteverify", siteverify.Client())
	outcome, err := client.Validate(solverPOST(), "")
	if err != nil || outcome != Pass {
		t.Fatalf("Validate json want success, got outcome=%v err=%v", outcome, err)
	}
	if !strings.HasPrefix(gotType, "application/json") {
		t.Fatalf("Content-Type want application/json, got %q", gotType)
	}
	var payload siteverifyRequest
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body is not JSON: %v %q", err, gotBody)
	}
	if payload.Secret != "secret" || payload.Response != "ok-token" {
		t.Fatalf("JSON want secret+response, got %+v", payload)
	}
	if strings.Contains(gotBody, "remoteip") {
		t.Fatalf("dest Validate has no address; body must omit remoteip: %s", gotBody)
	}
}

// Test_Validate_customJSONPostsRemoteIP proves custom+json marshals a non-empty
// Validate remoteIP as JSON "remoteip".
func Test_Validate_customJSONPostsRemoteIP(t *testing.T) {
	const passedRemoteIP = "203.0.113.9"
	var gotBody string
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestCaptchaClient(t, configuration.CustomProvider, configuration.CaptchaCustomValidateBodyJSON, siteverify.URL+"/siteverify", siteverify.Client())
	outcome, err := client.Validate(solverPOST(), passedRemoteIP)
	if err != nil || outcome != Pass {
		t.Fatalf("Validate json want success, got outcome=%v err=%v", outcome, err)
	}
	var payload siteverifyRequest
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body is not JSON: %v %q", err, gotBody)
	}
	if payload.RemoteIP != passedRemoteIP {
		t.Fatalf("JSON remoteip=%q, want %s", payload.RemoteIP, passedRemoteIP)
	}
}

func Test_Validate_customFormOrOmitStaysURLEncoded(t *testing.T) {
	for _, validateBody := range []string{"", configuration.CaptchaCustomValidateBodyForm} {
		t.Run("body="+validateBody, func(t *testing.T) {
			var gotType, gotBody string
			siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotType = r.Header.Get("Content-Type")
				raw, _ := io.ReadAll(r.Body)
				gotBody = string(raw)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"success":true}`))
			}))
			t.Cleanup(siteverify.Close)

			client := newTestCaptchaClient(t, configuration.CustomProvider, validateBody, siteverify.URL+"/siteverify", siteverify.Client())
			outcome, err := client.Validate(solverPOST(), "")
			if err != nil || outcome != Pass {
				t.Fatalf("Validate form want success, got outcome=%v err=%v", outcome, err)
			}
			if !strings.HasPrefix(gotType, "application/x-www-form-urlencoded") {
				t.Fatalf("Content-Type want urlencoded, got %q", gotType)
			}
			values, err := url.ParseQuery(gotBody)
			if err != nil {
				t.Fatal(err)
			}
			if values.Get("secret") != "secret" || values.Get("response") != "ok-token" {
				t.Fatalf("form want secret+response, got %q", gotBody)
			}
			if values.Has("remoteip") {
				t.Fatalf("dest Validate has no address; form must omit remoteip: %s", gotBody)
			}
		})
	}
}

func Test_Validate_builtinAlwaysURLEncoded(t *testing.T) {
	var gotType, gotBody string
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, configuration.CaptchaCustomValidateBodyJSON, siteverify.URL+"/siteverify", siteverify.Client())
	outcome, err := client.Validate(solverPOST(), "")
	if err != nil || outcome != Pass {
		t.Fatalf("built-in Validate want success, got outcome=%v err=%v", outcome, err)
	}
	if !strings.HasPrefix(gotType, "application/x-www-form-urlencoded") {
		t.Fatalf("built-in Content-Type want urlencoded, got %q", gotType)
	}
	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("secret") != "secret" || values.Get("response") != "ok-token" {
		t.Fatalf("built-in form want secret+response, got %q", gotBody)
	}
}

func Test_ServeHTTP_customJSONSuccessIssuesCookieAnd302(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestCaptchaClient(t, configuration.CustomProvider, configuration.CaptchaCustomValidateBodyJSON, siteverify.URL+"/siteverify", siteverify.Client())
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, solverPOST(), "192.0.2.10", "")
	if rw.Code != http.StatusFound {
		t.Fatalf("json success want 302, got %d", rw.Code)
	}
	cookie := rw.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("json success missing gate cookie: %s", cookie)
	}
}

func Test_Validate_successFalseIsReject(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestCaptchaClient(t, configuration.CustomProvider, "", siteverify.URL+"/siteverify", siteverify.Client())
	outcome, err := client.Validate(solverPOST(), "")
	if err != nil || outcome != Reject {
		t.Fatalf("success false want Reject, got outcome=%v err=%v", outcome, err)
	}
}

func Test_Validate_emptyTokenIsNoneAndDoesNotCallVerifier(t *testing.T) {
	called := false
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestCaptchaClient(t, configuration.CustomProvider, "", siteverify.URL+"/siteverify", siteverify.Client())
	emptyPOST := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(""))
	emptyPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	outcome, err := client.Validate(emptyPOST, "192.0.2.10")
	if err != nil || outcome != None {
		t.Fatalf("empty token want None, got outcome=%v err=%v", outcome, err)
	}
	if called {
		t.Fatal("empty token must not call the verifier")
	}
	getOutcome, getErr := client.Validate(httptest.NewRequest(http.MethodGet, "/foo", nil), "192.0.2.10")
	if getErr != nil || getOutcome != None {
		t.Fatalf("GET want None, got outcome=%v err=%v", getOutcome, getErr)
	}
	if called {
		t.Fatal("GET must not call the verifier")
	}
}
