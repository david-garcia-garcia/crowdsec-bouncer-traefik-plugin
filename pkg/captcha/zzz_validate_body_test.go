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
		"",
		templatePath,
		3600,
	)
	if err != nil {
		t.Fatal(err)
	}
	if provider != configuration.CustomProvider {
		info := *client.infoProvider
		info.response = "dummy-captcha-response"
		info.validate = validateURL
		client.infoProvider = &info
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
	ok, err := client.Validate(solverPOST(), "")
	if err != nil || !ok {
		t.Fatalf("Validate json want success, got ok=%v err=%v", ok, err)
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
			ok, err := client.Validate(solverPOST(), "")
			if err != nil || !ok {
				t.Fatalf("Validate form want success, got ok=%v err=%v", ok, err)
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
	ok, err := client.Validate(solverPOST(), "")
	if err != nil || !ok {
		t.Fatalf("built-in Validate want success, got ok=%v err=%v", ok, err)
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
	client.ServeHTTP(rw, solverPOST(), "192.0.2.10")
	if rw.Code != http.StatusFound {
		t.Fatalf("json success want 302, got %d", rw.Code)
	}
	cookie := rw.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("json success missing gate cookie: %s", cookie)
	}
}
