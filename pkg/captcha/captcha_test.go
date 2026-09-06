package captcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newTestCaptcha(t *testing.T, provider, instanceURL, siteKey, verifyKey string, httpClient *http.Client) *Client {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "captcha.html")
	templateBody := `{{ .CapApiEndpoint }}|{{ .FrontendJS }}|{{ .FrontendKey }}|{{ .SiteKey }}`
	if err := os.WriteFile(path, []byte(templateBody), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &Client{}
	err := client.New(
		logger.New("ERROR", ""),
		&cache.Client{},
		httpClient,
		provider,
		"", "", "", "",
		siteKey, verifyKey, instanceURL,
		"",
		path,
		60,
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestValidateTrycapJSONSuccess(t *testing.T) {
	var gotContentType, gotBody, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]bool{"success": true})
	}))
	defer server.Close()

	client := newTestCaptcha(t, configuration.TrycapProvider, server.URL, "sitekey", "trycap-verify", server.Client())
	req := httptest.NewRequest(http.MethodPost, "http://bouncer.example/captcha", strings.NewReader("cap-token=tok123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ok, err := client.Validate(req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected success")
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if gotPath != "/sitekey/siteverify" {
		t.Fatalf("path = %q", gotPath)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["secret"] != "trycap-verify" || payload["response"] != "tok123" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestValidateTrycapMissingTokenSkipsSiteverify(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()

	client := newTestCaptcha(t, configuration.TrycapProvider, server.URL, "sitekey", "trycap-verify", server.Client())
	req := httptest.NewRequest(http.MethodPost, "http://bouncer.example/captcha", strings.NewReader("other=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ok, err := client.Validate(req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected not valid")
	}
	if called {
		t.Fatal("siteverify must not be called without cap-token")
	}
}

func TestValidateHcaptchaStillPostForm(t *testing.T) {
	var gotContentType, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]bool{"success": true})
	}))
	defer server.Close()

	client := newTestCaptcha(t, configuration.HcaptchaProvider, "", "site", "hcaptcha-verify", server.Client())
	client.infoProvider.validate = server.URL
	form := url.Values{}
	form.Set("h-captcha-response", "tok")
	req := httptest.NewRequest(http.MethodPost, "http://bouncer.example/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ok, err := client.Validate(req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected success")
	}
	if !strings.Contains(gotContentType, "application/x-www-form-urlencoded") {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("secret") != "hcaptcha-verify" || values.Get("response") != "tok" {
		t.Fatalf("form = %q", gotBody)
	}
}

func TestServeHTTPTrycapRendersCapWidget(t *testing.T) {
	client := newTestCaptcha(t, configuration.TrycapProvider, "https://cap.example.com", "abc", "trycap-verify", http.DefaultClient)
	req := httptest.NewRequest(http.MethodGet, "http://bouncer.example/foo", nil)
	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, req, "1.2.3.4")
	body := rw.Body.String()
	if !strings.Contains(body, "https://cap.example.com/abc/") {
		t.Fatalf("body = %q", body)
	}
	if !strings.Contains(body, trycapWidgetJS) {
		t.Fatalf("missing widget JS in %q", body)
	}
}
