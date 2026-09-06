package captcha

import (
	"errors"
	"io"
	"log/slog"
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

const testTemplate = `<html><body>{{ .SiteKey }} {{ .FrontendKey }}</body></html>`

func writeTestTemplate(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "captcha.html")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestClient(t *testing.T, provider, templatePath string, cacheClient *cache.Client, validateURL string) *Client {
	t.Helper()
	log := logger.New("INFO", "")
	if cacheClient == nil {
		cacheClient = &cache.Client{}
		cacheClient.New(log, false, "", nil, "", "", "")
	}
	c := &Client{}
	var js, key, response, validate string
	if provider == configuration.CustomProvider {
		js = "https://example.com/captcha.js"
		key = "custom-key"
		response = "custom-response"
		validate = validateURL
		if validate == "" {
			validate = "https://example.com/siteverify"
		}
	}
	err := c.New(log, cacheClient, http.DefaultClient, provider, js, key, response, validate, "site-key", "secret-key", "", templatePath, 60)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

func siteverifyStub(t *testing.T, status int, contentType, body string, check func(*http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

func TestValidateSuccess(t *testing.T) {
	srv := siteverifyStub(t, http.StatusOK, "application/json", `{"success":true}`, nil)
	defer srv.Close()

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("custom-response=token123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	valid, err := c.Validate(req, "203.0.113.7")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !valid {
		t.Fatal("Validate() = false, want true")
	}
}

func TestValidateProviderFailure(t *testing.T) {
	srv := siteverifyStub(t, http.StatusOK, "application/json", `{"success":false}`, nil)
	defer srv.Close()

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("custom-response=bad"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	valid, err := c.Validate(req, "203.0.113.7")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if valid {
		t.Fatal("Validate() = true, want false")
	}
}

func TestValidateNonJSONContentType(t *testing.T) {
	srv := siteverifyStub(t, http.StatusOK, "text/plain", "ok", nil)
	defer srv.Close()

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := c.Validate(req, "203.0.113.7")
	if !errors.Is(err, ErrRetryableVerify) {
		t.Fatalf("Validate() error = %v, want ErrRetryableVerify", err)
	}
}

func TestValidateNetworkError(t *testing.T) {
	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, "http://127.0.0.1:1/siteverify")
	c.infoProvider.validate = "http://127.0.0.1:1/siteverify"

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := c.Validate(req, "203.0.113.7")
	if !errors.Is(err, ErrRetryableVerify) {
		t.Fatalf("Validate() error = %v, want ErrRetryableVerify", err)
	}
}

func TestValidateJSONParseError(t *testing.T) {
	srv := siteverifyStub(t, http.StatusOK, "application/json", `{not-json`, nil)
	defer srv.Close()

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := c.Validate(req, "203.0.113.7")
	if !errors.Is(err, ErrRetryableVerify) {
		t.Fatalf("Validate() error = %v, want ErrRetryableVerify", err)
	}
}

func TestValidateSiteverifyIncludesRemoteIP(t *testing.T) {
	const wantIP = "203.0.113.7"
	var gotBody string
	srv := siteverifyStub(t, http.StatusOK, "application/json", `{"success":true}`, func(r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		gotBody = string(body)
	})
	defer srv.Close()

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if _, err := c.Validate(req, wantIP); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	values, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("ParseQuery() error = %v", err)
	}
	if values.Get("remoteip") != wantIP {
		t.Fatalf("remoteip = %q, want %q", values.Get("remoteip"), wantIP)
	}
	if values.Get("secret") != "secret-key" {
		t.Fatalf("secret = %q, want secret-key", values.Get("secret"))
	}
	if values.Get("response") != "token" {
		t.Fatalf("response = %q, want token", values.Get("response"))
	}
}

func TestServeHTTPSuccessRedirects(t *testing.T) {
	srv := siteverifyStub(t, http.StatusOK, "application/json", `{"success":true}`, nil)
	defer srv.Close()

	log := logger.New("INFO", "")
	mem := &cache.Client{}
	mem.New(log, false, "", nil, "", "", "")

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), mem, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	c.ServeHTTP(rec, req, "203.0.113.7")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	value, err := mem.Get("203.0.113.7_captcha")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if value != cache.CaptchaDoneValue {
		t.Fatalf("cache value = %q, want %q", value, cache.CaptchaDoneValue)
	}
}

func TestServeHTTPFailedCacheWriteRendersCaptcha(t *testing.T) {
	srv := siteverifyStub(t, http.StatusOK, "application/json", `{"success":true}`, nil)
	defer srv.Close()

	log := logger.New("INFO", "")
	failCache := cache.NewFailingSetClient(log, errors.New("cache write failed"))

	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), failCache, srv.URL)
	c.infoProvider.validate = srv.URL

	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	c.ServeHTTP(rec, req, "203.0.113.7")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want empty", loc)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "site-key") {
		t.Fatalf("body = %q, want captcha template rendered", body)
	}
}

func TestServeHTTPRetryableErrorRendersCaptcha(t *testing.T) {
	c := newTestClient(t, configuration.CustomProvider, writeTestTemplate(t, testTemplate), nil, "http://127.0.0.1:1/siteverify")
	c.infoProvider.validate = "http://127.0.0.1:1/siteverify"

	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", strings.NewReader("custom-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	c.ServeHTTP(rec, req, "203.0.113.7")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "site-key") {
		t.Fatalf("body = %q, want captcha template rendered", rec.Body.String())
	}
}

func TestNewBuiltInProvider(t *testing.T) {
	path := writeTestTemplate(t, testTemplate)
	c := &Client{}
	log := slog.Default()
	err := c.New(log, nil, http.DefaultClient, configuration.HcaptchaProvider, "", "", "", "", "site", "secret", "", path, 60)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !c.Valid {
		t.Fatal("Valid = false, want true")
	}
	if c.infoProvider.validate != "https://api.hcaptcha.com/siteverify" {
		t.Fatalf("validate URL = %q", c.infoProvider.validate)
	}
}

func TestNewCustomProvider(t *testing.T) {
	path := writeTestTemplate(t, testTemplate)
	c := &Client{}
	log := slog.Default()
	err := c.New(log, nil, http.DefaultClient, configuration.CustomProvider, "js", "key", "resp", "https://verify.example", "site", "secret", "", path, 60)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.infoProvider.validate != "https://verify.example" {
		t.Fatalf("validate URL = %q", c.infoProvider.validate)
	}
}

func TestNewEmptyTemplatePath(t *testing.T) {
	c := &Client{}
	err := c.New(slog.Default(), nil, http.DefaultClient, configuration.HcaptchaProvider, "", "", "", "", "site", "secret", "", "", 60)
	if err == nil {
		t.Fatal("New() error = nil, want template error")
	}
}

func TestNewUnreadableTemplate(t *testing.T) {
	c := &Client{}
	err := c.New(slog.Default(), nil, http.DefaultClient, configuration.HcaptchaProvider, "", "", "", "", "site", "secret", "", filepath.Join(t.TempDir(), "missing.html"), 60)
	if err == nil {
		t.Fatal("New() error = nil, want template error")
	}
}

func TestNewNoProvider(t *testing.T) {
	c := &Client{}
	err := c.New(slog.Default(), nil, http.DefaultClient, "", "", "", "", "", "", "", "", "", 60)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if c.Valid {
		t.Fatal("Valid = true, want false")
	}
}
