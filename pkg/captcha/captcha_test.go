package captcha

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// newTestCaptchaClient builds a captcha Client for unit tests (no provider HTTP).
func newTestCaptchaClient(t *testing.T, provider, customResponse string) *Client {
	t.Helper()
	log := logger.New("ERROR", "")
	cacheClient := &cache.Client{}
	cacheClient.New(log, false, "", nil, "", "", "")
	client := &Client{}
	js, key, response, validate := "", "", "", ""
	if provider == configuration.CustomProvider {
		js = "http://example.com/captcha.js"
		key = "custom-key"
		response = customResponse
		validate = "http://example.com/siteverify"
	}
	err := client.New(log, cacheClient, &http.Client{}, provider, js, key, response, validate, "site", "secret", "X-Remediation", "", 60)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestIsCaptchaFormPostHcaptchaField(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "")
	form := url.Values{}
	form.Set("h-captcha-response", "token")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !client.IsCaptchaFormPost(req) {
		t.Fatal("expected h-captcha-response POST to be a captcha form")
	}
}

func TestIsCaptchaFormPostCustomField(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.CustomProvider, "my-captcha-token")
	form := url.Values{}
	form.Set("my-captcha-token", "token")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !client.IsCaptchaFormPost(req) {
		t.Fatal("expected custom response field POST to be a captcha form")
	}
}

func TestIsCaptchaFormPostGetIsFalse(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/login", nil)
	if client.IsCaptchaFormPost(req) {
		t.Fatal("GET must not be a captcha form POST")
	}
}

func TestIsCaptchaFormPostWithoutFieldRestoresBody(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "")
	payload := "username=alice&password=secret"
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.IsCaptchaFormPost(req) {
		t.Fatal("ordinary POST must not be a captcha form")
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != payload {
		t.Fatalf("origin body want %q got %q", payload, string(raw))
	}
}

func TestIsCaptchaFormPostOverMaxRestoresBody(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "")
	payload := "blob=" + strings.Repeat("a", captchaFormMaxBytes+1)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.IsCaptchaFormPost(req) {
		t.Fatal("oversized POST must not be treated as a captcha form")
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != payload {
		t.Fatalf("origin body length want %d got %d", len(payload), len(raw))
	}
}

func TestIsCaptchaFormPostUnknownLengthOverMaxRestoresBody(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "")
	payload := "blob=" + strings.Repeat("b", captchaFormMaxBytes+1)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1
	if client.IsCaptchaFormPost(req) {
		t.Fatal("chunked oversized POST must not be treated as a captcha form")
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != payload {
		t.Fatalf("origin body length want %d got %d", len(payload), len(raw))
	}
}

func TestWriteSolvedRedirect(t *testing.T) {
	client := newTestCaptchaClient(t, configuration.HcaptchaProvider, "")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login?next=1", nil)
	recorder := httptest.NewRecorder()
	client.WriteSolvedRedirect(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status want 302 got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Location"); got != "/login?next=1" && got != "http://example.com/login?next=1" {
		t.Fatalf("Location want request URL got %q", got)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "solved-captcha" {
		t.Fatalf("remediation header want solved-captcha got %q", got)
	}
}
