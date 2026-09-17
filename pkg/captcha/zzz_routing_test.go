package captcha

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_IsCaptchaFormPost(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "dummy-captcha-response"}}

	formPOST := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("dummy-captcha-response=token"))
	formPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !client.IsCaptchaFormPost(formPOST) {
		t.Fatal("POST with provider field must be a captcha-form POST")
	}

	ordinaryPOST := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("other=1"))
	ordinaryPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.IsCaptchaFormPost(ordinaryPOST) {
		t.Fatal("POST without provider field must not be a captcha-form POST")
	}

	queryGET := httptest.NewRequest(http.MethodGet, "/protected?dummy-captcha-response=token", nil)
	if client.IsCaptchaFormPost(queryGET) {
		t.Fatal("GET with provider field in query is not a form POST")
	}
}

func Test_IsCustomResourceRequest_exactPathOnly(t *testing.T) {
	client := &Client{}
	if err := client.New(
		slog.Default(),
		http.DefaultClient,
		"custom",
		"https://widget.example/assets/fast.js",
		"https://widget.example/v0/challenge",
		"dummy-captcha",
		"dummy-captcha-response",
		"https://widget.example/v0/siteverify",
		"site",
		"secret",
		"gate",
		true,
		"",
		"",
		3600,
	); err != nil {
		t.Fatal(err)
	}

	if !client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "http://app.example/assets/fast.js", nil)) {
		t.Fatal("absolute JsURL must match same-route path")
	}
	if !client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "http://app.example/v0/challenge", nil)) {
		t.Fatal("challenge URL path must match")
	}
	if client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "http://app.example/assets", nil)) {
		t.Fatal("prefix of the JS path must not match")
	}
	if client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "http://app.example/assets/fast.js/extra", nil)) {
		t.Fatal("JS path plus suffix must not match")
	}
	if client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "http://app.example/v0/siteverify", nil)) {
		t.Fatal("ValidateURL path must not match")
	}
}

func Test_IsCustomResourceRequest_emptyChallengeIsJsOnly(t *testing.T) {
	client := &Client{}
	if err := client.New(
		slog.Default(),
		http.DefaultClient,
		"custom",
		"/fast.js",
		"",
		"dummy-captcha",
		"dummy-captcha-response",
		"/v0/siteverify",
		"site",
		"secret",
		"gate",
		true,
		"",
		"",
		3600,
	); err != nil {
		t.Fatal(err)
	}
	if !client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "/fast.js", nil)) {
		t.Fatal("JsURL path must match when challenge URL is empty")
	}
	if client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "/v0/challenge", nil)) {
		t.Fatal("empty challenge URL must not add a second path")
	}
}

func Test_IsCustomResourceRequest_builtinCDNNotStored(t *testing.T) {
	client := &Client{}
	if err := client.New(
		slog.Default(),
		http.DefaultClient,
		"hcaptcha",
		"https://hcaptcha.com/1/api.js",
		"",
		"",
		"",
		"",
		"site",
		"secret",
		"gate",
		true,
		"",
		"",
		3600,
	); err != nil {
		t.Fatal(err)
	}
	if client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "/1/api.js", nil)) {
		t.Fatal("built-in CDN paths are not a match set")
	}
}

func Test_WriteSolvedRedirect_noCookieRemint(t *testing.T) {
	client := &Client{remediationCustomHeader: "X-Remediation"}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected?x=1", nil)
	rw := httptest.NewRecorder()
	client.WriteSolvedRedirect(rw, req)
	if rw.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rw.Code)
	}
	if got := rw.Header().Get("Location"); got != "http://example.com/protected?x=1" {
		t.Fatalf("want same URL, got %q", got)
	}
	if got := rw.Header().Get("X-Remediation"); got != "solved-captcha" {
		t.Fatalf("want solved-captcha header, got %q", got)
	}
	if got := rw.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("must not remint gate cookie, got %q", got)
	}
}
