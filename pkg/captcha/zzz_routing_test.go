package captcha

import (
	"bytes"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRoutingCaptchaTemplate writes a readable captcha.html for Client.New.
func writeRoutingCaptchaTemplate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(path, []byte("CAPTCHA_FIXTURE"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

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

func Test_IsCaptchaFormPost_ordinaryPostKeepsItsBody(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "dummy-captcha-response"}}
	payload := "comment=hello&other=1"
	req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.IsCaptchaFormPost(req) {
		t.Fatal("POST without provider field must not be a captcha-form POST")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != payload {
		t.Fatalf("origin body want %q, got %q", payload, string(body))
	}
	if req.ContentLength != int64(len(payload)) {
		t.Fatalf("ContentLength want %d, got %d", len(payload), req.ContentLength)
	}
}

func Test_IsCaptchaFormPost_overMaxBodyReachesOriginIntact(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "dummy-captcha-response"}}
	// A token cannot be this big, so the upload must pass through untouched even
	// though it does contain the provider field name.
	payload := "dummy-captcha-response=token&blob=" + strings.Repeat("a", captchaFormMaxBytes)
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.IsCaptchaFormPost(req) {
		t.Fatal("body over captchaFormMaxBytes must not be treated as a captcha form")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != payload {
		t.Fatalf("origin body want %d bytes unchanged, got %d", len(payload), len(body))
	}
}

func Test_IsCaptchaFormPost_unknownContentLength(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "dummy-captcha-response"}}

	small := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("dummy-captcha-response=token"))
	small.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	small.ContentLength = -1
	if !client.IsCaptchaFormPost(small) {
		t.Fatal("chunked captcha form must still be detected")
	}

	payload := strings.Repeat("b", captchaFormMaxBytes+1)
	large := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	large.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	large.ContentLength = -1
	if client.IsCaptchaFormPost(large) {
		t.Fatal("chunked body over the cap must not be treated as a captcha form")
	}
	body, err := io.ReadAll(large.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != payload {
		t.Fatalf("chunked origin body want %d bytes unchanged, got %d", len(payload), len(body))
	}
}

func Test_IsCaptchaFormPost_multipartForm(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "dummy-captcha-response"}}

	var solved bytes.Buffer
	writer := multipart.NewWriter(&solved)
	if err := writer.WriteField("dummy-captcha-response", "token"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/protected", bytes.NewReader(solved.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if !client.IsCaptchaFormPost(req) {
		t.Fatal("multipart POST carrying the provider field must be a captcha-form POST")
	}

	var upload bytes.Buffer
	otherWriter := multipart.NewWriter(&upload)
	if err := otherWriter.WriteField("comment", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := otherWriter.Close(); err != nil {
		t.Fatal(err)
	}
	payload := upload.Bytes()
	otherReq := httptest.NewRequest(http.MethodPost, "/protected", bytes.NewReader(payload))
	otherReq.Header.Set("Content-Type", otherWriter.FormDataContentType())
	if client.IsCaptchaFormPost(otherReq) {
		t.Fatal("multipart POST without the provider field must not be a captcha-form POST")
	}
	body, err := io.ReadAll(otherReq.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("multipart origin body must be restored unchanged")
	}
}

func Test_IsCaptchaFormPost_alreadyParsedPostForm(t *testing.T) {
	client := &Client{infoProvider: &infoProvider{response: "dummy-captcha-response"}}
	req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("dummy-captcha-response=token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	// Body is drained, so only the parsed PostForm can answer.
	if !client.IsCaptchaFormPost(req) {
		t.Fatal("already-parsed captcha form must be detected without rereading Body")
	}

	parsedOther := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("comment=hello"))
	parsedOther.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := parsedOther.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if client.IsCaptchaFormPost(parsedOther) {
		t.Fatal("already-parsed ordinary form must not be a captcha-form POST")
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
		"",
		"site",
		"secret",
		"gate",
		true,
		writeRoutingCaptchaTemplate(t),
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
		"",
		"site",
		"secret",
		"gate",
		true,
		writeRoutingCaptchaTemplate(t),
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
		"",
		"site",
		"secret",
		"gate",
		true,
		writeRoutingCaptchaTemplate(t),
		3600,
	); err != nil {
		t.Fatal(err)
	}
	if client.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "/1/api.js", nil)) {
		t.Fatal("built-in CDN paths are not a match set")
	}
}

func Test_ServeHTTP_rendersChallengeURL(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	template := `<div data-challenge-url="{{ .ChallengeURL }}" class="{{ .FrontendKey }}"></div>`
	if err := os.WriteFile(templatePath, []byte(template), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	if err := client.New(
		slog.Default(),
		http.DefaultClient,
		"custom",
		"/fast.js",
		"http://captcha.localhost:8000/v0/challenge",
		"dummy-captcha",
		"dummy-captcha-response",
		"/v0/siteverify",
		"",
		"site",
		"secret",
		"gate",
		true,
		templatePath,
		3600,
	); err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://app.example/protected", nil), "192.0.2.10", "")
	if !strings.Contains(rw.Body.String(), `data-challenge-url="http://captcha.localhost:8000/v0/challenge"`) {
		t.Fatalf("captcha page must render the configured challenge URL, got %q", rw.Body.String())
	}
}

func Test_ServeHTTP_challengeURLEmptyForBuiltinProvider(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte(`<div data-challenge-url="{{ .ChallengeURL }}"></div>`), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	if err := client.New(
		slog.Default(),
		http.DefaultClient,
		"hcaptcha",
		"", "", "", "", "", "",
		"site",
		"secret",
		"gate",
		true,
		templatePath,
		3600,
	); err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://app.example/protected", nil), "192.0.2.10", "")
	if !strings.Contains(rw.Body.String(), `data-challenge-url=""`) {
		t.Fatalf("built-in provider must render an empty challenge URL, got %q", rw.Body.String())
	}
}

func Test_WriteSolvedRedirect_noCookieRemint(t *testing.T) {
	client := &Client{}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected?x=1", nil)
	rw := httptest.NewRecorder()
	client.WriteSolvedRedirect(rw, req, "X-Remediation")
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
