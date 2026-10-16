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

// challengeMarkerBody is urlencoded challenge marker crowdsec_captcha_challenge=v1.
func challengeMarkerBody() string {
	return challengeMarkerName + "=" + challengeMarkerValue
}

func Test_HasChallengeMarker(t *testing.T) {
	client := &Client{}

	formPOST := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(challengeMarkerBody()))
	formPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !client.HasChallengeMarker(formPOST) {
		t.Fatal("POST with challenge marker must carry the challenge marker")
	}

	ordinaryPOST := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("other=1"))
	ordinaryPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.HasChallengeMarker(ordinaryPOST) {
		t.Fatal("POST without challenge marker must not carry the challenge marker")
	}

	queryGET := httptest.NewRequest(http.MethodGet, "/protected?"+challengeMarkerBody(), nil)
	if client.HasChallengeMarker(queryGET) {
		t.Fatal("GET with challenge marker in query is not a form POST")
	}
}

func Test_HasChallengeMarker_ordinaryPostKeepsItsBody(t *testing.T) {
	client := &Client{}
	payload := "comment=hello&other=1"
	req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.HasChallengeMarker(req) {
		t.Fatal("POST without challenge marker must not carry the challenge marker")
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

func Test_HasChallengeMarker_overMaxBodyReachesOriginIntact(t *testing.T) {
	client := &Client{}
	// A challenge marker cannot be this big, so the upload must pass through
	// untouched even though it does contain the challenge marker name.
	payload := challengeMarkerBody() + "&blob=" + strings.Repeat("a", captchaFormMaxBytes)
	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.HasChallengeMarker(req) {
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

func Test_HasChallengeMarker_unknownContentLength(t *testing.T) {
	client := &Client{}

	small := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(challengeMarkerBody()))
	small.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	small.ContentLength = -1
	if !client.HasChallengeMarker(small) {
		t.Fatal("chunked captcha form must still be detected")
	}

	payload := strings.Repeat("b", captchaFormMaxBytes+1)
	large := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(payload))
	large.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	large.ContentLength = -1
	if client.HasChallengeMarker(large) {
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

func Test_HasChallengeMarker_multipartForm(t *testing.T) {
	client := &Client{}

	var solved bytes.Buffer
	writer := multipart.NewWriter(&solved)
	if err := writer.WriteField(challengeMarkerName, challengeMarkerValue); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/protected", bytes.NewReader(solved.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if !client.HasChallengeMarker(req) {
		t.Fatal("multipart POST carrying the challenge marker must carry the challenge marker")
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
	if client.HasChallengeMarker(otherReq) {
		t.Fatal("multipart POST without the challenge marker must not carry the challenge marker")
	}
	body, err := io.ReadAll(otherReq.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("multipart origin body must be restored unchanged")
	}
}

func Test_HasChallengeMarker_alreadyParsedPostForm(t *testing.T) {
	client := &Client{}
	req := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(challengeMarkerBody()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	// Body is drained, so only the parsed PostForm can answer.
	if !client.HasChallengeMarker(req) {
		t.Fatal("already-parsed captcha form must be detected without rereading Body")
	}

	parsedOther := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("comment=hello"))
	parsedOther.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := parsedOther.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if client.HasChallengeMarker(parsedOther) {
		t.Fatal("already-parsed ordinary form must not carry the challenge marker")
	}
}

func Test_HasChallengeMarker_tokenFieldIsNotTheMarker(t *testing.T) {
	client := &Client{widget: Widget{TokenField: "dummy-captcha-response"}}

	vendorOnly := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader("dummy-captcha-response=token"))
	vendorOnly.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.HasChallengeMarker(vendorOnly) {
		t.Fatal("POST with TokenField and no challenge marker must not carry the challenge marker")
	}

	markerOnly := &Client{}
	markerPOST := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(challengeMarkerBody()))
	markerPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !markerOnly.HasChallengeMarker(markerPOST) {
		t.Fatal("POST with challenge marker and no TokenField must carry the challenge marker")
	}

	wrongValue := httptest.NewRequest(http.MethodPost, "/protected", strings.NewReader(challengeMarkerName+"=v2"))
	wrongValue.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.HasChallengeMarker(wrongValue) {
		t.Fatal("POST with challenge marker value other than v1 must not carry the challenge marker")
	}
}

func Test_shippedChallengePagesIncludeLeftoverFormMarker(t *testing.T) {
	pages := []string{
		filepath.Join("..", "..", "captcha.html"),
		filepath.Join("..", "..", "examples", "captcha", "captcha.html"),
		filepath.Join("..", "..", "examples", "custom-captcha", "captcha.html"),
		filepath.Join("..", "..", "tests", "e2e", "real", "config", "captcha-dummy.html"),
		filepath.Join("..", "..", "tests", "e2e", "mock", "scenarios", "captcha", "captcha.html"),
		filepath.Join("..", "..", "tests", "e2e", "mock", "scenarios", "captcha-ban-origins", "captcha.html"),
	}
	for _, path := range pages {
		raw, err := os.ReadFile(path) //nolint:gosec // shipped challenge-page fixtures
		if err != nil {
			t.Fatal(err)
		}
		page := string(raw)
		if !strings.Contains(page, challengeMarkerName) {
			t.Fatalf("%s must contain challenge marker name %q", path, challengeMarkerName)
		}
		if !strings.Contains(page, challengeMarkerValue) {
			t.Fatalf("%s must contain challenge marker value %q", path, challengeMarkerValue)
		}
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
		Enterprise{},
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
		Enterprise{},
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
		Enterprise{},
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
		Enterprise{},
	); err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, testCaptchaRequest(httptest.NewRequest(http.MethodGet, "http://app.example/protected", nil), "192.0.2.10"), "", "")
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
		Enterprise{},
	); err != nil {
		t.Fatal(err)
	}

	rw := httptest.NewRecorder()
	client.ServeHTTP(rw, testCaptchaRequest(httptest.NewRequest(http.MethodGet, "http://app.example/protected", nil), "192.0.2.10"), "", "")
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
	if got := rw.Header().Get("X-Remediation"); got != "captcha:solved" {
		t.Fatalf("want captcha:solved header, got %q", got)
	}
	if got := rw.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("must not remint gate cookie, got %q", got)
	}
	if got := rw.Header().Get("Cache-Control"); got != "no-cache, no-store" {
		t.Fatalf("Cache-Control=%q want no-cache, no-store", got)
	}
}
