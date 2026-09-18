package captcha

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test_ServeHTTP_dummyProviderSolveIssuesGateCookie is the in-process stand-in
// for mock e2e captcha: custom provider + always-pass siteverify + form POST.
func Test_ServeHTTP_dummyProviderSolveIssuesGateCookie(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("E2E_CAPTCHA_PAGE_MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	err := client.New(
		slog.Default(),
		siteverify.Client(),
		"custom",
		siteverify.URL+"/dummy.js",
		"",
		"dummy-captcha",
		"dummy-captcha-response",
		siteverify.URL+"/siteverify",
		"e2e-dummy-site",
		"e2e-dummy-secret",
		"e2e-gate-secret",
		true,
		"",
		templatePath,
		3600,
	)
	if err != nil {
		t.Fatal(err)
	}

	getRW := httptest.NewRecorder()
	client.ServeHTTP(getRW, httptest.NewRequest(http.MethodGet, "/foo", nil), "1.2.3.4")
	if getRW.Code != http.StatusOK || !strings.Contains(getRW.Body.String(), "E2E_CAPTCHA_PAGE_MARKER") {
		t.Fatalf("GET want captcha page, got %d %q", getRW.Code, getRW.Body.String())
	}

	emptyPOST := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(""))
	emptyPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	emptyRW := httptest.NewRecorder()
	client.ServeHTTP(emptyRW, emptyPOST, "1.2.3.4")
	if emptyRW.Code != http.StatusOK {
		t.Fatalf("POST without field want 200, got %d", emptyRW.Code)
	}

	form := url.Values{}
	form.Set("dummy-captcha-response", "ok")
	solveReq := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(form.Encode()))
	solveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solveReq, "1.2.3.4")
	if solveRW.Code != http.StatusFound {
		body, _ := io.ReadAll(solveRW.Result().Body)
		t.Fatalf("solve want 302, got %d %s", solveRW.Code, body)
	}
	cookie := solveRW.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("solve missing gate cookie: %s", cookie)
	}

	follow := httptest.NewRequest(http.MethodGet, "/foo", nil)
	follow.Header.Set("Cookie", cookie)
	if !client.Check(follow, "1.2.3.4") {
		t.Fatal("Check same IP should pass after solve")
	}
	if client.Check(follow, "5.6.7.8") {
		t.Fatal("Check other IP should fail when bind-IP is on")
	}
}

// Test_ServeHTTP_queryTokenSolvesWithoutBody covers Traefik Yaegi leaving POST form empty.
func Test_ServeHTTP_queryTokenSolvesWithoutBody(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("E2E_CAPTCHA_PAGE_MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	if err := client.New(
		slog.Default(),
		siteverify.Client(),
		"custom",
		siteverify.URL+"/dummy.js",
		"",
		"dummy-captcha",
		"dummy-captcha-response",
		siteverify.URL+"/siteverify",
		"e2e-dummy-site",
		"e2e-dummy-secret",
		"e2e-gate-secret",
		true,
		"",
		templatePath,
		3600,
	); err != nil {
		t.Fatal(err)
	}

	solveReq := httptest.NewRequest(http.MethodPost, "/foo?dummy-captcha-response=ok", nil)
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solveReq, "1.2.3.4")
	if solveRW.Code != http.StatusFound {
		t.Fatalf("query-token solve want 302, got %d", solveRW.Code)
	}
}

// TestHunt_siteverifyJSONContentTypeIsCaseInsensitive proves a mixed-case
// siteverify Content-Type still issues the gate cookie and 302.
func TestHunt_siteverifyJSONContentTypeIsCaseInsensitive(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "Application/JSON")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("E2E_CAPTCHA_PAGE_MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	if err := client.New(
		slog.Default(),
		siteverify.Client(),
		"custom",
		siteverify.URL+"/dummy.js",
		"",
		"dummy-captcha",
		"dummy-captcha-response",
		siteverify.URL+"/siteverify",
		"e2e-dummy-site",
		"e2e-dummy-secret",
		"e2e-gate-secret",
		true,
		"",
		templatePath,
		3600,
	); err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("dummy-captcha-response", "ok")
	solveReq := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(form.Encode()))
	solveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solveReq, "1.2.3.4")
	if solveRW.Code != http.StatusFound {
		body, _ := io.ReadAll(solveRW.Result().Body)
		t.Fatalf("solve want 302, got %d %s", solveRW.Code, body)
	}
	cookie := solveRW.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("solve missing gate cookie: %s", cookie)
	}
}

// Test_ServeHTTP_jsonpSiteverifyContentTypeIsNotJSON proves a jsonp type token
// is not treated as JSON even when the body is success:true.
func Test_ServeHTTP_jsonpSiteverifyContentTypeIsNotJSON(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jsonp")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("E2E_CAPTCHA_PAGE_MARKER"), 0o600); err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	if err := client.New(
		slog.Default(),
		siteverify.Client(),
		"custom",
		siteverify.URL+"/dummy.js",
		"",
		"dummy-captcha",
		"dummy-captcha-response",
		siteverify.URL+"/siteverify",
		"e2e-dummy-site",
		"e2e-dummy-secret",
		"e2e-gate-secret",
		true,
		"",
		templatePath,
		3600,
	); err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("dummy-captcha-response", "ok")
	solveReq := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader(form.Encode()))
	solveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solveReq, "1.2.3.4")
	if solveRW.Code != http.StatusOK {
		t.Fatalf("jsonp siteverify want 200 challenge, got %d", solveRW.Code)
	}
	cookie := solveRW.Result().Header.Get("Set-Cookie")
	if strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("jsonp siteverify must not mint gate cookie: %s", cookie)
	}
}

func Test_captchaResponseFromRequest_rawBodyWithoutContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/foo", strings.NewReader("dummy-captcha-response=ok"))
	// No Content-Type: ParseForm skips the body; the raw ParseQuery path must still win.
	got := captchaResponseFromRequest(req, "dummy-captcha-response")
	if got != "ok" {
		t.Fatalf("got %q, want ok", got)
	}
}
