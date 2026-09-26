package captcha

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const siteverifyChallengeMarker = "E2E_CAPTCHA_PAGE_MARKER"

// newTestSiteverifyClient builds a custom-provider client against one siteverify URL.
func newTestSiteverifyClient(t *testing.T, siteverifyURL string, httpClient *http.Client) *Client {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte(siteverifyChallengeMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &Client{}
	if err := client.New(
		slog.Default(),
		httpClient,
		"custom",
		siteverifyURL+"/dummy.js",
		"",
		"dummy-captcha",
		"dummy-captcha-response",
		siteverifyURL+"/siteverify",
		"",
		"e2e-dummy-site",
		"e2e-dummy-secret",
		"e2e-gate-secret",
		true,
		templatePath,
		3600,
		Enterprise{},
	); err != nil {
		t.Fatal(err)
	}
	return client
}

// Test_ServeHTTP_siteverifyPostsRemoteIP proves the provider form includes the
// remoteIP already passed into ServeHTTP, not a header parse inside captcha.
func Test_ServeHTTP_siteverifyPostsRemoteIP(t *testing.T) {
	const passedRemoteIP = "203.0.113.9"
	var gotSecret, gotResponse, gotRemoteIP string
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		gotSecret = r.PostForm.Get("secret")
		gotResponse = r.PostForm.Get("response")
		gotRemoteIP = r.PostForm.Get("remoteip")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestSiteverifyClient(t, siteverify.URL, siteverify.Client())
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solverPOST(), passedRemoteIP, "", "")
	if solveRW.Code != http.StatusFound {
		body, _ := io.ReadAll(solveRW.Result().Body)
		t.Fatalf("solve want 302, got %d %s", solveRW.Code, body)
	}
	cookie := solveRW.Result().Header.Get("Set-Cookie")
	if !strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("solve missing gate cookie: %s", cookie)
	}
	formVerifier, ok := client.verifier.(*siteverifyVerifier)
	if !ok {
		t.Fatalf("verifier type %T", client.verifier)
	}
	if gotSecret != formVerifier.secretKey || gotResponse != "ok-token" || gotRemoteIP != passedRemoteIP {
		t.Fatalf("siteverify form secret=%q response=%q remoteip=%q, want secret=%q response=ok-token remoteip=%s",
			gotSecret, gotResponse, gotRemoteIP, formVerifier.secretKey, passedRemoteIP)
	}
}

// Test_ServeHTTP_transportErrorRendersChallenge proves a provider PostForm
// failure is HTTP 200 captcha HTML, not a bare 400.
func Test_ServeHTTP_transportErrorRendersChallenge(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	httpClient := siteverify.Client()
	siteverify.Close()

	client := newTestSiteverifyClient(t, siteverify.URL, httpClient)
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solverPOST(), "1.2.3.4", "", "")
	if solveRW.Code != http.StatusOK {
		t.Fatalf("transport error want 200 challenge, got %d (must not be 400)", solveRW.Code)
	}
	if !strings.Contains(solveRW.Body.String(), siteverifyChallengeMarker) {
		t.Fatalf("transport error want captcha HTML, got %q", solveRW.Body.String())
	}
	cookie := solveRW.Result().Header.Get("Set-Cookie")
	if strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("transport error must not mint gate cookie: %s", cookie)
	}
}

// Test_ServeHTTP_jsonDecodeErrorRendersChallenge proves Siteverify JSON
// Content-Type with a non-JSON body is HTTP 200 captcha HTML, not a bare 400.
func Test_ServeHTTP_jsonDecodeErrorRendersChallenge(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not-json`))
	}))
	t.Cleanup(siteverify.Close)

	client := newTestSiteverifyClient(t, siteverify.URL, siteverify.Client())
	solveRW := httptest.NewRecorder()
	client.ServeHTTP(solveRW, solverPOST(), "1.2.3.4", "", "")
	if solveRW.Code != http.StatusOK {
		t.Fatalf("decode error want 200 challenge, got %d (must not be 400)", solveRW.Code)
	}
	if !strings.Contains(solveRW.Body.String(), siteverifyChallengeMarker) {
		t.Fatalf("decode error want captcha HTML, got %q", solveRW.Body.String())
	}
	cookie := solveRW.Result().Header.Get("Set-Cookie")
	if strings.Contains(cookie, gateCookieName+"=") {
		t.Fatalf("decode error must not mint gate cookie: %s", cookie)
	}
}

// Test_New_warnsWhenCaptchaTemplateUnavailable leaves Valid false and returns nil.
func Test_New_warnsWhenCaptchaTemplateUnavailable(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		log, sink := newTestLogSink(slog.LevelWarn)
		client := &Client{}
		err := client.New(
			log,
			http.DefaultClient,
			"hcaptcha",
			"",
			"",
			"",
			"",
			"",
			"",
			"site",
			"secret",
			"gate-secret",
			true,
			"",
			3600,
			Enterprise{},
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if client.Valid {
			t.Fatal("New must leave Valid false when the captcha template is empty")
		}
		logged := sink.String()
		if strings.Count(logged, msgCaptchaTemplateUnavailable) != 1 {
			t.Fatalf("want one captcha template WARN, got %s", logged)
		}
		if !strings.Contains(logged, `"reason":"empty"`) {
			t.Fatalf("want reason empty, got %s", logged)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		log, sink := newTestLogSink(slog.LevelWarn)
		client := &Client{}
		missing := filepath.Join(t.TempDir(), "missing-captcha.html")
		err := client.New(
			log,
			http.DefaultClient,
			"hcaptcha",
			"",
			"",
			"",
			"",
			"",
			"",
			"site",
			"secret",
			"gate-secret",
			true,
			missing,
			3600,
			Enterprise{},
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if client.Valid {
			t.Fatal("New must leave Valid false when the captcha template is unloadable")
		}
		logged := sink.String()
		if strings.Count(logged, msgCaptchaTemplateUnavailable) != 1 {
			t.Fatalf("want one captcha template WARN, got %s", logged)
		}
		if !strings.Contains(logged, `"reason":"unloadable"`) {
			t.Fatalf("want reason unloadable, got %s", logged)
		}
	})
}
