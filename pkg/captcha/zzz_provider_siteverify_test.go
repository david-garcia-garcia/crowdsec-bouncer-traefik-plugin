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

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
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
	client.ServeHTTP(solveRW, testCaptchaRequest(solverPOST(), passedRemoteIP), "", "")
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
	client.ServeHTTP(solveRW, testCaptchaRequest(solverPOST(), "1.2.3.4"), "", "")
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
	client.ServeHTTP(solveRW, testCaptchaRequest(solverPOST(), "1.2.3.4"), "", "")
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

// Test_ServeHTTP_unusableSiteverifyAnswerLogsWarn proves a provider error page or
// non-JSON answer re-renders the challenge at 200 and logs WARN with status and type.
func Test_ServeHTTP_unusableSiteverifyAnswerLogsWarn(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantInLog   string
	}{
		{"500 html", http.StatusInternalServerError, "text/html", "<html>oops</html>", `siteverify: status 500, content type \"text/html\"`},
		{"404 plain", http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found", `siteverify: status 404, content type \"text/plain; charset=utf-8\"`},
		{"503 json success", http.StatusServiceUnavailable, "application/json", `{"success":true}`, `siteverify: status 503, content type \"application/json\"`},
		{"200 html", http.StatusOK, "text/html", "<html>login</html>", `siteverify: status 200, content type \"text/html\"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(siteverify.Close)

			logger.ResetDebounceForTest()
			client := newTestSiteverifyClient(t, siteverify.URL, siteverify.Client())
			log, sink := newTestLogSink(slog.LevelInfo)
			client.log = log

			outcome, err := client.Validate(testCaptchaRequest(solverPOST(), "1.2.3.4"))
			if err == nil || outcome == Pass {
				t.Fatalf("Validate = (%v, %v), want not-passed with an error", outcome, err)
			}

			solveRW := httptest.NewRecorder()
			client.ServeHTTP(solveRW, testCaptchaRequest(solverPOST(), "1.2.3.4"), "", "")
			if solveRW.Code != http.StatusOK {
				t.Fatalf("want 200 challenge, got %d", solveRW.Code)
			}
			if !strings.Contains(solveRW.Body.String(), siteverifyChallengeMarker) {
				t.Fatalf("want captcha HTML, got %q", solveRW.Body.String())
			}
			if cookie := solveRW.Result().Header.Get("Set-Cookie"); strings.Contains(cookie, gateCookieName+"=") {
				t.Fatalf("must not mint gate cookie: %s", cookie)
			}
			logs := sink.String()
			if !strings.Contains(logs, `"level":"WARN"`) || !strings.Contains(logs, `"msg":"captcha:ServeHTTP:validate"`) {
				t.Fatalf("want WARN captcha:ServeHTTP:validate, got %s", logs)
			}
			if !strings.Contains(logs, tc.wantInLog) {
				t.Fatalf("want %s in log, got %s", tc.wantInLog, logs)
			}
			for _, secret := range []string{"e2e-dummy-secret", "ok-token", tc.body} {
				if strings.Contains(logs, secret) {
					t.Fatalf("log leaks %q: %s", secret, logs)
				}
			}
		})
	}
}

// Test_ServeHTTP_siteverifyWarnIsDebounced proves repeated failed submits inside 5 seconds log one WARN.
func Test_ServeHTTP_siteverifyWarnIsDebounced(t *testing.T) {
	logger.ResetDebounceForTest()
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(siteverify.Close)

	client := newTestSiteverifyClient(t, siteverify.URL, siteverify.Client())
	log, sink := newTestLogSink(slog.LevelInfo)
	client.log = log
	for range 3 {
		client.ServeHTTP(httptest.NewRecorder(), testCaptchaRequest(solverPOST(), "1.2.3.4"), "", "")
	}
	if n := strings.Count(sink.String(), `"msg":"captcha:ServeHTTP:validate"`); n != 1 {
		t.Fatalf("want 1 WARN line for 3 failed submits, got %d: %s", n, sink.String())
	}
}

// Test_ServeHTTP_clientErrorJSONIsReject proves a 4xx JSON answer is a reject with no error and no log,
// even when the body says success true.
func Test_ServeHTTP_clientErrorJSONIsReject(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"400 success false", http.StatusBadRequest, `{"success":false}`},
		{"403 success true", http.StatusForbidden, `{"success":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger.ResetDebounceForTest()
			siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(siteverify.Close)

			client := newTestSiteverifyClient(t, siteverify.URL, siteverify.Client())
			log, sink := newTestLogSink(slog.LevelInfo)
			client.log = log

			outcome, err := client.Validate(testCaptchaRequest(solverPOST(), "1.2.3.4"))
			if err != nil || outcome != Reject {
				t.Fatalf("Validate = (%v, %v), want (Reject, nil)", outcome, err)
			}
			solveRW := httptest.NewRecorder()
			client.ServeHTTP(solveRW, testCaptchaRequest(solverPOST(), "1.2.3.4"), "", "")
			if solveRW.Code != http.StatusOK {
				t.Fatalf("want 200 challenge, got %d", solveRW.Code)
			}
			if cookie := solveRW.Result().Header.Get("Set-Cookie"); strings.Contains(cookie, gateCookieName+"=") {
				t.Fatalf("must not mint gate cookie: %s", cookie)
			}
			if strings.Contains(sink.String(), "captcha:ServeHTTP:validate") {
				t.Fatalf("a wrong solve must not log the provider failure: %s", sink.String())
			}
		})
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
