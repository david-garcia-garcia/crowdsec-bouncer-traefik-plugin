package bouncer

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecconnection"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestHandleBanServeHTTPWithDifferentMethods(t *testing.T) {
	html := "<html>You are banned</html>"
	banTemplate, _ := template.New("html").Delims("{{", "}}").Parse(html)
	tests := []struct {
		name              string
		method            string
		banTemplate       *template.Template
		expectBodyContent bool
	}{
		{name: "GET request should have body with template", method: http.MethodGet, banTemplate: banTemplate, expectBodyContent: true},
		{name: "HEAD request should NOT have body even with template", method: http.MethodHead, banTemplate: banTemplate, expectBodyContent: false},
		{name: "POST request should have body with template", method: http.MethodPost, banTemplate: banTemplate, expectBodyContent: true},
		{name: "PUT request should have body with template", method: http.MethodPut, banTemplate: banTemplate, expectBodyContent: true},
		{name: "DELETE request should have body with template", method: http.MethodDelete, banTemplate: banTemplate, expectBodyContent: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Bouncer{
				remediationStatusCode:   http.StatusForbidden,
				remediationCustomHeader: "X-Test-Remediation",
				banTemplate:             tt.banTemplate,
				banTemplateContentType:  "text/html; charset=utf-8",
			}
			rw := httptest.NewRecorder()
			req := &http.Request{Method: tt.method}
			b.handleBanServeHTTP(rw, req, "0.0.0.0", "TEST", "")
			if rw.Code != http.StatusForbidden {
				t.Errorf("Expected status code 403, got %d", rw.Code)
			}
			if headerValue := rw.Header().Get("X-Test-Remediation"); headerValue != "ban" {
				t.Errorf("Expected header X-Test-Remediation to be 'ban', got %s", headerValue)
			}
			body := rw.Body.String()
			hasBodyContent := len(body) > 0
			if hasBodyContent != tt.expectBodyContent {
				t.Errorf("Method %s: expected body content: %v, got body content: %v (body: %q)",
					tt.method, tt.expectBodyContent, hasBodyContent, body)
			}
			if tt.expectBodyContent && body != html {
				t.Errorf("Expected body %q, got %q", html, body)
			}
		})
	}
}

func TestHandleBanServeHTTPContentType(t *testing.T) {
	html := "<html>You are banned</html>"
	banTemplate, _ := template.New("html").Delims("{{", "}}").Parse(html)
	tests := []struct {
		name                   string
		banTemplate            *template.Template
		banTemplateContentType string
	}{
		{name: "Default HTML content type", banTemplate: banTemplate, banTemplateContentType: "text/html; charset=utf-8"},
		{name: "Custom JSON content type", banTemplate: banTemplate, banTemplateContentType: "application/json"},
		{name: "Content type set even when banTemplate is nil", banTemplate: nil, banTemplateContentType: "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Bouncer{
				remediationStatusCode:  http.StatusForbidden,
				banTemplate:            tt.banTemplate,
				banTemplateContentType: tt.banTemplateContentType,
			}
			rw := httptest.NewRecorder()
			req := &http.Request{Method: http.MethodGet}
			b.handleBanServeHTTP(rw, req, "0.0.0.0", "TEST", "")
			if got := rw.Header().Get("Content-Type"); got != tt.banTemplateContentType {
				t.Errorf("Expected Content-Type %q, got %q", tt.banTemplateContentType, got)
			}
		})
	}
}

func TestCaptchaMethodBasedLogic(t *testing.T) {
	tests := []struct {
		name              string
		method            string
		remediation       string
		expectBanFallback bool
	}{
		{name: "GET with captcha remediation should allow captcha", method: http.MethodGet, remediation: cache.CaptchaValue, expectBanFallback: false},
		{name: "HEAD with captcha remediation should fallback to ban", method: http.MethodHead, remediation: cache.CaptchaValue, expectBanFallback: true},
		{name: "POST with captcha remediation should allow captcha", method: http.MethodPost, remediation: cache.CaptchaValue, expectBanFallback: false},
		{name: "PUT with captcha remediation should allow captcha", method: http.MethodPut, remediation: cache.CaptchaValue, expectBanFallback: false},
		{name: "DELETE with captcha remediation should allow captcha", method: http.MethodDelete, remediation: cache.CaptchaValue, expectBanFallback: false},
		{name: "PATCH with captcha remediation should allow captcha", method: http.MethodPatch, remediation: cache.CaptchaValue, expectBanFallback: false},
		{name: "OPTIONS with captcha remediation should allow captcha", method: http.MethodOptions, remediation: cache.CaptchaValue, expectBanFallback: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shouldUseCaptcha := tt.remediation == cache.CaptchaValue && tt.method != http.MethodHead
			if shouldUseCaptcha == tt.expectBanFallback {
				t.Errorf("Method %s with %s remediation: expected ban fallback %v, but logic would use captcha %v",
					tt.method, tt.remediation, tt.expectBanFallback, shouldUseCaptcha)
			}
		})
	}
}

func testBouncerWithAppsec(t *testing.T, handler http.HandlerFunc, banTemplate *template.Template) (*Bouncer, *httptest.Server) {
	t.Helper()
	appsec := httptest.NewServer(handler)
	appsecURL, err := url.Parse(appsec.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("next handler should not be called")
		}),
		appsecEnabled:           true,
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		banTemplate:             banTemplate,
		banTemplateContentType:  "text/html; charset=utf-8",
		log:                     logger.New("DEBUG", ""),
		conn:                    crowdsecconnection.NewTestAppsecConnection(appsecURL, appsec.Client(), logger.New("DEBUG", "")),
	}, appsec
}

func TestHandleNextServeHTTPRelaysStructuredAppsecChallenge(t *testing.T) {
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{
			"action":"challenge",
			"http_status":200,
			"user_body_content":"<html>challenge</html>",
			"user_cookies":["__crowdsec_challenge=value; Path=/; HttpOnly"],
			"user_headers":{
				"Content-Type":["text/html"],
				"Cache-Control":["no-store"]
			}
		}`))
	}, nil)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected challenge status 200, got %d", recorder.Code)
	}
	if got := recorder.Body.String(); got != "<html>challenge</html>" {
		t.Fatalf("expected appsec challenge body, got %q", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html" {
		t.Fatalf("expected Content-Type relayed, got %q", got)
	}
	if got := recorder.Header().Get("Set-Cookie"); got != "__crowdsec_challenge=value; Path=/; HttpOnly" {
		t.Fatalf("expected Set-Cookie relayed, got %q", got)
	}
	if got := recorder.Header().Get("X-Remediation"); got != crowdsecconnection.AppsecActionChallenge {
		t.Fatalf("expected custom remediation header challenge, got %q", got)
	}
}

func TestHandleNextServeHTTPLegacyAppsecForbiddenFallsBackToBan(t *testing.T) {
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, nil)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected fallback ban status 403, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "ban" {
		t.Fatalf("expected fallback remediation header ban, got %q", got)
	}
}

func TestHandleNextServeHTTPStructuredBanKeepsBanTemplate(t *testing.T) {
	banTemplate, err := template.New("ban").Parse("<html>custom ban for {{.ClientIP}} reason={{.RemediationReason}}</html>")
	if err != nil {
		t.Fatal(err)
	}
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"ban","http_status":403,"user_body_content":"appsec default page"}`))
	}, banTemplate)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
	want := "<html>custom ban for 192.0.2.10 reason=APPSEC</html>"
	if got := recorder.Body.String(); got != want {
		t.Fatalf("appsec ban must keep the configured ban template, got %q want %q", got, want)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "ban" {
		t.Fatalf("expected remediation header ban, got %q", got)
	}
}

func TestHandleNextServeHTTPChallengeFallsBackToBanContentType(t *testing.T) {
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","http_status":200,"user_body_content":"<html>challenge</html>"}`))
	}, nil)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected challenge status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("challenge without a Content-Type from appsec should fall back, got %q", got)
	}
}

func TestHandleNextServeHTTPOutOfRangeStatusDoesNotPanic(t *testing.T) {
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","http_status":42,"user_body_content":"<html>challenge</html>"}`))
	}, nil)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected clamped status 403, got %d", recorder.Code)
	}
}

func TestHandleNextServeHTTPEmptyChallengeBodyBans(t *testing.T) {
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","http_status":200}`))
	}, nil)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected ban for empty challenge body, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "ban" {
		t.Fatalf("expected ban header, got %q", got)
	}
}

func TestHandleNextServeHTTPZeroStatusIs200(t *testing.T) {
	b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","user_body_content":"<html>challenge</html>"}`))
	}, nil)
	defer appsec.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected missing http_status to be 200, got %d", recorder.Code)
	}
}

func TestHandleNextServeHTTPAllowCallsNext(t *testing.T) {
	appsec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsec.Close()
	appsecURL, err := url.Parse(appsec.URL)
	if err != nil {
		t.Fatal(err)
	}
	nextCalled := false
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}),
		appsecEnabled: true,
		log:           logger.New("ERROR", ""),
		conn:          crowdsecconnection.NewTestAppsecConnection(appsecURL, appsec.Client(), logger.New("ERROR", "")),
	}
	b.handleNextServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")
	if !nextCalled {
		t.Fatal("next handler should be called for allow")
	}
}

func TestApplyLapiFailureAction(t *testing.T) {
	t.Run("passthrough calls next", func(t *testing.T) {
		nextCalled := false
		b := &Bouncer{
			next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}),
			log:  logger.New("ERROR", ""),
			conn: crowdsecconnection.NewTestLapiFailureActionConnection(configuration.FailureActionPassthrough),
		}
		b.applyLapiFailureAction(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10", configuration.ReasonTECH, crowdsecconnection.OriginPluginTechStreamFail)
		if !nextCalled {
			t.Fatal("passthrough should use the pass path")
		}
	})
	t.Run("ban forbids", func(t *testing.T) {
		b := &Bouncer{
			next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("next handler should not be called")
			}),
			remediationStatusCode: http.StatusForbidden,
			log:                   logger.New("ERROR", ""),
			conn:                  crowdsecconnection.NewTestLapiFailureActionConnection(configuration.FailureActionBan),
		}
		recorder := httptest.NewRecorder()
		b.applyLapiFailureAction(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10", configuration.ReasonLAPI, crowdsecconnection.OriginPluginLapiFailure)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("ban want 403, got %d", recorder.Code)
		}
	})
}

func TestHandleNextServeHTTPAppsecFailureAction(t *testing.T) {
	t.Run("500 passthrough calls next", func(t *testing.T) {
		appsec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer appsec.Close()
		appsecURL, err := url.Parse(appsec.URL)
		if err != nil {
			t.Fatal(err)
		}
		nextCalled := false
		b := &Bouncer{
			next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}),
			appsecEnabled:       true,
			appsecFailureAction: configuration.FailureActionPassthrough,
			log:                 logger.New("ERROR", ""),
			conn:                crowdsecconnection.NewTestAppsecConnection(appsecURL, appsec.Client(), logger.New("ERROR", "")),
		}
		b.handleNextServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")
		if !nextCalled {
			t.Fatal("passthrough on AppSec 500 should call next")
		}
	})
	t.Run("500 ban forbids", func(t *testing.T) {
		b, appsec := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, nil)
		defer appsec.Close()
		b.appsecFailureAction = configuration.FailureActionBan
		recorder := httptest.NewRecorder()
		b.handleNextServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10")
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("ban on AppSec 500 want 403, got %d", recorder.Code)
		}
	})
}
