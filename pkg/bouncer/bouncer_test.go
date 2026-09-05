package bouncer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
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
			b.handleBanServeHTTP(rw, req, "0.0.0.0", "TEST")
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
			b.handleBanServeHTTP(rw, req, "0.0.0.0", "TEST")
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
