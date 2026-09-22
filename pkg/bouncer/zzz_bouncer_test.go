package bouncer

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// testClientRequest is req plus the chosen client address for handler tests.
func testClientRequest(req *http.Request, remoteIP string) clientRequest {
	parsed := net.ParseIP(remoteIP)
	if parsed != nil {
		remoteIP = parsed.String()
	}
	return clientRequest{Request: req, ipAddr: parsed, ipType: ip.FamilyOfIP(parsed), remoteIP: remoteIP}
}

func TestClientRequestRemoteIPIsCanonical(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	got := testClientRequest(req, "2001:0db8:0000:0000:0000:0000:0000:0001")
	if got.remoteIP != "2001:db8::1" {
		t.Fatalf("remoteIP=%q", got.remoteIP)
	}
}

// TestServeHTTP_NonCanonicalHeaderHitsCanonicalIpBan fails if ServeHTTP keeps the raw
// header on remoteIP: lookup keys on that string and misses the canonical slot.
func TestServeHTTP_NonCanonicalHeaderHitsCanonicalIpBan(t *testing.T) {
	log := logger.New("ERROR", "")
	lapiClient, store := lapi.NewTestClient(log)
	store.Put(decisionstore.Decision{Scope: decisionscope.ScopeIP, Value: "2001:db8::1", Kind: decisionscope.BannedValue, DurationSec: 60})
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned")
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	b := &Bouncer{
		enabled:                  true,
		forwardedHeadersInsecure: true,
		forwardedCustomHeader:    "X-Forwarded-For",
		clientPoolStrategy:       &ip.PoolStrategy{Checker: clientChecker},
		captchaClient:            &captcha.Client{},
		log:                      log,
		remediationStatusCode:    http.StatusForbidden,
		banTemplate:              banTemplate,
		banTemplateContentType:   "text/html; charset=utf-8",
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	bindTestLAPI(b, lapiClient, configuration.StreamMode)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "2001:0db8:0000:0000:0000:0000:0000:0001")
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	if passed {
		t.Fatal("origin must not run; the expanded header must hit the canonical Ip ban")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_PackedMemoryBanRecordsCrowdsecOrigin(t *testing.T) {
	log := logger.New("ERROR", "")
	lapiClient, store := lapi.NewTestClient(log)
	lapi.AttachTestMetricsReporter(lapiClient)
	lapi.SeedLiveSnapshotForTest(store, "203.0.113.10", decisionscope.BannedValue, "crowdsec", 60)
	clientChecker, err := ip.NewChecker(log, nil)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned")
	if err != nil {
		t.Fatal(err)
	}
	passed := false
	b := &Bouncer{
		enabled:                true,
		clientPoolStrategy:     &ip.PoolStrategy{Checker: clientChecker},
		captchaClient:          &captcha.Client{},
		log:                    log,
		remediationStatusCode:  http.StatusForbidden,
		banTemplate:            banTemplate,
		banTemplateContentType: "text/html; charset=utf-8",
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	bindTestLAPI(b, lapiClient, configuration.StreamMode)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "203.0.113.10:1"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	if passed {
		t.Fatal("origin must not run; packed ban must drop")
	}
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rw.Code)
	}
	if got := lapiClient.TestDroppedCount("crowdsec", "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped crowdsec=%d", got)
	}
}

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
			b.handleBanServeHTTP(rw, testClientRequest(req, "0.0.0.0"), "TEST", "")
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

// TestHandleBanServeHTTPTrustedTraceID checks that only a conservative inbound TraceID token reaches the ban template.
func TestHandleBanServeHTTPTrustedTraceID(t *testing.T) {
	banTemplate, err := template.New("html").Parse("id={{ .TraceID }}")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		headerValue string
		wantBody    string
	}{
		{name: "UUID", headerValue: "550e8400-e29b-41d4-a716-446655440000", wantBody: "id=550e8400-e29b-41d4-a716-446655440000"},
		{name: "W3C traceparent", headerValue: "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", wantBody: "id=00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		{name: "injection", headerValue: `";alert(1);//`, wantBody: "id="},
		{name: "201-character token", headerValue: strings.Repeat("a", 201), wantBody: "id="},
		{name: "empty header", headerValue: "", wantBody: "id="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Bouncer{
				remediationStatusCode:  http.StatusForbidden,
				banTemplate:            banTemplate,
				banTemplateContentType: "text/html; charset=utf-8",
				traceCustomHeader:      "X-Request-Id",
			}
			rw := httptest.NewRecorder()
			req := &http.Request{Method: http.MethodGet, Header: make(http.Header)}
			if tt.headerValue != "" {
				req.Header.Set("X-Request-Id", tt.headerValue)
			}
			b.handleBanServeHTTP(rw, testClientRequest(req, "0.0.0.0"), "TEST", "")
			body := rw.Body.String()
			if body != tt.wantBody {
				t.Errorf("body=%q want %q", body, tt.wantBody)
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
			b.handleBanServeHTTP(rw, testClientRequest(req, "0.0.0.0"), "TEST", "")
			if got := rw.Header().Get("Content-Type"); got != tt.banTemplateContentType {
				t.Errorf("Expected Content-Type %q, got %q", tt.banTemplateContentType, got)
			}
		})
	}
}

func testBouncerWithAppsec(t *testing.T, handler http.HandlerFunc, banTemplate *template.Template) (*Bouncer, *httptest.Server) {
	t.Helper()
	appsecServer := httptest.NewServer(handler)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("next handler should not be called")
		}),
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		banTemplate:             banTemplate,
		banTemplateContentType:  "text/html; charset=utf-8",
		log:                     logger.New("DEBUG", ""),
	}
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("DEBUG", "")))
	return b, appsecServer
}

func TestHandleNextServeHTTPRelaysStructuredAppsecChallenge(t *testing.T) {
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
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
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

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
	if got := recorder.Header().Get("X-Remediation"); got != appsec.ActionChallenge {
		t.Fatalf("expected custom remediation header challenge, got %q", got)
	}
}

func TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha(t *testing.T) {
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{
			"action":"captcha",
			"http_status":403,
			"user_body_content":"<html>captcha</html>",
			"user_cookies":["captcha=pending; Path=/; HttpOnly"],
			"user_headers":{
				"Content-Type":["text/html"],
				"Cache-Control":["no-store"]
			}
		}`))
	}, nil)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected captcha status 403, got %d", recorder.Code)
	}
	if got := recorder.Body.String(); got != "<html>captcha</html>" {
		t.Fatalf("expected appsec captcha body, got %q", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html" {
		t.Fatalf("expected Content-Type relayed, got %q", got)
	}
	if got := recorder.Header().Get("Set-Cookie"); got != "captcha=pending; Path=/; HttpOnly" {
		t.Fatalf("expected Set-Cookie relayed, got %q", got)
	}
	if got := recorder.Header().Get("X-Remediation"); got != appsec.ActionCaptcha {
		t.Fatalf("expected custom remediation header captcha, got %q", got)
	}
}

func TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus(t *testing.T) {
	banTemplate, err := template.New("ban").Parse("<html>operator ban for {{.ClientIP}}</html>")
	if err != nil {
		t.Fatal(err)
	}
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"captcha","http_status":403}`))
	}, banTemplate)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected captcha status 403, got %d", recorder.Code)
	}
	if got := recorder.Body.String(); got != "" {
		t.Fatalf("expected empty captcha body, got %q", got)
	}
	if got := recorder.Header().Get("X-Remediation"); got != appsec.ActionCaptcha {
		t.Fatalf("expected custom remediation header captcha, got %q", got)
	}
}

func TestHandleNextServeHTTPLegacyAppsecForbiddenFallsBackToBan(t *testing.T) {
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}, nil)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

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
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"ban","http_status":403,"user_body_content":"appsec default page"}`))
	}, banTemplate)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

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
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","http_status":200,"user_body_content":"<html>challenge</html>"}`))
	}, nil)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected challenge status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("challenge without a Content-Type from appsec should fall back, got %q", got)
	}
}

func TestHandleNextServeHTTPOutOfRangeStatusDoesNotPanic(t *testing.T) {
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","http_status":42,"user_body_content":"<html>challenge</html>"}`))
	}, nil)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected clamped status 403, got %d", recorder.Code)
	}
}

func TestHandleNextServeHTTPEmptyChallengeBodyBans(t *testing.T) {
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","http_status":200}`))
	}, nil)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected ban for empty challenge body, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Remediation"); got != "ban" {
		t.Fatalf("expected ban header, got %q", got)
	}
}

func TestHandleNextServeHTTPZeroStatusIs200(t *testing.T) {
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"action":"challenge","user_body_content":"<html>challenge</html>"}`))
	}, nil)
	defer appsecServer.Close()

	recorder := httptest.NewRecorder()
	b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected missing http_status to be 200, got %d", recorder.Code)
	}
}

func TestHandleNextServeHTTPAllowCallsNext(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer appsecServer.Close()
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	nextCalled := false
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}),
		log: logger.New("ERROR", ""),
	}
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	b.handleNextServeHTTP(httptest.NewRecorder(), testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))
	if !nextCalled {
		t.Fatal("next handler should be called for allow")
	}
}

// failingBodyForDisconnectTest simulates a readable POST whose Read fails mid-copy.
type failingBodyForDisconnectTest struct {
	err error
}

func (b failingBodyForDisconnectTest) Read(_ []byte) (int, error) {
	return 0, b.err
}

func (failingBodyForDisconnectTest) Close() error { return nil }

type statusWatchRecorder struct {
	*httptest.ResponseRecorder
	wroteStatus bool
}

func (r *statusWatchRecorder) WriteHeader(code int) {
	r.wroteStatus = true
	r.ResponseRecorder.WriteHeader(code)
}

// TestHandleNextServeHTTP_clientDisconnected is a regression for
// https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395
func TestHandleNextServeHTTP_clientDisconnected(t *testing.T) {
	var appsecHits int
	appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		appsecHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer appsecServer.Close()
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	traceLog := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: logger.LevelTrace}))
	lapiClient, _ := lapi.NewTestClient(logger.New("ERROR", ""))
	lapi.AttachTestMetricsReporter(lapiClient)
	nextCalled := false
	b := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			nextCalled = true
		}),
		appsecFailureAction:     configuration.FailureActionBan,
		remediationStatusCode:   http.StatusForbidden,
		remediationCustomHeader: "X-Remediation",
		log:                     traceLog,
	}
	bindTestLAPI(b, lapiClient, configuration.StreamMode)
	bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", failingBodyForDisconnectTest{err: context.Canceled})
	req.ContentLength = 100
	rw := &statusWatchRecorder{ResponseRecorder: httptest.NewRecorder()}
	b.handleNextServeHTTP(rw, testClientRequest(req, "192.0.2.10"))
	if nextCalled {
		t.Fatal("origin must not run after client disconnect")
	}
	if appsecHits != 0 {
		t.Fatalf("AppSec called %d times, want 0", appsecHits)
	}
	if rw.wroteStatus {
		t.Fatalf("must not WriteHeader; got status %d", rw.Code)
	}
	if got := rw.Header().Get("X-Remediation"); got != remediationHeaderClientDisconnected {
		t.Fatalf("header=%q want %q", got, remediationHeaderClientDisconnected)
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginAppsecFailure, "ipv4", "ban"); got != 0 {
		t.Fatalf("dropped ban count=%d want 0", got)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "client disconnected while buffering AppSec body") {
		t.Fatalf("TRACE log missing disconnect line: %s", logged)
	}

	t.Run("INFO logger stays silent", func(t *testing.T) {
		var infoBuf bytes.Buffer
		infoLog := slog.New(slog.NewJSONHandler(&infoBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		b.log = infoLog
		req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", failingBodyForDisconnectTest{err: context.Canceled})
		req.ContentLength = 100
		b.handleNextServeHTTP(httptest.NewRecorder(), testClientRequest(req, "192.0.2.10"))
		if infoBuf.Len() != 0 {
			t.Fatalf("INFO log should be empty, got %s", infoBuf.String())
		}
	})
}

func TestTwoBouncersDistinctLapiFailureActions(t *testing.T) {
	shared := &lapi.Client{}
	passthroughCalled := false
	passthrough := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passthroughCalled = true
		}),
		log:               logger.New("ERROR", ""),
		lapiFailureAction: configuration.FailureActionPassthrough,
	}
	bindTestLAPI(passthrough, shared, configuration.StreamMode)
	ban := &Bouncer{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("ban bouncer must not call next")
		}),
		remediationStatusCode: http.StatusForbidden,
		log:                   logger.New("ERROR", ""),
		lapiFailureAction:     configuration.FailureActionBan,
	}
	bindTestLAPI(ban, shared, configuration.StreamMode)
	if !passthrough.SameLapiClient(ban) {
		t.Fatal("both bouncers must share one Client")
	}
	passthrough.applyLapiFailureAction(httptest.NewRecorder(), testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10"), configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
	if !passthroughCalled {
		t.Fatal("passthrough bouncer must use the pass path")
	}
	recorder := httptest.NewRecorder()
	ban.applyLapiFailureAction(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10"), configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("ban want 403, got %d", recorder.Code)
	}
}

func TestApplyLapiFailureAction(t *testing.T) {
	t.Run("passthrough calls next", func(t *testing.T) {
		nextCalled := false
		b := &Bouncer{
			next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}),
			log:               logger.New("ERROR", ""),
			lapiFailureAction: configuration.FailureActionPassthrough,
		}
		b.applyLapiFailureAction(httptest.NewRecorder(), testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10"), configuration.ReasonTECH, lapi.OriginPluginTechStreamFail)
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
			lapiFailureAction:     configuration.FailureActionBan,
		}
		recorder := httptest.NewRecorder()
		b.applyLapiFailureAction(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), "192.0.2.10"), configuration.ReasonLAPI, lapi.OriginPluginLapiFailure)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("ban want 403, got %d", recorder.Code)
		}
	})
}

func TestHandleNextServeHTTPAppsecFailureAction(t *testing.T) {
	t.Run("500 passthrough calls next", func(t *testing.T) {
		appsecServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer appsecServer.Close()
		appsecURL, err := url.Parse(appsecServer.URL)
		if err != nil {
			t.Fatal(err)
		}
		nextCalled := false
		b := &Bouncer{
			next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			}),
			appsecFailureAction: configuration.FailureActionPassthrough,
			log:                 logger.New("ERROR", ""),
		}
		bindTestAppSec(b, appsec.NewTestClient(appsecURL, appsecServer.Client(), logger.New("ERROR", "")))
		b.handleNextServeHTTP(httptest.NewRecorder(), testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))
		if !nextCalled {
			t.Fatal("passthrough on AppSec 500 should call next")
		}
	})
	t.Run("500 ban forbids", func(t *testing.T) {
		b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}, nil)
		defer appsecServer.Close()
		b.appsecFailureAction = configuration.FailureActionBan
		recorder := httptest.NewRecorder()
		b.handleNextServeHTTP(recorder, testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil), "192.0.2.10"))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("ban on AppSec 500 want 403, got %d", recorder.Code)
		}
	})
}

func TestNewForwardedHeadersInsecureHeaderName(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	log := logger.New("ERROR", "")
	t.Run("default custom name becomes X-Real-Ip", func(t *testing.T) {
		cfg := configuration.New()
		cfg.CrowdsecMode = configuration.StreamMode
		cfg.ForwardedHeadersInsecure = true
		handler, err := New(next, "test", cfg, false, true, log)
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		b, ok := handler.(*Bouncer)
		if !ok {
			t.Fatalf("handler type %T want *Bouncer", handler)
		}
		if b.forwardedCustomHeader != "X-Real-Ip" {
			t.Fatalf("forwardedCustomHeader = %q want X-Real-Ip", b.forwardedCustomHeader)
		}
	})
	t.Run("explicit non-default name is passed through", func(t *testing.T) {
		cfg := configuration.New()
		cfg.CrowdsecMode = configuration.StreamMode
		cfg.ForwardedHeadersInsecure = true
		cfg.ForwardedHeadersCustomName = "CF-Connecting-IP"
		handler, err := New(next, "test", cfg, false, true, log)
		if err != nil {
			t.Fatalf("New = %v", err)
		}
		b, ok := handler.(*Bouncer)
		if !ok {
			t.Fatalf("handler type %T want *Bouncer", handler)
		}
		if b.forwardedCustomHeader != "CF-Connecting-IP" {
			t.Fatalf("forwardedCustomHeader = %q want CF-Connecting-IP", b.forwardedCustomHeader)
		}
	})
}
