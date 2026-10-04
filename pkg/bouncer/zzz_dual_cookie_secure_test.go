package bouncer

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// TestDualCookieSecureFollowsConstructorScheme checks both cookies' Secure under proto and TLS.
func TestDualCookieSecureFollowsConstructorScheme(t *testing.T) {
	cases := []struct {
		name   string
		proto  string
		tlsOn  bool
		secure bool
	}{
		{name: "https proto", proto: "https", secure: true},
		{name: "TLS fallback", tlsOn: true, secure: true},
		{name: "http proto", proto: "http", tlsOn: true, secure: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assertChallengeCookieSecure(t, testCase.proto, testCase.tlsOn, testCase.secure)
			assertGateCookieSecure(t, testCase.proto, testCase.tlsOn, testCase.secure)
		})
	}
}

// originFormRequest is a Traefik-like request: empty URL.Scheme and URL.Host, Host set.
func originFormRequest(method, path string, body io.Reader, proto string, tlsOn bool) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Host = "app.example"
	req.URL.Scheme = ""
	req.URL.Host = ""
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	if tlsOn {
		req.TLS = &tls.ConnectionState{}
	}
	return req
}

// cookieNamed returns the first cookie with name, or nil.
func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// assertChallengeCookieSecure drives AppSec challenge relay and checks __crowdsec_challenge.Secure.
func assertChallengeCookieSecure(t *testing.T, proto string, tlsOn, wantSecure bool) {
	t.Helper()
	b, appsecServer := testBouncerWithAppsec(t, func(w http.ResponseWriter, r *http.Request) {
		parsed, err := url.Parse(r.Header.Get("X-Crowdsec-Appsec-Uri"))
		cookie := "__crowdsec_challenge=e2e; Path=/; HttpOnly"
		if err == nil && parsed.Scheme == "https" {
			cookie += "; Secure"
		}
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"action":            "challenge",
			"http_status":       200,
			"user_body_content": "<html>challenge</html>",
			"user_cookies":      []string{cookie},
		})
	}, nil)
	t.Cleanup(appsecServer.Close)

	req := originFormRequest(http.MethodGet, "/protected", nil, proto, tlsOn)
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(req, "192.0.2.10"))
	got := cookieNamed(rw.Result().Cookies(), "__crowdsec_challenge")
	if got == nil {
		t.Fatal("missing __crowdsec_challenge")
	}
	if got.Secure != wantSecure {
		t.Fatalf("__crowdsec_challenge Secure=%v want %v", got.Secure, wantSecure)
	}
}

// assertGateCookieSecure drives a captcha solve through the plugin and checks crowdsec_captcha_gate.Secure.
func assertGateCookieSecure(t *testing.T, proto string, tlsOn, wantSecure bool) {
	t.Helper()
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)
	client := testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
	b, _ := testCaptchaRoutingBouncer(t, client)

	form := url.Values{}
	form.Set("dummy-captcha-response", "ok")
	req := originFormRequest(http.MethodPost, "/protected", strings.NewReader(form.Encode()), proto, tlsOn)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	b.handleRemediationServeHTTP(rw, testClientRequest(req, testCaptchaRemoteIP), decisionscope.CaptchaValue, "cscli")
	got := cookieNamed(rw.Result().Cookies(), "crowdsec_captcha_gate")
	if got == nil {
		t.Fatal("missing crowdsec_captcha_gate")
	}
	if got.Secure != wantSecure {
		t.Fatalf("crowdsec_captcha_gate Secure=%v want %v", got.Secure, wantSecure)
	}
}
