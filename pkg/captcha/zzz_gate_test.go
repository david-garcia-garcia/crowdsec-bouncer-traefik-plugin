package captcha

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// issuedGateCookie calls setGateCookie and returns the cookie written to rw.
func issuedGateCookie(t *testing.T, req *http.Request) *http.Cookie {
	t.Helper()
	rw := httptest.NewRecorder()
	setGateCookie(rw, req, "v", 60)
	cookies := rw.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].Name != gateCookieName {
		t.Fatalf("cookie name %q", cookies[0].Name)
	}
	return cookies[0]
}

func Test_validateGateValue_bindIP(t *testing.T) {
	secret := []byte("test-secret")
	now := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, true, "203.0.113.5", now)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: gateCookieName, Value: value})
	if !validateGateValue(secret, true, "203.0.113.5", value, now.Add(time.Minute), 3600) {
		t.Fatal("expected valid gate within grace")
	}
	if validateGateValue(secret, true, "203.0.113.6", value, now.Add(time.Minute), 3600) {
		t.Fatal("expected IP mismatch to fail")
	}
}

func Test_validateGateValue_cookieOnly(t *testing.T) {
	secret := []byte("cookie-only")
	now := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, false, "203.0.113.5", now)
	if !validateGateValue(secret, false, "198.51.100.1", value, now.Add(time.Minute), 3600) {
		t.Fatal("cookie-only should ignore client IP")
	}
}

func Test_validateGateValue_expired(t *testing.T) {
	secret := []byte("exp")
	issued := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, true, "10.0.0.1", issued)
	afterGrace := issued.Add(2 * time.Hour)
	if validateGateValue(secret, true, "10.0.0.1", value, afterGrace, 60) {
		t.Fatal("expected expiry failure")
	}
}

func Test_validateGateValue_tamper(t *testing.T) {
	secret := []byte("tamper")
	now := time.Unix(1_700_000_000, 0)
	value := mintGateValue(secret, true, "10.0.0.1", now) + "x"
	if validateGateValue(secret, true, "10.0.0.1", value, now, 3600) {
		t.Fatal("tampered value should fail")
	}
}

func Test_Check_readsCookie(t *testing.T) {
	secret := []byte("check")
	now := time.Now()
	client := &Client{
		Valid:              true,
		gateSecret:         secret,
		gateBindIP:         true,
		gracePeriodSeconds: 3600,
		log:                slog.Default(),
	}
	value := mintGateValue(secret, true, "10.0.0.2", now)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: gateCookieName, Value: value})
	if !client.Check(req, "10.0.0.2") {
		t.Fatal("Check should accept valid cookie")
	}
}

func Test_setGateCookie_forwardedHTTPSSetsSecure(t *testing.T) {
	for _, proto := range []string{"https", "HTTPS", " https "} {
		t.Run(proto, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Forwarded-Proto", proto)
			cookie := issuedGateCookie(t, req)
			if !cookie.Secure {
				t.Fatalf("Secure=false for proto %q", proto)
			}
		})
	}
}

func Test_setGateCookie_connectionTLSSetsSecure(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	cookie := issuedGateCookie(t, req)
	if !cookie.Secure {
		t.Fatal("Secure=false when request TLS is set")
	}
}

func Test_setGateCookie_httpOrAbsentProtoOmitsSecure(t *testing.T) {
	cases := []struct {
		name      string
		setHeader bool
		proto     string
	}{
		{name: "http", setHeader: true, proto: "http"},
		{name: "wss", setHeader: true, proto: "wss"},
		{name: "absent", setHeader: false},
		{name: "empty", setHeader: true, proto: ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if testCase.setHeader {
				req.Header.Set("X-Forwarded-Proto", testCase.proto)
			}
			cookie := issuedGateCookie(t, req)
			if cookie.Secure {
				t.Fatalf("Secure=true for proto case %s", testCase.name)
			}
		})
	}
}
