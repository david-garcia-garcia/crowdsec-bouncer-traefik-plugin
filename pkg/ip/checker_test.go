package ip

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckerContains(t *testing.T) {
	log := slog.Default()

	t.Run("CIDR hit and miss", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"10.0.0.0/8"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("10.1.2.3")
		if err != nil || !ok {
			t.Fatalf("Contains 10.1.2.3 = %v, %v want true", ok, err)
		}
		ok, err = checker.Contains("203.0.113.10")
		if err != nil || ok {
			t.Fatalf("Contains 203.0.113.10 = %v, %v want false", ok, err)
		}
	})

	t.Run("bare host", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("192.0.2.1")
		if err != nil || !ok {
			t.Fatalf("Contains bare host = %v, %v want true", ok, err)
		}
		ok, err = checker.Contains("192.0.2.2")
		if err != nil || ok {
			t.Fatalf("Contains other host = %v, %v want false", ok, err)
		}
	})

	t.Run("overlapping any-match", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"192.168.0.0/16", "192.168.1.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("192.168.1.5")
		if err != nil || !ok {
			t.Fatalf("Contains overlapping = %v, %v want true", ok, err)
		}
	})

	t.Run("empty list", func(t *testing.T) {
		checker, err := NewChecker(log, []string{})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("10.1.2.3")
		if err != nil || ok {
			t.Fatalf("empty Contains = %v, %v want false", ok, err)
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		_, err := NewChecker(log, []string{"192.168.1.0/33"})
		if err == nil {
			t.Fatal("expected error for 192.168.1.0/33")
		}
	})
}

func TestCheckerContainsCatchAllFamily(t *testing.T) {
	log := slog.Default()

	t.Run("IPv4 catch-all does not match IPv6", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"0.0.0.0/0"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("2001:db8::1")
		if err != nil || ok {
			t.Fatalf("Contains IPv6 under 0.0.0.0/0 = %v, %v want false", ok, err)
		}
		ok, err = checker.Contains("203.0.113.10")
		if err != nil || !ok {
			t.Fatalf("Contains IPv4 under 0.0.0.0/0 = %v, %v want true", ok, err)
		}
	})

	t.Run("IPv6 catch-all does not match IPv4", func(t *testing.T) {
		checker, err := NewChecker(log, []string{"::/0"})
		if err != nil {
			t.Fatal(err)
		}
		ok, err := checker.Contains("203.0.113.10")
		if err != nil || ok {
			t.Fatalf("Contains IPv4 under ::/0 = %v, %v want false", ok, err)
		}
		ok, err = checker.Contains("2001:db8::1")
		if err != nil || !ok {
			t.Fatalf("Contains IPv6 under ::/0 = %v, %v want true", ok, err)
		}
	})
}

// TestGetRemoteIP covers the forwarded-header walk, RemoteAddr gate, and fallback.
func TestGetRemoteIP(t *testing.T) {
	log := slog.Default()
	hopChecker, err := NewChecker(log, []string{"10.0.0.1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	strategy := &PoolStrategy{Checker: hopChecker}
	trustedProxyAddr := "10.0.0.1:443"

	t.Run("trusted hops skipped, client kept", func(t *testing.T) {
		req := newTestTrustRequest(trustedProxyAddr, "X-Forwarded-For", "203.0.113.10, 10.0.0.1")
		got, _, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "203.0.113.10" {
			t.Fatalf("GetRemoteIP = %q, %v want 203.0.113.10", got, err)
		}
	})

	t.Run("untrusted RemoteAddr ignores forged header", func(t *testing.T) {
		req := newTestTrustRequest("198.51.100.5:443", "X-Forwarded-For", "203.0.113.10, 10.0.0.1")
		got, _, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "198.51.100.5" {
			t.Fatalf("GetRemoteIP = %q, %v want 198.51.100.5", got, err)
		}
	})

	t.Run("empty trusted pool ignores header", func(t *testing.T) {
		emptyChecker, err := NewChecker(log, []string{})
		if err != nil {
			t.Fatal(err)
		}
		emptyStrategy := &PoolStrategy{Checker: emptyChecker}
		req := newTestTrustRequest("198.51.100.5:443", "X-Forwarded-For", "203.0.113.10")
		got, _, err := GetRemoteIP(req, emptyStrategy, "X-Forwarded-For")
		if err != nil || got != "198.51.100.5" {
			t.Fatalf("GetRemoteIP = %q, %v want 198.51.100.5", got, err)
		}
	})

	t.Run("empty header uses RemoteAddr", func(t *testing.T) {
		req := newTestTrustRequest("192.0.2.1:12345", "X-Forwarded-For", "")
		got, _, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "192.0.2.1" {
			t.Fatalf("GetRemoteIP = %q, %v want 192.0.2.1", got, err)
		}
	})

	t.Run("all hops trusted uses RemoteAddr", func(t *testing.T) {
		req := newTestTrustRequest("192.0.2.9:80", "X-Forwarded-For", "10.0.0.1")
		got, _, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "192.0.2.9" {
			t.Fatalf("GetRemoteIP = %q, %v want 192.0.2.9", got, err)
		}
	})

	t.Run("empty header segments skipped", func(t *testing.T) {
		req := newTestTrustRequest(trustedProxyAddr, "X-Forwarded-For", "203.0.113.10, , 10.0.0.1")
		got, _, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "203.0.113.10" {
			t.Fatalf("GetRemoteIP = %q, %v want 203.0.113.10", got, err)
		}
	})

	t.Run("custom header name", func(t *testing.T) {
		req := newTestTrustRequest(trustedProxyAddr, "X-Real-IP", "203.0.113.10, 10.0.0.1")
		got, _, err := GetRemoteIP(req, strategy, "X-Real-IP")
		if err != nil || got != "203.0.113.10" {
			t.Fatalf("GetRemoteIP custom header = %q, %v want 203.0.113.10", got, err)
		}
	})

	t.Run("malformed hop between trusted and client fails closed", func(t *testing.T) {
		req := newTestTrustRequest(trustedProxyAddr, "X-Forwarded-For", "203.0.113.10, not-an-ip, 10.0.0.1")
		got, parsed, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "not-an-ip" || parsed != nil {
			t.Fatalf("GetRemoteIP = %q, parsed=%v, %v want not-an-ip, nil", got, parsed, err)
		}
	})

	t.Run("malformed rightmost hop fails closed", func(t *testing.T) {
		req := newTestTrustRequest(trustedProxyAddr, "X-Forwarded-For", "bad-hop")
		got, parsed, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "bad-hop" || parsed != nil {
			t.Fatalf("GetRemoteIP = %q, parsed=%v, %v want bad-hop, nil", got, parsed, err)
		}
	})

	t.Run("port suffixed hop fails closed", func(t *testing.T) {
		req := newTestTrustRequest(trustedProxyAddr, "X-Forwarded-For", "203.0.113.10:443, 10.0.0.1")
		got, parsed, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err != nil || got != "203.0.113.10:443" || parsed != nil {
			t.Fatalf("GetRemoteIP = %q, parsed=%v, %v want 203.0.113.10:443, nil", got, parsed, err)
		}
	})

	t.Run("RemoteAddr without port fails", func(t *testing.T) {
		req := newTestTrustRequest("192.0.2.1", "X-Forwarded-For", "")
		_, _, err := GetRemoteIP(req, strategy, "X-Forwarded-For")
		if err == nil {
			t.Fatal("expected error for RemoteAddr without port")
		}
	})
}

// newTestTrustRequest builds a request with RemoteAddr and an optional forwarded header.
func newTestTrustRequest(remoteAddr, headerName, headerVal string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = remoteAddr
	if headerVal != "" {
		req.Header.Set(headerName, headerVal)
	}
	return req
}
