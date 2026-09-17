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

	emptyChecker, err := NewChecker(log, []string{})
	if err != nil {
		t.Fatal(err)
	}
	emptyStrategy := &PoolStrategy{Checker: emptyChecker}

	tests := []struct {
		name       string
		remoteAddr string
		headerName string
		headerVal  string
		strategy   *PoolStrategy
		wantIP     string
		wantParsed bool
		wantErr    bool
	}{
		{
			name:       "trusted hops skipped, client kept",
			remoteAddr: trustedProxyAddr,
			headerName: "X-Forwarded-For",
			headerVal:  "203.0.113.10, 10.0.0.1",
			strategy:   strategy,
			wantIP:     "203.0.113.10",
			wantParsed: true,
		},
		{
			name:       "untrusted RemoteAddr ignores forged header",
			remoteAddr: "198.51.100.5:443",
			headerName: "X-Forwarded-For",
			headerVal:  "203.0.113.10, 10.0.0.1",
			strategy:   strategy,
			wantIP:     "198.51.100.5",
			wantParsed: true,
		},
		{
			name:       "empty trusted pool ignores header",
			remoteAddr: "198.51.100.5:443",
			headerName: "X-Forwarded-For",
			headerVal:  "203.0.113.10",
			strategy:   emptyStrategy,
			wantIP:     "198.51.100.5",
			wantParsed: true,
		},
		{
			name:       "empty header uses RemoteAddr",
			remoteAddr: "192.0.2.1:12345",
			headerName: "X-Forwarded-For",
			strategy:   strategy,
			wantIP:     "192.0.2.1",
			wantParsed: true,
		},
		{
			name:       "all hops trusted uses RemoteAddr",
			remoteAddr: "192.0.2.9:80",
			headerName: "X-Forwarded-For",
			headerVal:  "10.0.0.1",
			strategy:   strategy,
			wantIP:     "192.0.2.9",
			wantParsed: true,
		},
		{
			name:       "empty header segments skipped",
			remoteAddr: trustedProxyAddr,
			headerName: "X-Forwarded-For",
			headerVal:  "203.0.113.10, , 10.0.0.1",
			strategy:   strategy,
			wantIP:     "203.0.113.10",
			wantParsed: true,
		},
		{
			name:       "custom header name",
			remoteAddr: trustedProxyAddr,
			headerName: "X-Real-IP",
			headerVal:  "203.0.113.10, 10.0.0.1",
			strategy:   strategy,
			wantIP:     "203.0.113.10",
			wantParsed: true,
		},
		{
			name:       "malformed hop between trusted and client fails closed",
			remoteAddr: trustedProxyAddr,
			headerName: "X-Forwarded-For",
			headerVal:  "203.0.113.10, not-an-ip, 10.0.0.1",
			strategy:   strategy,
			wantIP:     "not-an-ip",
			wantParsed: false,
		},
		{
			name:       "malformed rightmost hop fails closed",
			remoteAddr: trustedProxyAddr,
			headerName: "X-Forwarded-For",
			headerVal:  "bad-hop",
			strategy:   strategy,
			wantIP:     "bad-hop",
			wantParsed: false,
		},
		{
			name:       "port suffixed hop fails closed",
			remoteAddr: trustedProxyAddr,
			headerName: "X-Forwarded-For",
			headerVal:  "203.0.113.10:443, 10.0.0.1",
			strategy:   strategy,
			wantIP:     "203.0.113.10:443",
			wantParsed: false,
		},
		{
			name:       "RemoteAddr without port fails",
			remoteAddr: "192.0.2.1",
			headerName: "X-Forwarded-For",
			strategy:   strategy,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newTestTrustRequest(tc.remoteAddr, tc.headerName, tc.headerVal)
			got, parsed, err := GetRemoteIP(req, tc.strategy, tc.headerName)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("GetRemoteIP = %q, %v", got, err)
			}
			if got != tc.wantIP {
				t.Fatalf("GetRemoteIP = %q want %q", got, tc.wantIP)
			}
			if tc.wantParsed && parsed == nil {
				t.Fatalf("GetRemoteIP parsed = nil want non-nil for %q", got)
			}
			if !tc.wantParsed && parsed != nil {
				t.Fatalf("GetRemoteIP parsed = %v want nil for %q", parsed, got)
			}
		})
	}
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
