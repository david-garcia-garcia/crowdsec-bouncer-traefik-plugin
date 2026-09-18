package decisionscope

import (
	"net"
	"net/http"
	"testing"
)

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ip", ScopeIP},
		{"IP", ScopeIP},
		{"range", ScopeRange},
		{"country", ScopeCountry},
		{"as", ScopeAS},
		{"AS", ScopeAS},
		{"username", "username"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NormalizeScope(tt.in); got != tt.want {
			t.Errorf("NormalizeScope(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeCountry(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"fr", "FR"},
		{"FR", "FR"},
		{" XX ", ""},
		{"T1", ""},
		{"USA", ""},
		{"12", ""},
		{"", ""},
		{"F", ""},
	}
	for _, tt := range tests {
		if got := NormalizeCountry(tt.in); got != tt.want {
			t.Errorf("NormalizeCountry(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeASN(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"13335", "13335"},
		{"AS13335", "13335"},
		{"as13335", "13335"},
		{"AS 13335", "13335"},
		{" 13335 ", "13335"},
		{"", ""},
		{"AS", ""},
		{"AS-1", ""},
	}
	for _, tt := range tests {
		if got := NormalizeASN(tt.in); got != tt.want {
			t.Errorf("NormalizeASN(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeDecisionScopeHeaders(t *testing.T) {
	got := NormalizeDecisionScopeHeaders(map[string]string{
		"country":  "CF-IPCountry",
		"AS":       "CF-ASN",
		"username": "X-User",
		"ip":       "X-Real-IP",
		"range":    "X-Range",
		"":         "X-Empty",
		"session":  "  ",
	})
	if got[ScopeCountry] != "CF-IPCountry" || got[ScopeAS] != "CF-ASN" || got["username"] != "X-User" {
		t.Fatalf("kept scopes: %+v", got)
	}
	if _, ok := got[ScopeIP]; ok {
		t.Fatal("ip must be dropped")
	}
	if _, ok := got[ScopeRange]; ok {
		t.Fatal("range must be dropped")
	}
	if _, ok := got["session"]; ok {
		t.Fatal("empty header must be dropped")
	}
}

// TestIPCacheKey covers the spellings CrowdSec was measured to hand back verbatim on the stream:
// expanded, upper-case, and IPv4-mapped forms all have to land on one key.
func TestIPCacheKey(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1.2.3.4", "1.2.3.4"},
		{"10.0.0.1/32", "10.0.0.1"},
		{"2001:db8::1/128", "2001:db8::1"},
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"2001:DB8::2", "2001:db8::2"},
		{"::ffff:192.0.2.4", "192.0.2.4"},
		{" 1.2.3.4 ", "1.2.3.4"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"not-an-address", "not-an-address"},
	}
	for _, tt := range tests {
		if got := IPCacheKey(tt.in); got != tt.want {
			t.Errorf("IPCacheKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCanonicalRemoteIPAgreesWithStore is the request-path invariant after canonicalize-at-origin:
// ServeHTTP sets remoteIP to ipAddr.String(), and that string is the lookup key. It must match
// IPCacheKey of every spelling of the same address (unparseable values never reach lookup).
func TestCanonicalRemoteIPAgreesWithStore(t *testing.T) {
	addresses := []string{
		"1.2.3.4",
		"2001:db8::1",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"2001:DB8::2",
		"::ffff:192.0.2.4",
	}
	for _, address := range addresses {
		ipAddr := net.ParseIP(address)
		if ipAddr == nil {
			t.Fatalf("parse %q", address)
		}
		lookup := ipAddr.String()
		if store := IPCacheKey(address); lookup != store {
			t.Errorf("%q: lookup key %q, store key %q", address, lookup, store)
		}
	}
}

func TestRequestScopeValuesSkipsMissingHeader(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	req.Header.Set("Cf-Ipcountry", "fr")
	got := RequestScopeValues(map[string]string{ScopeCountry: "CF-IPCountry", ScopeAS: "CF-ASN"}, req)
	if got[ScopeCountry] != "FR" {
		t.Fatalf("Country: %+v", got)
	}
	if _, ok := got[ScopeAS]; ok {
		t.Fatal("missing AS header must be skipped")
	}
}
