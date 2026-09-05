package decisionscope

import (
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

func TestIPCacheKey(t *testing.T) {
	if got := IPCacheKey("1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("bare IP: %q", got)
	}
	if got := IPCacheKey("10.0.0.1/32"); got != "10.0.0.1" {
		t.Fatalf("/32: %q", got)
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
