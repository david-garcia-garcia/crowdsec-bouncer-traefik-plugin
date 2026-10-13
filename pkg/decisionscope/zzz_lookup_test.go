package decisionscope

import (
	"reflect"
	"testing"
)

func TestRemediationValue(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"ban", BannedValue},
		{"captcha", CaptchaValue},
		{"BAN", ""},
		{"", ""},
		{"allow", ""},
	}
	for _, tt := range tests {
		if got := RemediationValue(tt.in); got != tt.want {
			t.Errorf("RemediationValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsActiveRemediation(t *testing.T) {
	if !IsActiveRemediation(BannedValue) || !IsActiveRemediation(CaptchaValue) {
		t.Fatal("ban and captcha letters are active")
	}
	for _, inactive := range []string{NoBannedValue, "", "ban", "allow"} {
		if IsActiveRemediation(inactive) {
			t.Errorf("IsActiveRemediation(%q) = true, want false", inactive)
		}
	}
}

func TestPreferRemediation(t *testing.T) {
	tests := []struct {
		current, incoming, want string
	}{
		{BannedValue, CaptchaValue, BannedValue},
		{CaptchaValue, BannedValue, BannedValue},
		{CaptchaValue, "", CaptchaValue},
		{"", CaptchaValue, CaptchaValue},
		{"", "", ""},
		{NoBannedValue, CaptchaValue, CaptchaValue},
		{"t:cscli", CaptchaValue, "t:cscli"},
	}
	for _, tt := range tests {
		if got := PreferRemediation(tt.current, tt.incoming); got != tt.want {
			t.Errorf("PreferRemediation(%q, %q) = %q, want %q", tt.current, tt.incoming, got, tt.want)
		}
	}
}

func TestCanonicalStreamScopes(t *testing.T) {
	got := CanonicalStreamScopes([]string{"Country", "country", " ip ", "", "AS"})
	want := []string{"ip", "range", "as", "country"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CanonicalStreamScopes = %v, want %v", got, want)
	}
	if query := StreamScopeQuery([]string{"username", "country"}); query != "ip,range,country,username" {
		t.Fatalf("StreamScopeQuery = %q", query)
	}
}

func TestStreamScopeList(t *testing.T) {
	got := StreamScopeList(map[string]string{
		ScopeAS:      "CF-ASN",
		ScopeCountry: "CF-IPCountry",
		"username":   "X-User",
	})
	if got != "ip,range,AS,country,username" {
		t.Fatalf("StreamScopeList = %q", got)
	}
}

func TestMissingStreamScopes(t *testing.T) {
	headers := map[string]string{
		ScopeCountry: "CF-IPCountry",
		ScopeAS:      "CF-ASN",
		"username":   "X-User",
	}
	got := MissingStreamScopes(headers, []string{"country", "as"})
	want := []string{"username"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingStreamScopes = %v, want %v", got, want)
	}
	if missing := MissingStreamScopes(nil, nil); len(missing) != 0 {
		t.Fatalf("empty headers missing = %v", missing)
	}
}
