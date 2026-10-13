package ip

import (
	"net"
	"testing"
)

func TestFamily(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"1.2.3.4", "ipv4"},
		{" 1.2.3.4 ", "ipv4"},
		{"2001:db8::1", "ipv6"},
		{"", ""},
		{"not-an-ip", ""},
	}
	for _, tt := range tests {
		if got := Family(tt.in); got != tt.want {
			t.Errorf("Family(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if got := FamilyOfIP(nil); got != "" {
		t.Errorf("FamilyOfIP(nil) = %q, want empty", got)
	}
	if got := FamilyOfIP(net.ParseIP("2001:db8::2")); got != "ipv6" {
		t.Errorf("FamilyOfIP(ipv6) = %q", got)
	}
}

func TestFamilyOfHostOrCIDR(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"10.1.2.3", "ipv4"},
		{"10.0.0.0/8", "ipv4"},
		{"2001:db8::/32", "ipv6"},
		{"2001:db8::1", "ipv6"},
		{"", ""},
		{"not-a-network", ""},
	}
	for _, tt := range tests {
		if got := FamilyOfHostOrCIDR(tt.in); got != tt.want {
			t.Errorf("FamilyOfHostOrCIDR(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
