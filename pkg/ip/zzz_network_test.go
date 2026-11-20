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

// TestMaskPrefix proves each family uses its own prefix, IPv4-mapped IPv6 uses the IPv4 prefix,
// and 0 keeps the full address.
func TestMaskPrefix(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		ipv4Prefix int
		ipv6Prefix int
		want       string
	}{
		{name: "ipv4 /24", addr: "198.51.100.77", ipv4Prefix: 24, ipv6Prefix: 64, want: "198.51.100.0"},
		{name: "ipv6 /64", addr: "2001:db8:1:2:aaaa::1", ipv4Prefix: 24, ipv6Prefix: 64, want: "2001:db8:1:2::"},
		{name: "ipv4-mapped uses ipv4 prefix", addr: "::ffff:198.51.100.77", ipv4Prefix: 16, ipv6Prefix: 64, want: "198.51.0.0"},
		{name: "ipv4 zero keeps the address", addr: "198.51.100.77", ipv6Prefix: 64, want: "198.51.100.77"},
		{name: "ipv6 zero keeps the address", addr: "2001:db8::1", ipv4Prefix: 24, want: "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskPrefix(net.ParseIP(tt.addr), tt.ipv4Prefix, tt.ipv6Prefix)
			if got.String() != tt.want {
				t.Fatalf("MaskPrefix(%s, %d, %d)=%s want %s", tt.addr, tt.ipv4Prefix, tt.ipv6Prefix, got, tt.want)
			}
		})
	}
	if MaskPrefix(nil, 24, 64) != nil {
		t.Fatal("nil must stay nil")
	}
}
