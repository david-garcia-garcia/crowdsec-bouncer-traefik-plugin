package decisionstore

import (
	"net"
	"testing"
)

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
