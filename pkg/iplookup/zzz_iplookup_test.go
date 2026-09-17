package iplookup

import (
	"net"
	"testing"
)

func TestHelper_IPv4(t *testing.T) {
	cidrBlocks := []string{
		"192.168.1.0/24",
		"10.0.0.0/8",
		"203.0.113.0/24",
		"198.51.100.0/24",
		"192.168.1.10/32",
	}

	helper, err := NewHelper(cidrBlocks)
	if err != nil {
		t.Fatalf("Failed to create Helper: %v", err)
	}

	tests := []struct {
		name           string
		ip             string
		shouldMatch    bool
		expectedPrefix int
	}{
		{"IP in 192.168.1.0/24", "192.168.1.5", true, 24},
		{"Specific IP 192.168.1.10/32", "192.168.1.10", true, 32},
		{"IP in 10.0.0.0/8", "10.5.10.15", true, 8},
		{"IP in test network", "203.0.113.100", true, 24},
		{"IP not in any range", "8.8.8.8", false, 0},
		{"IP not in any range 1.1.1.1", "1.1.1.1", false, 0},
		{"Edge of range", "192.168.1.255", true, 24},
		{"Just outside range", "192.168.2.1", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}

			found, prefixLen, err := helper.IsContained(ip)
			if err != nil {
				t.Errorf("IsContained returned error: %v", err)
			}

			if found != tt.shouldMatch {
				t.Errorf("IsContained(%s) = %v, want %v", tt.ip, found, tt.shouldMatch)
			}

			if found && prefixLen != tt.expectedPrefix {
				t.Errorf("IsContained(%s) prefix = %d, want %d", tt.ip, prefixLen, tt.expectedPrefix)
			}
		})
	}
}

func TestHelper_IPv6(t *testing.T) {
	cidrBlocks := []string{
		"2001:db8::/32",
		"fe80::/10",
		"::1/128",
		"2001:db8:85a3::/48",
		"2001:db8:85a3:8d3::/64",
	}

	helper, err := NewHelper(cidrBlocks)
	if err != nil {
		t.Fatalf("Failed to create Helper: %v", err)
	}

	tests := []struct {
		name           string
		ip             string
		shouldMatch    bool
		expectedPrefix int
	}{
		{"IPv6 localhost", "::1", true, 128},
		{"IPv6 in 2001:db8::/32", "2001:db8:1234:5678::1", true, 32},
		{"IPv6 in more specific subnet", "2001:db8:85a3:1234::1", true, 48},
		{"IPv6 in most specific subnet", "2001:db8:85a3:8d3:1234::1", true, 64},
		{"IPv6 link-local", "fe80::1", true, 10},
		{"IPv6 not in any range", "2001:db9::1", false, 0},
		{"IPv6 global unicast not in range", "2a00:1450:4001::1", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}

			found, prefixLen, err := helper.IsContained(ip)
			if err != nil {
				t.Errorf("IsContained returned error: %v", err)
			}

			if found != tt.shouldMatch {
				t.Errorf("IsContained(%s) = %v, want %v", tt.ip, found, tt.shouldMatch)
			}

			if found && prefixLen != tt.expectedPrefix {
				t.Errorf("IsContained(%s) prefix = %d, want %d", tt.ip, prefixLen, tt.expectedPrefix)
			}
		})
	}
}

func TestHelper_MixedIPv4AndIPv6(t *testing.T) {
	cidrBlocks := []string{
		"192.168.1.0/24",
		"2001:db8::/32",
		"10.0.0.0/8",
		"::1/128",
	}

	helper, err := NewHelper(cidrBlocks)
	if err != nil {
		t.Fatalf("Failed to create Helper: %v", err)
	}

	tests := []struct {
		name        string
		ip          string
		shouldMatch bool
	}{
		{"IPv4 in range", "192.168.1.100", true},
		{"IPv4 not in range", "8.8.8.8", false},
		{"IPv6 in range", "2001:db8::1", true},
		{"IPv6 not in range", "2001:db9::1", false},
		{"IPv6 localhost", "::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}

			found, _, err := helper.IsContained(ip)
			if err != nil {
				t.Errorf("IsContained returned error: %v", err)
			}

			if found != tt.shouldMatch {
				t.Errorf("IsContained(%s) = %v, want %v", tt.ip, found, tt.shouldMatch)
			}
		})
	}
}

func TestHelper_EmptyHelper(t *testing.T) {
	helper, err := NewHelper([]string{})
	if err != nil {
		t.Fatalf("Failed to create empty Helper: %v", err)
	}

	testIPs := []string{"192.168.1.1", "8.8.8.8", "::1", "2001:db8::1"}

	for _, ipStr := range testIPs {
		t.Run("Empty_helper_"+ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", ipStr)
			}

			found, prefixLen, err := helper.IsContained(ip)
			if err != nil {
				t.Errorf("IsContained returned error: %v", err)
			}

			if found {
				t.Errorf("Empty helper should not match any IP, but matched %s with prefix %d", ipStr, prefixLen)
			}
		})
	}
}

func TestHelper_InvalidCIDR(t *testing.T) {
	invalidCIDRs := []string{
		"invalid-cidr",
		"192.168.1.0/33",
		"2001:db8::/129",
		"192.168.1",
		"",
	}

	for _, cidr := range invalidCIDRs {
		t.Run("Invalid_CIDR_"+cidr, func(t *testing.T) {
			_, err := NewHelper([]string{cidr})
			if err == nil {
				t.Errorf("Expected error for invalid CIDR %s, but got none", cidr)
			}
		})
	}
}

func TestHelper_OverlappingRanges(t *testing.T) {
	cidrBlocks := []string{
		"192.168.0.0/16",
		"192.168.1.0/24",
		"192.168.1.10/32",
		"10.0.0.0/8",
		"10.1.0.0/16",
	}

	helper, err := NewHelper(cidrBlocks)
	if err != nil {
		t.Fatalf("Failed to create Helper: %v", err)
	}

	tests := []struct {
		name           string
		ip             string
		expectedPrefix int
	}{
		{"Most specific match", "192.168.1.10", 32},
		{"Subnet match", "192.168.1.5", 24},
		{"Large network match", "192.168.2.1", 16},
		{"Other network subnet", "10.1.1.1", 16},
		{"Other network general", "10.2.1.1", 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}

			found, prefixLen, err := helper.IsContained(ip)
			if err != nil {
				t.Errorf("IsContained returned error: %v", err)
			}

			if !found {
				t.Errorf("IsContained(%s) = false, expected true", tt.ip)
			}

			if prefixLen != tt.expectedPrefix {
				t.Errorf("IsContained(%s) prefix = %d, want %d", tt.ip, prefixLen, tt.expectedPrefix)
			}
		})
	}
}

func TestHelper_CatchAllStaysSameFamily(t *testing.T) {
	v4, err := NewHelper([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatalf("Failed to create Helper: %v", err)
	}
	v6, err := NewHelper([]string{"::/0"})
	if err != nil {
		t.Fatalf("Failed to create Helper: %v", err)
	}

	tests := []struct {
		name    string
		helper  *Helper
		ip      string
		want    bool
		wantLen int
	}{
		{"IPv4 catch-all matches IPv4", v4, "8.8.8.8", true, 0},
		{"IPv4 catch-all misses IPv6", v4, "2001:db8::1", false, 0},
		{"IPv6 catch-all matches IPv6", v6, "2001:db8::1", true, 0},
		{"IPv6 catch-all misses IPv4", v6, "8.8.8.8", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Invalid IP address: %s", tt.ip)
			}
			found, prefixLen, err := tt.helper.IsContained(ip)
			if err != nil {
				t.Fatalf("IsContained returned error: %v", err)
			}
			if found != tt.want {
				t.Errorf("IsContained(%s) = %v, want %v", tt.ip, found, tt.want)
			}
			if found && prefixLen != tt.wantLen {
				t.Errorf("IsContained(%s) prefix = %d, want %d", tt.ip, prefixLen, tt.wantLen)
			}
		})
	}
}

func TestHelper_NilIP(t *testing.T) {
	helper := NewEmptyHelper()
	found, prefixLen, err := helper.IsContained(nil)
	if err == nil {
		t.Fatal("expected error for nil IP")
	}
	if found || prefixLen != 0 {
		t.Fatalf("IsContained(nil) = %v, %d; want false, 0", found, prefixLen)
	}
}
