package ip

import (
	"fmt"
	"net"
	"strings"
)

// InNetwork reports whether addr is inside network (CIDR) or equals a bare IP.
func InNetwork(addr, network string) (bool, error) {
	ipAddr, err := parseIP(addr)
	if err != nil {
		return false, fmt.Errorf("InNetwork:parseAddress %w", err)
	}
	_, ipNet, cidrErr := net.ParseCIDR(strings.TrimSpace(network))
	if cidrErr == nil {
		return ipNet.Contains(ipAddr), nil
	}
	other, err := parseIP(strings.TrimSpace(network))
	if err != nil {
		return false, fmt.Errorf("InNetwork:parseNetwork %s %w", network, err)
	}
	return ipAddr.Equal(other), nil
}

// Family is ipv4 or ipv6 for an address GetRemoteIP already returned. Empty if unparseable.
func Family(addr string) string {
	parsed := net.ParseIP(strings.TrimSpace(addr))
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// FamilyOfHostOrCIDR classifies a decision value (host or network) for usage-metrics ip_type.
func FamilyOfHostOrCIDR(value string) string {
	if family := Family(value); family != "" {
		return family
	}
	_, network, err := net.ParseCIDR(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	if network.IP.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}
