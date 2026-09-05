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
