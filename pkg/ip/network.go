package ip

import (
	"net"
	"strings"
)

// Family is ipv4 or ipv6 for a host string (decision values, tests). Empty if unparseable.
// Request-path ip_type uses FamilyOfIP on the net.IP GetRemoteIP already yielded.
func Family(addr string) string {
	return FamilyOfIP(net.ParseIP(strings.TrimSpace(addr)))
}

// FamilyOfIP is ipv4 or ipv6 for a net.IP. Empty if nil.
func FamilyOfIP(ipAddr net.IP) string {
	if ipAddr == nil {
		return ""
	}
	if ipAddr.To4() != nil {
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

// MaskPrefix masks ipAddr to its network: the first ipv4Prefix bits of an IPv4 address (an
// IPv4-mapped IPv6 address counts as IPv4) or the first ipv6Prefix bits of an IPv6 address.
// A prefix of 0 returns the address unchanged. Nil stays nil.
func MaskPrefix(ipAddr net.IP, ipv4Prefix, ipv6Prefix int) net.IP {
	if ipAddr == nil {
		return nil
	}
	// IPv4, including IPv4-mapped IPv6: mask the 4-byte form.
	if ipv4Addr := ipAddr.To4(); ipv4Addr != nil {
		if ipv4Prefix == 0 {
			return ipAddr
		}
		return ipv4Addr.Mask(net.CIDRMask(ipv4Prefix, 8*net.IPv4len))
	}
	// IPv6.
	if ipv6Prefix == 0 {
		return ipAddr
	}
	return ipAddr.Mask(net.CIDRMask(ipv6Prefix, 8*net.IPv6len))
}
