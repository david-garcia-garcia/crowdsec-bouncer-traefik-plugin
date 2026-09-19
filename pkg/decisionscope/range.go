package decisionscope

import (
	"net"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// rangeIndexCIDR maps a parseable host to /32 or /128 so the index key is a CIDR.
func rangeIndexCIDR(cidr string) string {
	network := strings.TrimSpace(cidr)
	if network == "" {
		return ""
	}
	if ipAddr := net.ParseIP(network); ipAddr != nil {
		return ip.HostCIDR(ipAddr)
	}
	return network
}

// ApplyRangeIndex applies removals then upserts to a range-index blob.
// Removals run first so a CIDR present in both maps remains the replacement.
func ApplyRangeIndex(index string, upserts map[string]string, removals []string) string {
	for _, cidr := range removals {
		network := rangeIndexCIDR(cidr)
		if network == "" {
			continue
		}
		index = removeCIDRFromIndex(index, network)
	}
	for cidr, remediation := range upserts {
		network := rangeIndexCIDR(cidr)
		if network == "" || !IsActiveRemediation(remediation) {
			continue
		}
		index = upsertIndexCIDR(index, network, remediation)
	}
	return index
}

// parseIndexLine splits one cidr=remediation line. A missing equals leaves remediation empty.
func parseIndexLine(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", ""
	}
	network, remediation, ok := strings.Cut(trimmed, "=")
	if !ok {
		return trimmed, ""
	}
	return network, remediation
}

// indexCIDRsSameNetwork reports whether two range-index CIDR texts name the same network.
func indexCIDRsSameNetwork(existing, cidr string) bool {
	// Compare the parsed networks, not the host-bit first IP ParseCIDR also returns.
	_, existingNet, existingErr := net.ParseCIDR(existing)
	_, incomingNet, incomingErr := net.ParseCIDR(cidr)
	// Unparseable text still matches only when the raw strings are identical.
	if existingErr != nil || incomingErr != nil {
		return existing == cidr
	}
	existingOnes, existingBits := existingNet.Mask.Size()
	incomingOnes, incomingBits := incomingNet.Mask.Size()
	return existingNet.IP.Equal(incomingNet.IP) && existingOnes == incomingOnes && existingBits == incomingBits
}

// upsertIndexCIDR replaces or appends one CIDR line. Ban/captcha for that CIDR is the last write.
func upsertIndexCIDR(index, cidr, remediation string) string {
	kept := make([]string, 0)
	replaced := false
	for _, line := range strings.Split(index, "\n") {
		existing, existingRem := parseIndexLine(line)
		if existing == "" {
			continue
		}
		if indexCIDRsSameNetwork(existing, cidr) {
			kept = append(kept, cidr+"="+remediation)
			replaced = true
			continue
		}
		if existingRem == "" {
			kept = append(kept, existing)
			continue
		}
		kept = append(kept, existing+"="+existingRem)
	}
	if !replaced {
		kept = append(kept, cidr+"="+remediation)
	}
	return strings.Join(kept, "\n")
}

// removeCIDRFromIndex drops every line whose CIDR is the same network as cidr.
func removeCIDRFromIndex(index, cidr string) string {
	kept := make([]string, 0)
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || indexCIDRsSameNetwork(network, cidr) {
			continue
		}
		if remediation == "" {
			kept = append(kept, network)
			continue
		}
		kept = append(kept, network+"="+remediation)
	}
	return strings.Join(kept, "\n")
}
