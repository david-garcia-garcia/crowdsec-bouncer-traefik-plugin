package decisionscope

import (
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	ip "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// AddRange upserts a Range decision on the shared index as cidr=remediation.
func AddRange(cacheClient *cache.Client, cidr, remediation string, _ int64) {
	network := strings.TrimSpace(cidr)
	if network == "" || !IsActiveRemediation(remediation) {
		return
	}
	ApplyRangeBatch(cacheClient, map[string]string{network: remediation}, nil)
}

// RemoveRange drops a Range decision from the shared index.
func RemoveRange(cacheClient *cache.Client, cidr string) {
	ApplyRangeBatch(cacheClient, nil, []string{strings.TrimSpace(cidr)})
}

// ApplyRangeBatch upserts and removes Range lines with one cache read and one write.
func ApplyRangeBatch(cacheClient *cache.Client, upserts map[string]string, removals []string) {
	if len(upserts) == 0 && len(removals) == 0 {
		return
	}
	index := readRangeIndex(cacheClient)
	for cidr, remediation := range upserts {
		network := strings.TrimSpace(cidr)
		if network == "" || !IsActiveRemediation(remediation) {
			continue
		}
		index = upsertIndexCIDR(index, network, remediation)
	}
	for _, cidr := range removals {
		index = removeCIDRFromIndex(index, strings.TrimSpace(cidr))
	}
	if index == "" {
		cacheClient.Delete(RangeIndexKey)
		return
	}
	cacheClient.Set(RangeIndexKey, index, rangeIndexTTL)
}

// MatchRange returns the remediation for a containing CIDR. Ban wins if several match.
func MatchRange(cacheClient *cache.Client, remoteIP string) string {
	return MatchRangeFromIndex(readRangeIndex(cacheClient), remoteIP)
}

// MatchRangeFromIndex walks cidr=remediation lines. Ban wins if several match.
func MatchRangeFromIndex(index, remoteIP string) string {
	if index == "" {
		return ""
	}
	chosen := ""
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || !IsActiveRemediation(remediation) {
			continue
		}
		inside, err := ip.InNetwork(remoteIP, network)
		if err != nil || !inside {
			continue
		}
		chosen = PreferRemediation(chosen, remediation)
		if chosen == cache.BannedValue {
			return cache.BannedValue
		}
	}
	return chosen
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

// upsertIndexCIDR replaces or appends one CIDR line. Ban/captcha for that CIDR is the last write.
func upsertIndexCIDR(index, cidr, remediation string) string {
	kept := make([]string, 0)
	replaced := false
	for _, line := range strings.Split(index, "\n") {
		existing, existingRem := parseIndexLine(line)
		if existing == "" {
			continue
		}
		if existing == cidr {
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

// readRangeIndex returns the cached range-index blob, or empty on miss or error.
func readRangeIndex(cacheClient *cache.Client) string {
	index, err := cacheClient.Get(RangeIndexKey)
	if err != nil {
		return ""
	}
	return index
}

// removeCIDRFromIndex drops every line whose CIDR equals cidr.
func removeCIDRFromIndex(index, cidr string) string {
	kept := make([]string, 0)
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || network == cidr {
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
