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
	index := upsertIndexCIDR(readRangeIndex(cacheClient), network, remediation)
	cacheClient.Set(RangeIndexKey, index, rangeIndexTTL)
}

// RemoveRange drops a Range decision from the shared index.
func RemoveRange(cacheClient *cache.Client, cidr string) {
	next := removeCIDRFromIndex(readRangeIndex(cacheClient), strings.TrimSpace(cidr))
	if next == "" {
		cacheClient.Delete(RangeIndexKey)
		return
	}
	cacheClient.Set(RangeIndexKey, next, rangeIndexTTL)
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

func readRangeIndex(cacheClient *cache.Client) string {
	index, err := cacheClient.Get(RangeIndexKey)
	if err != nil {
		return ""
	}
	return index
}

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
