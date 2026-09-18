package decisionscope

import (
	"net"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// indexNetworkID is Range-index line identity: masked IP plus prefix ones and bits.
type indexNetworkID struct {
	ip   [16]byte
	ones int
	bits int
}

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
	collapsedUpserts := collapseRangeUpserts(upserts)
	if len(collapsedUpserts) == 0 && !hasParseableIndexCIDR(removals) {
		return
	}
	index := readRangeIndex(cacheClient)
	for cidr, remediation := range collapsedUpserts {
		index = upsertIndexCIDR(index, cidr, remediation)
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

// collapseRangeUpserts keeps one incoming CIDR per canonical network (last write wins).
func collapseRangeUpserts(upserts map[string]string) map[string]string {
	incomingByID := make(map[indexNetworkID]string)
	remediationByID := make(map[indexNetworkID]string)
	for cidr, remediation := range upserts {
		trimmed := strings.TrimSpace(cidr)
		network, ok := parseIndexNetwork(trimmed)
		if !ok || !IsActiveRemediation(remediation) {
			continue
		}
		id := indexNetworkIDOf(network)
		incomingByID[id] = trimmed
		remediationByID[id] = remediation
	}
	collapsed := make(map[string]string, len(incomingByID))
	for id, incoming := range incomingByID {
		collapsed[incoming] = remediationByID[id]
	}
	return collapsed
}

// hasParseableIndexCIDR reports whether any CIDR text parses as a Range-index network.
func hasParseableIndexCIDR(cidrs []string) bool {
	for _, cidr := range cidrs {
		if _, ok := parseIndexNetwork(cidr); ok {
			return true
		}
	}
	return false
}

// parseIndexNetwork parses CIDR text as a masked network. Unparseable text is a miss.
func parseIndexNetwork(cidr string) (*net.IPNet, bool) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || network == nil {
		return nil, false
	}
	return network, true
}

// indexNetworkIDOf returns the comparable identity of a parsed index network.
func indexNetworkIDOf(network *net.IPNet) indexNetworkID {
	var id indexNetworkID
	copy(id.ip[:], network.IP.To16())
	id.ones, id.bits = network.Mask.Size()
	return id
}

// sameIndexNetwork reports whether two parsed networks share Range-index line identity.
func sameIndexNetwork(left, right *net.IPNet) bool {
	if left == nil || right == nil {
		return false
	}
	leftOnes, leftBits := left.Mask.Size()
	rightOnes, rightBits := right.Mask.Size()
	return left.IP.Equal(right.IP) && leftOnes == rightOnes && leftBits == rightBits
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

// upsertIndexCIDR replaces every line of the incoming network and persists one canonical line.
func upsertIndexCIDR(index, cidr, remediation string) string {
	incoming, ok := parseIndexNetwork(cidr)
	if !ok {
		return index
	}
	persistCIDR := incoming.String()
	kept := make([]string, 0)
	replaced := false
	for _, line := range strings.Split(index, "\n") {
		existing, existingRem := parseIndexLine(line)
		if existing == "" {
			continue
		}
		existingNet, existingOK := parseIndexNetwork(existing)
		if existingOK && sameIndexNetwork(existingNet, incoming) {
			if !replaced {
				kept = append(kept, persistCIDR+"="+remediation)
				replaced = true
			}
			continue
		}
		if existingRem == "" {
			kept = append(kept, existing)
			continue
		}
		kept = append(kept, existing+"="+existingRem)
	}
	if !replaced {
		kept = append(kept, persistCIDR+"="+remediation)
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

// removeCIDRFromIndex drops every line of the incoming network. Unparseable incoming is a no-op.
func removeCIDRFromIndex(index, cidr string) string {
	incoming, ok := parseIndexNetwork(cidr)
	if !ok {
		return index
	}
	kept := make([]string, 0)
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" {
			continue
		}
		existingNet, existingOK := parseIndexNetwork(network)
		if existingOK && sameIndexNetwork(existingNet, incoming) {
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
