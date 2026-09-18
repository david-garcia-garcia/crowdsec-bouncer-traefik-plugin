package decisionscope

import (
	"net"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// AddRange upserts a Range decision on the shared index as cidr=remediation.
func AddRange(cacheClient *cache.Client, cidr, remediation string, _ int64) {
	network := strings.TrimSpace(cidr)
	if network == "" || !IsActiveRemediation(remediation) {
		return
	}
	_ = ApplyRangeBatch(cacheClient, map[string]string{network: remediation}, nil)
}

// RemoveRange drops a Range decision from the shared index.
func RemoveRange(cacheClient *cache.Client, cidr string) {
	_ = ApplyRangeBatch(cacheClient, nil, []string{strings.TrimSpace(cidr)})
}

// ApplyRangeBatch upserts and removes Range lines with one cache read and one write.
// Removals run first so a CIDR present in both maps remains the replacement.
// The index is shared by every bouncer on this cache, so a read that did not answer is not an
// empty index: writing the batch onto an empty base would drop every Range decision this poll
// did not carry. A read failure returns the error and leaves the stored index alone.
func ApplyRangeBatch(cacheClient *cache.Client, upserts map[string]string, removals []string) error {
	if len(upserts) == 0 && len(removals) == 0 {
		return nil
	}
	index, err := readRangeIndex(cacheClient)
	if err != nil {
		return err
	}
	for _, cidr := range removals {
		index = removeCIDRFromIndex(index, strings.TrimSpace(cidr))
	}
	for cidr, remediation := range upserts {
		network := strings.TrimSpace(cidr)
		if network == "" || !IsActiveRemediation(remediation) {
			continue
		}
		index = upsertIndexCIDR(index, network, remediation)
	}
	if index == "" {
		cacheClient.Delete(RangeIndexKey)
		return nil
	}
	cacheClient.Set(RangeIndexKey, index, rangeIndexTTL)
	return nil
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

// readRangeIndex returns the cached range-index blob. A miss is an empty index and no error; every
// other failure is returned, because the caller cannot tell "no Range decisions" from "no answer".
func readRangeIndex(cacheClient *cache.Client) (string, error) {
	index, err := cacheClient.Get(RangeIndexKey)
	if err != nil {
		if err.Error() == cache.CacheMiss {
			return "", nil
		}
		return "", err
	}
	return index, nil
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
