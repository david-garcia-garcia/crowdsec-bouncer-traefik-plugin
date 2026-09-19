package decisionstore

import (
	"net"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// rangeRecord is one CIDR in the range-index blob. Origin sits on the following line.
type rangeRecord struct {
	cidr   string
	kind   string
	origin string
}

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
func ApplyRangeIndex(index string, upserts map[string]Decision, removals []string) string {
	records := parseRangeRecords(index)
	for _, cidr := range removals {
		network := rangeIndexCIDR(cidr)
		if network == "" {
			continue
		}
		records = removeRangeRecord(records, network)
	}
	for cidr, item := range upserts {
		network := rangeIndexCIDR(cidr)
		if network == "" || !decisionscope.IsActiveRemediation(item.Kind) {
			continue
		}
		records = upsertRangeRecord(records, network, item.Kind, item.Origin)
	}
	return formatRangeRecords(records)
}

func parseRangeRecords(index string) []rangeRecord {
	if index == "" {
		return nil
	}
	lines := strings.Split(index, "\n")
	records := make([]rangeRecord, 0)
	for i := 0; i < len(lines); i++ {
		network, kind := parseIndexLine(lines[i])
		if network == "" {
			continue
		}
		origin := ""
		if i+1 < len(lines) && !strings.Contains(lines[i+1], "=") {
			origin = strings.TrimSpace(lines[i+1])
			i++
		}
		records = append(records, rangeRecord{cidr: network, kind: kind, origin: origin})
	}
	return records
}

func formatRangeRecords(records []rangeRecord) string {
	kept := make([]string, 0, len(records))
	for _, rec := range records {
		if rec.cidr == "" || rec.kind == "" {
			continue
		}
		line := rec.cidr + "=" + rec.kind
		if rec.origin != "" {
			line += "\n" + rec.origin
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func upsertRangeRecord(records []rangeRecord, cidr, kind, origin string) []rangeRecord {
	next := make([]rangeRecord, 0, len(records)+1)
	replaced := false
	for _, rec := range records {
		if indexCIDRsSameNetwork(rec.cidr, cidr) {
			next = append(next, rangeRecord{cidr: cidr, kind: kind, origin: origin})
			replaced = true
			continue
		}
		next = append(next, rec)
	}
	if !replaced {
		next = append(next, rangeRecord{cidr: cidr, kind: kind, origin: origin})
	}
	return next
}

func removeRangeRecord(records []rangeRecord, cidr string) []rangeRecord {
	next := make([]rangeRecord, 0, len(records))
	for _, rec := range records {
		if indexCIDRsSameNetwork(rec.cidr, cidr) {
			continue
		}
		next = append(next, rec)
	}
	return next
}

// parseIndexLine splits one cidr=kind line. A missing equals leaves kind empty.
func parseIndexLine(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", ""
	}
	network, kind, ok := strings.Cut(trimmed, "=")
	if !ok {
		return trimmed, ""
	}
	return network, kind
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
