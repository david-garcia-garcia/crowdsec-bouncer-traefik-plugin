// Package decisionscope matches CrowdSec decisions by Ip, Range, and header-mapped scopes.
package decisionscope

import (
	"net"
	"strings"
)

// Canonical CrowdSec scope strings after NormalizeScope.
const (
	ScopeIP      = "Ip"
	ScopeRange   = "Range"
	ScopeCountry = "Country"
	ScopeAS      = "AS"
)

// RangeIndexKey is the shared cache key for Range membership (cidr=remediation lines).
const RangeIndexKey = "range-index"

const rangeIndexTTL = 365 * 24 * 3600

// NormalizeScope returns the CrowdSec stored spelling for ip, range, country, and AS.
func NormalizeScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "ip":
		return ScopeIP
	case "range":
		return ScopeRange
	case "country":
		return ScopeCountry
	case "as":
		return ScopeAS
	default:
		return strings.TrimSpace(scope)
	}
}

// NormalizeCountry returns an upper-case ISO 3166-1 alpha-2 code, or empty if unusable.
func NormalizeCountry(value string) string {
	code := strings.ToUpper(strings.TrimSpace(value))
	if len(code) != 2 {
		return ""
	}
	if code == "XX" || code == "T1" {
		return ""
	}
	for _, char := range code {
		if char < 'A' || char > 'Z' {
			return ""
		}
	}
	return code
}

// NormalizeASN returns decimal ASN digits, stripping an optional AS/as prefix.
func NormalizeASN(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) >= 2 && strings.EqualFold(trimmed[:2], "as") {
		trimmed = strings.TrimSpace(trimmed[2:])
	}
	if trimmed == "" {
		return ""
	}
	for _, char := range trimmed {
		if char < '0' || char > '9' {
			return ""
		}
	}
	return trimmed
}

// HeaderScopeKey is the shared-cache key for a header-matched scope (Country, AS, or custom).
func HeaderScopeKey(scope, value string) string {
	return strings.ToLower(scope) + ":" + value
}

// NormalizeHeaderScopeValue applies Country/AS rules, else a trim. Empty means skip that scope.
func NormalizeHeaderScopeValue(scope, raw string) string {
	switch scope {
	case ScopeCountry:
		return NormalizeCountry(raw)
	case ScopeAS:
		return NormalizeASN(raw)
	default:
		return strings.TrimSpace(raw)
	}
}

// StreamScopeToken is the LAPI stream `scopes=` spelling for a configured header scope.
func StreamScopeToken(scope string) string {
	switch scope {
	case ScopeCountry:
		return "country"
	case ScopeAS:
		return "AS"
	default:
		return scope
	}
}

// NormalizeDecisionScopeHeaders keeps configured header scopes. Ip and Range are not header scopes.
func NormalizeDecisionScopeHeaders(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for rawScope, rawHeader := range in {
		header := strings.TrimSpace(rawHeader)
		if header == "" {
			continue
		}
		scope := NormalizeScope(rawScope)
		if scope == "" || scope == ScopeIP || scope == ScopeRange {
			continue
		}
		out[scope] = header
	}
	return out
}

// IPCacheKey is the cache key for an Ip-scoped decision value (bare IP or /32 / /128).
func IPCacheKey(value string) string {
	trimmed := strings.TrimSpace(value)
	ipAddr, ipNet, err := net.ParseCIDR(trimmed)
	if err != nil {
		return trimmed
	}
	ones, bits := ipNet.Mask.Size()
	if ones == bits {
		return ipAddr.String()
	}
	return trimmed
}

// IPLookupCacheKey is the request-path Ip cache key aligned with IPCacheKey store canonicalization.
func IPLookupCacheKey(remoteIP string, ipAddr net.IP) string {
	trimmed := strings.TrimSpace(remoteIP)
	key := IPCacheKey(remoteIP)
	if key != trimmed {
		return key
	}
	if ipAddr != nil {
		if v4 := ipAddr.To4(); v4 != nil {
			return v4.String()
		}
		return ipAddr.String()
	}
	return key
}
