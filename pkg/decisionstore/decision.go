package decisionstore

import (
	"net"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// Decision is one Ip or header-scope remediation (stream/alone or live/none).
// ApplyRangeBatch uses Kind and Origin; the map key is the CIDR.
// DeleteMany reads Scope and Value only.
type Decision struct {
	Scope       string
	Value       string
	Kind        string
	Origin      string
	DurationSec int64
}

// PutManyChunk is SimpleRedis maxMSetEXPairs. Redis PutMany and stream apply flush at this size.
const PutManyChunk = 1024

// SlotKey is the canonical map/Redis key for scope+value. Empty when the value cannot be stored.
func SlotKey(scope, value string) string {
	key, _ := slotKeys(scope, value)
	return key
}

// slotKeys is the canonical slot key and a prior Ip spelling to delete on lift.
func slotKeys(scope, value string) (string, string) {
	scope = decisionscope.NormalizeScope(scope)
	switch scope {
	case decisionscope.ScopeRange:
		return "", ""
	case decisionscope.ScopeIP, "":
		key := IPCacheKey(value)
		if key == "" {
			return "", ""
		}
		trimmed := strings.TrimSpace(value)
		if trimmed != "" && trimmed != key {
			return key, trimmed
		}
		return key, ""
	default:
		identifier := decisionscope.NormalizeHeaderScopeValue(scope, value)
		if identifier == "" {
			return "", ""
		}
		return HeaderScopeKey(scope, identifier), ""
	}
}

// HeaderScopeKey is the slot key for a header-matched scope (Country, AS, or custom).
func HeaderScopeKey(scope, value string) string {
	return strings.ToLower(scope) + ":" + value
}

// IPCacheKey is the slot key for an Ip-scoped decision value (bare IP or /32 / /128).
// CrowdSec stores a decision value exactly as it was submitted, so the same address reaches this
// bouncer as an expanded, upper-case, or IPv4-mapped spelling. Every spelling that parses as an
// address collapses to net.IP.String(); a value that parses as neither is keyed verbatim.
func IPCacheKey(value string) string {
	trimmed := strings.TrimSpace(value)
	ipAddr, ipNet, err := net.ParseCIDR(trimmed)
	if err == nil {
		ones, bits := ipNet.Mask.Size()
		if ones == bits {
			return ipAddr.String()
		}
		return trimmed
	}
	if bare := net.ParseIP(trimmed); bare != nil {
		return bare.String()
	}
	return trimmed
}
