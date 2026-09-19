package decisionstore

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// Decision is one stream/alone Ip or header-scope remediation. Range is ApplyRangeBatch.
type Decision struct {
	Scope       string
	Value       string
	Kind        string
	Origin      string
	DurationSec int64
}

// SlotKey is the canonical map/Redis key for scope+value. Empty when the value cannot be stored.
func SlotKey(scope, value string) string {
	key, _ := slotKeys(scope, value)
	return key
}

// slotKeys is the canonical slot key and a prior Ip spelling to delete on lift.
func slotKeys(scope, value string) (key, legacy string) {
	scope = decisionscope.NormalizeScope(scope)
	switch scope {
	case decisionscope.ScopeRange:
		return "", ""
	case decisionscope.ScopeIP, "":
		key = decisionscope.IPCacheKey(value)
		if key == "" {
			return "", ""
		}
		trimmed := strings.TrimSpace(value)
		if trimmed != "" && trimmed != key {
			legacy = trimmed
		}
		return key, legacy
	default:
		identifier := decisionscope.NormalizeHeaderScopeValue(scope, value)
		if identifier == "" {
			return "", ""
		}
		return decisionscope.HeaderScopeKey(scope, identifier), ""
	}
}
