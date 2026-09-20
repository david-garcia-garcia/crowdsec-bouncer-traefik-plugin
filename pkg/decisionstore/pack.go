package decisionstore

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const kindOriginSep = "\n"

// Unpack reads a packed word or a kind+origin string (Redis slot or Range blob payload).
func Unpack(payload any) (string, string, uint16) {
	switch payloadTyped := payload.(type) {
	case uint32:
		return unpackWord(payloadTyped)
	case string:
		kind, origin := splitKindOrigin(payloadTyped)
		return kind, origin, 0
	default:
		return "", "", 0
	}
}

// KindOriginString is the Redis SET value and the Range blob remediation: kind, then newline, then origin.
func KindOriginString(kind, origin string) string {
	if origin == "" {
		return kind
	}
	return kind + kindOriginSep + origin
}

func splitKindOrigin(stored string) (string, string) {
	kind, origin, ok := strings.Cut(stored, kindOriginSep)
	if !ok {
		return decisionscope.RemediationKind(stored), ""
	}
	return decisionscope.RemediationKind(kind), origin
}

func packWord(kind string, originID uint16) uint32 {
	if kind == "" {
		return 0
	}
	return uint32(kind[0]) | uint32(originID)<<8
}

func unpackWord(word uint32) (string, string, uint16) {
	return string([]byte{byte(word)}), "", uint16(word >> 8) //nolint:gosec // G115 intern id is stored in 16 bits
}
