package decisionstore

import (
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const kindOriginSep = "\n"

// Unpack reads a packed word or a kind+origin string (Redis slot or Range blob payload).
func Unpack(payload any) (kind string, origin string, originID uint16) {
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

const packedFamilyShift = 24
const packedFamilyMask = 3

const (
	packedFamilyIPv4 = 1
	packedFamilyIPv6 = 2
)

// packWord is kind[0] in bits 0-7, intern id in 8-23, family code in 24-25 (1=ipv4, 2=ipv6, 0=empty).
func packWord(kind string, originID uint16, family string) uint32 {
	if kind == "" {
		return 0
	}
	return uint32(kind[0]) | uint32(originID)<<8 | packFamilyCode(family)<<packedFamilyShift
}

// packFamilyCode is 1 for ipv4, 2 for ipv6, 0 for header-scope or unknown.
func packFamilyCode(family string) uint32 {
	switch family {
	case "ipv4":
		return packedFamilyIPv4
	case "ipv6":
		return packedFamilyIPv6
	default:
		return 0
	}
}

// packedOriginID is bits 8-23. The uint16 cast drops the family code.
func packedOriginID(word uint32) uint16 {
	return uint16(word >> 8) //nolint:gosec // G115 intern id is stored in 16 bits
}

// packedFamily is ipv4, ipv6, or empty from bits 24-25.
func packedFamily(word uint32) string {
	switch (word >> packedFamilyShift) & packedFamilyMask {
	case packedFamilyIPv4:
		return "ipv4"
	case packedFamilyIPv6:
		return "ipv6"
	default:
		return ""
	}
}

// unpackWord is kind letter, empty origin name, and intern id. Family stays in the high bits for packedFamily.
func unpackWord(word uint32) (string, string, uint16) {
	return string([]byte{byte(word)}), "", packedOriginID(word)
}
