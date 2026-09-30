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

const (
	packedKindMask      = 3
	packedOriginShift   = 2
	packedOriginMask    = 4095
	packedFamilyShift   = 14
	packedFamilyMask    = 3
	packedScenarioShift = 16
	packedKindEmpty     = 0
	packedKindBan       = 1
	packedKindCaptcha   = 2
	packedKindNoBan     = 3
	packedFamilyIPv4    = 1
	packedFamilyIPv6    = 2
)

// packWord is 2-bit kind, 12-bit origin id, 2-bit family, 16-bit scenario id.
// Origin id greater than 4095 packs as 0. Unpack of the kind bits returns ASCII t/c/f.
func packWord(kind string, originID uint16, family string, scenarioID uint16) uint32 {
	if kind == "" {
		return 0
	}
	packedOrigin := uint32(originID)
	if packedOrigin > packedOriginMask {
		packedOrigin = 0
	}
	return packKindCode(kind) |
		packedOrigin<<packedOriginShift |
		packFamilyCode(family)<<packedFamilyShift |
		uint32(scenarioID)<<packedScenarioShift
}

// packKindCode is 1 for t, 2 for c, 3 for f, 0 for empty or unknown.
func packKindCode(kind string) uint32 {
	switch kind {
	case decisionscope.BannedValue:
		return packedKindBan
	case decisionscope.CaptchaValue:
		return packedKindCaptcha
	case decisionscope.NoBannedValue:
		return packedKindNoBan
	default:
		return packedKindEmpty
	}
}

// unpackKindCode maps packed kind 1/2/3 back to ASCII t/c/f.
func unpackKindCode(code uint32) string {
	switch code {
	case packedKindBan:
		return decisionscope.BannedValue
	case packedKindCaptcha:
		return decisionscope.CaptchaValue
	case packedKindNoBan:
		return decisionscope.NoBannedValue
	default:
		return ""
	}
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

// packedOriginID is bits 2-13.
func packedOriginID(word uint32) uint16 {
	return uint16((word >> packedOriginShift) & packedOriginMask) //nolint:gosec // G115 origin id is stored in 12 bits
}

// packedFamily is ipv4, ipv6, or empty from bits 14-15.
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

// unpackWord is ASCII kind, empty origin name, and packed origin id.
func unpackWord(word uint32) (string, string, uint16) {
	return unpackKindCode(word & packedKindMask), "", packedOriginID(word)
}
