package decisionstore

import (
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

// Memory keeps each decision in an 8-byte LiveSlot: this uint32 plus an int32 expiry.
// The word is 2-bit kind, 12-bit origin id, 2-bit family, 16-bit scenario id.
// Origin and scenario names are stored once, in the memory intern tables.
// Family is packed so ActiveCounts can group without parsing the address again.
// Redis stores the same hit as text. These ids are process-local, so another
// bouncer cannot decode them. Expiry stays outside both payloads.
//
// Retained heap for 400k decisions. The map key is the IP. The value is the slot.
// Kind, origin, and scenario are t, crowdsec, and crowdsecurity/http-probing.
// Each total is the IP keys plus that map (values and buckets).
//
//	(A) packed word                          12.7 + 14.0 = 26.7 MB
//	(B) struct of interned strings           12.7 + 42.0 = 54.7 MB
//	(C) struct of private string copies      12.7 + 61.2 = 73.9 MB
//
// (B) and (C) are {kind, origin, scenario string, int32 expiry}, 56 bytes.
// Interning shares the 35 bytes of text. (C) copies those 35 bytes on every slot
// (14.0 MB of characters, 19.2 MB once the allocator rounds them).
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

// packToWord encodes the hit into one uint32. Family comes from value. Intern overflow packs id 0.
func (m *memory) packToWord(hit lookupHit, value string) uint32 {
	originID, _ := m.origins.ID(hit.origin)
	scenarioID, _ := m.scenarios.ID(hit.scenario)
	return packWord(hit.kind, originID, ip.FamilyOfHostOrCIDR(value), scenarioID)
}

// unpackFromWord reads a memory word back into the same hit Redis stores as text.
func (m *memory) unpackFromWord(word uint32) lookupHit {
	kind, originID, _, scenarioID := unpackWord(word)
	return lookupHit{
		kind:     kind,
		origin:   m.origins.Name(originID),
		scenario: m.scenarios.Name(scenarioID),
	}
}

// packWord is 2-bit kind, 12-bit origin id, 2-bit family, 16-bit scenario id.
// Origin id greater than 4095 packs as 0.
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

// unpackFamilyCode is ipv4, ipv6, or empty for family code 1, 2, or anything else.
func unpackFamilyCode(code uint32) string {
	switch code {
	case packedFamilyIPv4:
		return "ipv4"
	case packedFamilyIPv6:
		return "ipv6"
	default:
		return ""
	}
}

// unpackWord is the inverse of packWord: kind letter, origin id, family, scenario id.
func unpackWord(word uint32) (string, uint16, string, uint16) {
	originID := uint16((word >> packedOriginShift) & packedOriginMask) //nolint:gosec // G115 origin id is stored in 12 bits
	scenarioID := uint16(word >> packedScenarioShift)                  //nolint:gosec // G115 scenario id is stored in 16 bits
	return unpackKindCode(word & packedKindMask),
		originID,
		unpackFamilyCode((word >> packedFamilyShift) & packedFamilyMask),
		scenarioID
}
