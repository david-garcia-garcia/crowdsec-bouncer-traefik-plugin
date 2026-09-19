package decisionscope

import (
	"strings"
)

const remediationOriginSep = "\x1f"

// RemediationKind is the ban/captcha/none/captcha-done letter. A leftover origin suffix is ignored.
func RemediationKind(stored string) string {
	if stored == "" {
		return ""
	}
	kind := stored[:1]
	switch kind {
	case "t", "f", "c", "d":
		return kind
	default:
		return stored
	}
}

// RemediationOrigin is the leftover metrics origin stored after the letter, or empty.
func RemediationOrigin(stored string) string {
	_, origin, ok := strings.Cut(stored, remediationOriginSep)
	if !ok {
		return ""
	}
	return origin
}

// RemediationWithOrigin stores kind, optionally with a leftover metrics origin suffix.
func RemediationWithOrigin(kind, origin string) string {
	if origin == "" {
		return kind
	}
	return kind + remediationOriginSep + origin
}

// OriginIntern is the DecisionStore intern table used when packing cache payloads.
type OriginIntern interface {
	Intern(name string) (uint16, bool)
	PacksMemory() bool
}

// Pack encodes a cache slot payload: a memory uint32 word when intern succeeds, otherwise a leftover string.
func Pack(kind, origin string, origins OriginIntern) any {
	if kind != "" && origins != nil && origins.PacksMemory() {
		if originID, ok := origins.Intern(origin); ok {
			return packWord(kind, originID)
		}
	}
	return RemediationWithOrigin(kind, origin)
}

// Unpack reads a Pack word or a leftover/bare letter string.
func Unpack(payload any) (string, string, uint16) {
	switch stored := payload.(type) {
	case uint32:
		return unpackWord(stored)
	case string:
		return RemediationKind(stored), RemediationOrigin(stored), 0
	default:
		return "", "", 0
	}
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
