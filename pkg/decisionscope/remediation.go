package decisionscope

import (
	"strconv"
	"strings"
	"unicode"
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

// PackWord is the store/lapi packed remediation: kind letter in the low byte, intern id above.
func PackWord(kind string, originID uint16) uint32 {
	if kind == "" {
		return 0
	}
	return uint32(kind[0]) | uint32(originID)<<8
}

// UnpackWord splits a packed remediation word into kind letter and intern id.
func UnpackWord(word uint32) (kind string, originID uint16) {
	return string([]byte{byte(word)}), uint16(word >> 8)
}

// PackedRemediationLine is a range-index value: letter plus decimal intern id.
func PackedRemediationLine(kind string, originID uint16) string {
	if originID == 0 {
		return kind
	}
	return kind + strconv.FormatUint(uint64(originID), 10)
}

// SplitStoredRemediation reads leftover U+001F origin or a packed letter+decimal id.
func SplitStoredRemediation(stored string) (kind, leftoverOrigin string, originID uint16) {
	kind = RemediationKind(stored)
	if stored == "" {
		return "", "", 0
	}
	if _, origin, ok := strings.Cut(stored, remediationOriginSep); ok {
		return kind, origin, 0
	}
	if len(stored) <= 1 {
		return kind, "", 0
	}
	rest := stored[1:]
	for _, r := range rest {
		if !unicode.IsDigit(r) {
			return kind, "", 0
		}
	}
	parsed, err := strconv.ParseUint(rest, 10, 16)
	if err != nil {
		return kind, "", 0
	}
	return kind, "", uint16(parsed)
}
