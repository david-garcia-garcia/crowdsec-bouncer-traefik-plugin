package cache

import "strings"

const remediationOriginSep = "\x1f"

// RemediationKind is the ban/captcha/none/captcha-done letter. A stored origin suffix is ignored.
func RemediationKind(stored string) string {
	if stored == "" {
		return ""
	}
	kind := stored[:1]
	switch kind {
	case BannedValue, NoBannedValue, CaptchaValue, CaptchaDoneValue:
		return kind
	default:
		return stored
	}
}

// RemediationOrigin is the metrics origin stored after the letter, or empty.
func RemediationOrigin(stored string) string {
	_, origin, ok := strings.Cut(stored, remediationOriginSep)
	if !ok {
		return ""
	}
	return origin
}

// RemediationWithOrigin stores kind, optionally with a metrics origin suffix.
func RemediationWithOrigin(kind, origin string) string {
	if origin == "" {
		return kind
	}
	return kind + remediationOriginSep + origin
}
