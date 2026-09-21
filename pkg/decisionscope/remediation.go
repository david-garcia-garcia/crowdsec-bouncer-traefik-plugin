package decisionscope

// RemediationKind is the ban/captcha/none letter.
func RemediationKind(stored string) string {
	if stored == "" {
		return ""
	}
	kind := stored[:1]
	switch kind {
	case BannedValue, NoBannedValue, CaptchaValue:
		return kind
	default:
		return stored
	}
}
