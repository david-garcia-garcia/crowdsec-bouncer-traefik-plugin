package decisionscope

// RemediationKind is the ban/captcha/none/captcha-done letter.
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
