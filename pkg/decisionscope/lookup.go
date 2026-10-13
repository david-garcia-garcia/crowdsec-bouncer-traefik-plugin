package decisionscope

import (
	"net/http"
	"sort"
	"strings"
)

const (
	// BannedValue is the cache payload for a ban remediation.
	BannedValue = "t"
	// NoBannedValue is the cache payload for no active remediation.
	NoBannedValue = "f"
	// CaptchaValue is the cache payload for a captcha remediation.
	CaptchaValue = "c"
)

// IsActiveRemediation reports whether value is ban or captcha.
func IsActiveRemediation(value string) bool {
	kind := RemediationKind(value)
	return kind == BannedValue || kind == CaptchaValue
}

// RemediationValue maps a CrowdSec decision type to a decisionscope remediation code.
func RemediationValue(decisionType string) string {
	switch decisionType {
	case "ban":
		return BannedValue
	case "captcha":
		return CaptchaValue
	default:
		return ""
	}
}

// PreferRemediation keeps ban over captcha over empty.
func PreferRemediation(current, incoming string) string {
	currentKind := RemediationKind(current)
	incomingKind := RemediationKind(incoming)
	if currentKind == BannedValue {
		return current
	}
	if incomingKind == BannedValue {
		return incoming
	}
	if IsActiveRemediation(current) {
		return current
	}
	return incoming
}

// RequestScopeValues reads configured scope headers. Country and AS are normalized; others are trimmed.
func RequestScopeValues(headers map[string]string, req *http.Request) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for scope, header := range headers {
		value := NormalizeHeaderScopeValue(scope, req.Header.Get(header))
		if value != "" {
			out[scope] = value
		}
	}
	return out
}

// StreamScopeList is the LAPI scopes query value for this bouncer config.
func StreamScopeList(headers map[string]string) string {
	parts := []string{"ip", "range"}
	mapped := make([]string, 0, len(headers))
	for scope := range headers {
		mapped = append(mapped, StreamScopeToken(scope))
	}
	sort.Strings(mapped)
	return strings.Join(append(parts, mapped...), ",")
}

// CanonicalStreamScopes is ip, range, then extra opener names (lowercased, sorted, unique).
func CanonicalStreamScopes(extra []string) []string {
	seen := map[string]struct{}{"ip": {}, "range": {}}
	out := []string{"ip", "range"}
	extras := make([]string, 0, len(extra))
	for _, raw := range extra {
		token := strings.ToLower(strings.TrimSpace(raw))
		if token == "" {
			continue
		}
		if _, exists := seen[token]; exists {
			continue
		}
		seen[token] = struct{}{}
		extras = append(extras, token)
	}
	sort.Strings(extras)
	return append(out, extras...)
}

// StreamScopeQuery is the LAPI stream scopes= value from the opener list.
func StreamScopeQuery(extra []string) string {
	return strings.Join(CanonicalStreamScopes(extra), ",")
}

// MissingStreamScopes are decisionScopeHeaders keys the opener list does not cover.
func MissingStreamScopes(headers map[string]string, extra []string) []string {
	covered := make(map[string]struct{}, 8)
	for _, name := range CanonicalStreamScopes(extra) {
		covered[strings.ToLower(name)] = struct{}{}
	}
	missing := make([]string, 0)
	for scope := range headers {
		token := strings.ToLower(StreamScopeToken(scope))
		if _, ok := covered[token]; ok {
			continue
		}
		if _, ok := covered[strings.ToLower(scope)]; ok {
			continue
		}
		missing = append(missing, scope)
	}
	sort.Strings(missing)
	return missing
}
