package decisionscope

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
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
	return value == BannedValue || value == CaptchaValue
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
	if current == BannedValue || incoming == BannedValue {
		return BannedValue
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

// LookupCachedRemediation merges Ip, Range, and present header-scope hits. Ban wins across those scopes.
// Stream and alone Range hits come from membership, not from a range-index GetMany.
func LookupCachedRemediation(cacheClient *cache.Client, mode, remoteIP string, scopes map[string]string, membership *RangeMembership) (string, error) {
	useRangeMembership := mode == configuration.StreamMode || mode == configuration.AloneMode
	found, err := cacheClient.GetMany(LookupCacheKeys(remoteIP, scopes))
	if err != nil {
		return "", err
	}
	// Merge Ip, Range, and header hits so a Country ban beats a Range captcha.
	chosen := found[remoteIP]
	if useRangeMembership {
		chosen = PreferRemediation(chosen, membership.Remediation(remoteIP))
	}
	for scope, identifier := range scopes {
		if identifier == "" {
			continue
		}
		chosen = PreferRemediation(chosen, found[HeaderScopeKey(scope, identifier)])
	}
	if IsActiveRemediation(chosen) {
		return chosen, nil
	}
	if value, ok := found[remoteIP]; ok {
		return value, nil
	}
	return "", errors.New(cache.CacheMiss)
}

// LookupCacheKeys is the GetMany key list for the request path: IP, then present header scopes. Range is not a cache key.
func LookupCacheKeys(remoteIP string, scopes map[string]string) []string {
	keys := []string{remoteIP}
	for scope, identifier := range scopes {
		if identifier != "" {
			keys = append(keys, HeaderScopeKey(scope, identifier))
		}
	}
	return keys
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
