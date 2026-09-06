package decisionscope

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// IsActiveRemediation reports whether value is ban or captcha (origin suffix ignored).
func IsActiveRemediation(value string) bool {
	kind := cache.RemediationKind(value)
	return kind == cache.BannedValue || kind == cache.CaptchaValue
}

// RemediationValue maps a CrowdSec decision type to a cache remediation.
func RemediationValue(decisionType string) string {
	switch decisionType {
	case "ban":
		return cache.BannedValue
	case "captcha":
		return cache.CaptchaValue
	default:
		return ""
	}
}

// PreferRemediation keeps ban over captcha over empty. Origin suffix is ignored for the winner's letter.
func PreferRemediation(current, incoming string) string {
	currentKind := cache.RemediationKind(current)
	incomingKind := cache.RemediationKind(incoming)
	if currentKind == cache.BannedValue {
		return current
	}
	if incomingKind == cache.BannedValue {
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

// LookupCachedRemediation merges Ip, Range, and present header-scope hits. Ban wins across those scopes.
// Stream and alone Range hits come from membership, not from a range-index GetMany.
// The returned remediation is the letter only; origin is the metrics origin of the winning Ip, header, or Range value.
// ipAddr is the net.IP GetRemoteIP already yielded; remoteIP remains the cache key.
func LookupCachedRemediation(cacheClient *cache.Client, mode, remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (string, string, error) {
	useRangeMembership := mode == configuration.StreamMode || mode == configuration.AloneMode
	found, err := cacheClient.GetMany(LookupCacheKeys(remoteIP, scopes))
	if err != nil {
		return "", "", err
	}
	// Merge Ip, Range, and header hits so a Country ban beats a Range captcha.
	chosen := found[remoteIP]
	if useRangeMembership {
		chosen = PreferRemediation(chosen, membership.Remediation(ipAddr))
	}
	for scope, identifier := range scopes {
		if identifier == "" {
			continue
		}
		chosen = PreferRemediation(chosen, found[HeaderScopeKey(scope, identifier)])
	}
	if IsActiveRemediation(chosen) {
		return cache.RemediationKind(chosen), cache.RemediationOrigin(chosen), nil
	}
	if value, ok := found[remoteIP]; ok {
		return cache.RemediationKind(value), cache.RemediationOrigin(value), nil
	}
	return "", "", errors.New(cache.CacheMiss)
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
