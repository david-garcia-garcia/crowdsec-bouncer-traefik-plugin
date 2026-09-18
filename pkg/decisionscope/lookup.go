package decisionscope

import (
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

const (
	// BannedValue is the cache payload for a ban remediation.
	BannedValue = "t"
	// NoBannedValue is the cache payload for no active remediation.
	NoBannedValue = "f"
	// CaptchaValue is the cache payload for a captcha remediation.
	CaptchaValue = "c"
)

// IsActiveRemediation reports whether value is ban or captcha (origin suffix ignored).
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

// PreferRemediation keeps ban over captcha over empty. Origin suffix is ignored for the winner's letter.
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

// lookupHit is one Ip, header, or Range candidate while merging ban over captcha.
type lookupHit struct {
	stored   string
	origin   string
	originID uint16
}

// mergeLookupHit keeps ban over captcha and remembers the winner's leftover origin or packed id.
func mergeLookupHit(chosen lookupHit, incoming lookupHit) lookupHit {
	if incoming.stored == "" {
		return chosen
	}
	next := PreferRemediation(chosen.stored, incoming.stored)
	if next == chosen.stored {
		return chosen
	}
	return incoming
}

// hitFromStored splits a leftover string or packed letter+id line.
func hitFromStored(stored string) lookupHit {
	_, leftover, originID := SplitStoredRemediation(stored)
	return lookupHit{stored: stored, origin: leftover, originID: originID}
}

// hitFromPackedWord unpacks a memory SetInt word.
func hitFromPackedWord(word uint32) lookupHit {
	kind, originID := UnpackWord(word)
	return lookupHit{stored: kind, origin: "", originID: originID}
}

// LookupCachedRemediation merges Ip, Range, and present header-scope hits. Ban wins across those scopes.
// Range comes from membership.Remediation; nil or empty membership is a miss (live/none never hydrate).
// Kind is ban, captcha, or none. Origin is a leftover name; OriginID is a packed intern id.
// remoteIP is the canonical client address string owned by clientRequest; ipAddr is Range membership only.
func LookupCachedRemediation(cacheClient *cache.Client, remoteIP string, ipAddr net.IP, scopes map[string]string, membership *RangeMembership) (kind, origin string, originID uint16, err error) {
	keys := LookupCacheKeys(remoteIP, scopes)
	var chosen lookupHit
	var leftoverKeys []string
	for _, key := range keys {
		word, getIntErr := cacheClient.GetInt(key)
		if getIntErr == nil {
			chosen = mergeLookupHit(chosen, hitFromPackedWord(word))
			continue
		}
		leftoverKeys = append(leftoverKeys, key)
	}
	if len(leftoverKeys) > 0 {
		found, err := cacheClient.GetMany(leftoverKeys)
		if err != nil {
			return "", "", 0, err
		}
		chosen = mergeLookupHit(chosen, hitFromStored(found[remoteIP]))
		for scope, identifier := range scopes {
			if identifier == "" {
				continue
			}
			chosen = mergeLookupHit(chosen, hitFromStored(found[HeaderScopeKey(scope, identifier)]))
		}
	}
	chosen = mergeLookupHit(chosen, hitFromStored(membership.Remediation(ipAddr)))
	if chosen.stored != "" {
		return RemediationKind(chosen.stored), chosen.origin, chosen.originID, nil
	}
	return "", "", 0, errors.New(cache.CacheMiss)
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
