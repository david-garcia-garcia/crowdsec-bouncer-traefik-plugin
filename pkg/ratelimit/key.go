package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	ip "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
)

const (
	// redisKeyPrefix starts every counter key this plugin writes.
	redisKeyPrefix = "rl:"
	// keyHashHexLen is how many hex characters of the SHA-256 of the key parts the Redis key keeps (64 bits).
	keyHashHexLen = 16
	// keyPartSeparator joins key parts before hashing, so ("a", "bc") and ("ab", "c") differ.
	keyPartSeparator = "\x00"
)

// keySource is one request as the key parts read it. The query string is parsed at most once,
// and only when a part asks for it.
type keySource struct {
	httpReq     *http.Request
	clientIP    net.IP
	query       url.Values
	queryParsed bool
}

// queryValues parses the URL query on first use.
func (source *keySource) queryValues() url.Values {
	if !source.queryParsed {
		source.queryParsed = true
		if source.httpReq.URL != nil {
			source.query = source.httpReq.URL.Query()
		}
	}
	return source.query
}

// counterKey joins every part's value and returns the Redis key of this bucket for the request.
// False means a part has no value, so the bucket is skipped for this request.
func (bucket *compiledBucket) counterKey(middlewareName string, source *keySource) (string, bool) {
	values := make([]string, 0, len(bucket.key))
	for i := range bucket.key {
		value, found := bucket.key[i].value(source)
		if !found {
			return "", false
		}
		values = append(values, value)
	}
	return redisCounterKey(middlewareName, bucket.name, values), true
}

// value reads this part from the request. False means the value is missing or empty,
// or the pattern did not match.
func (part *compiledKeyPart) value(source *keySource) (string, bool) {
	raw := part.rawValue(source)
	if raw == "" {
		return "", false
	}
	if part.pattern == nil {
		return raw, true
	}
	groups := part.pattern.FindStringSubmatch(raw)
	if len(groups) < 2 || groups[1] == "" {
		return "", false
	}
	return groups[1], true
}

// rawValue is the request value the part's source names, before the pattern. Empty means missing.
func (part *compiledKeyPart) rawValue(source *keySource) string {
	httpReq := source.httpReq
	switch part.from {
	case KeyFromIP:
		masked := ip.MaskPrefix(source.clientIP, part.ipv4Prefix, part.ipv6Prefix)
		if masked == nil {
			return ""
		}
		return masked.String()
	case KeyFromHeader:
		return httpReq.Header.Get(part.name)
	case KeyFromCookie:
		cookie, err := httpReq.Cookie(part.name)
		if err != nil {
			return ""
		}
		return cookie.Value
	case KeyFromQuery:
		return source.queryValues().Get(part.name)
	case KeyFromHost:
		return httprule.RequestHostname(httpReq)
	case KeyFromPath:
		if httpReq.URL == nil {
			return ""
		}
		return httpReq.URL.Path
	case KeyFromMethod:
		return httpReq.Method
	}
	return ""
}

// redisCounterKey is rl:<middleware>:<bucket>:<first 16 hex of SHA-256 of the parts joined by NUL>.
// The counter appends the window start. Raw part values never reach Redis.
func redisCounterKey(middlewareName, bucketName string, values []string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, keyPartSeparator)))
	return redisKeyPrefix + middlewareName + ":" + bucketName + ":" + hex.EncodeToString(sum[:])[:keyHashHexLen]
}
