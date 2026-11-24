package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"strings"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/clientrequest"
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
	req         clientrequest.Request
	clientIP    net.IP
	query       url.Values
	queryParsed bool
}

// newKeySource reads the client address of req once for every bucket of one Charge.
func newKeySource(req clientrequest.Request) *keySource {
	return &keySource{req: req, clientIP: req.IPAddr()}
}

// queryValues parses the URL query on first use.
func (source *keySource) queryValues() url.Values {
	if source.queryParsed {
		return source.query
	}
	source.queryParsed = true
	if source.req.URL == nil {
		return nil
	}
	source.query = source.req.URL.Query()
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
	req := source.req
	switch part.from {
	case KeyFromIP:
		masked := ip.MaskPrefix(source.clientIP, part.ipv4Prefix, part.ipv6Prefix)
		if masked == nil {
			return ""
		}
		return masked.String()
	case KeyFromHeader:
		return req.Header.Get(part.name)
	case KeyFromCookie:
		cookie, err := req.Cookie(part.name)
		if err != nil {
			return ""
		}
		return cookie.Value
	case KeyFromQuery:
		return source.queryValues().Get(part.name)
	case KeyFromHost:
		return req.Hostname()
	case KeyFromPath:
		if req.URL == nil {
			return ""
		}
		return req.URL.Path
	case KeyFromMethod:
		return req.Method
	}
	return ""
}

// redisCounterKey is rl:<middleware>:<bucket>:<first 16 hex of SHA-256 of the parts joined by NUL>.
// Each counter appends its own suffix: the sliding window the window start, the token bucket ":tb".
// Raw part values never reach Redis.
func redisCounterKey(middlewareName, bucketName string, values []string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, keyPartSeparator)))
	return redisKeyPrefix + middlewareName + ":" + bucketName + ":" + hex.EncodeToString(sum[:])[:keyHashHexLen]
}
