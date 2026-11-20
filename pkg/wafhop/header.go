package wafhop

import (
	"net/http"
	"strings"
)

// IsHopByHopHeader reports a connection-scoped header (RFC 9110 section 7.6.1) that no WAF hop
// forwards or relays. The list is static on purpose: a pattern such as every Proxy-* name would let a
// client hide a header of its own choosing from the WAF.
func IsHopByHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
		"Te", "Trailer", "Trailers", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

// CopyEndToEndHeaders appends the headers of src onto dst, except hop-by-hop names and omit (case-insensitive).
// Values are copied, so dst never aliases src's slices.
//
// Names the client lists in its own Connection header are copied on purpose. RFC 9110 tells a proxy to
// drop them, but a WAF copy is an inspection copy: honoring that rule would let a client hide Cookie
// (or any other header) from the WAF with "Connection: Cookie". The static hop-by-hop list is the whole filter.
func CopyEndToEndHeaders(dst, src http.Header, omit ...string) {
	for name, values := range src {
		if IsHopByHopHeader(name) || matchesAny(name, omit) {
			continue
		}
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func matchesAny(name string, names []string) bool {
	for _, candidate := range names {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}
