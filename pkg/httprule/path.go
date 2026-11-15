package httprule

import (
	"net/url"
	"path"
	"strings"
)

// singleReadingPathChars are the path bytes every backend reads the same way:
// RFC 3986 unreserved characters and sub-delims, minus ';' and '*', plus ':', '@' and '/'.
const singleReadingPathChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~!$&'()+,=:@/"

// SingleReadingPath reports whether the request path has one reading only.
// False when the client percent-encoded any byte, or the path holds a byte outside
// singleReadingPathChars (';', '\', '%', '*', space...), an empty segment, or a '.' or '..' segment.
// A Java servlet backend reads /healthz/..;/admin as /admin, and an IIS backend reads '\' as '/'.
// A rule that skips a leg must not trust its path regex on such a path.
func SingleReadingPath(requestURL *url.URL) bool {
	if requestURL == nil {
		return false
	}
	requestPath := requestURL.Path
	if !strings.HasPrefix(requestPath, "/") || requestURL.EscapedPath() != requestPath {
		return false
	}
	if strings.Trim(requestPath, singleReadingPathChars) != "" {
		return false
	}
	cleaned := path.Clean(requestPath)
	if cleaned != "/" && strings.HasSuffix(requestPath, "/") {
		cleaned += "/"
	}
	if cleaned != requestPath {
		return false
	}
	// path.Clean leaves a segment like "..." alone; some backends still collapse it.
	for _, segment := range strings.Split(requestPath, "/") {
		if segment != "" && strings.Trim(segment, ".") == "" {
			return false
		}
	}
	return true
}
