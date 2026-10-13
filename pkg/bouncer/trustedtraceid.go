package bouncer

import "regexp"

// trustedTraceIDToken is A-Z a-z 0-9 _ . : - with length 1–200.
var trustedTraceIDToken = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)

// trustedTraceID drops client-controlled header bytes that are not a conservative token so text/template cannot emit them into the ban body.
func trustedTraceID(headerValue string) string {
	if trustedTraceIDToken.MatchString(headerValue) {
		return headerValue
	}
	return ""
}
