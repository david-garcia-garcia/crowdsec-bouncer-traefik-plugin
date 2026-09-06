package bouncer

import (
	"net"
	"net/http"
)

// clientRequest is one inbound request together with the client address GetRemoteIP already chose.
// Scopes, remediation origin, and captcha state are other jobs and stay off this type.
type clientRequest struct {
	req      *http.Request
	remoteIP string // cache, LAPI, AppSec, logs, ban template ClientIP
	parsed   net.IP // same address, already parsed; nil when unparseable
	ipType   string // FamilyOfIP(parsed): ipv4, ipv6, or empty
}
