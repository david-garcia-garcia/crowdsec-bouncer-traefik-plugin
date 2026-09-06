package bouncer

import (
	"net"
	"net/http"
)

// clientRequest is one inbound request together with the client address GetRemoteIP already chose.
// Callers keep the name req: this is still that request, with the address already prepared.
// Scopes, remediation origin, and captcha state are other jobs and stay off this type.
type clientRequest struct {
	*http.Request
	remoteIP string // cache, LAPI, AppSec, logs, ban template ClientIP
	parsed   net.IP // same address, already parsed; nil when unparseable
	ipType   string // FamilyOfIP(parsed): ipv4, ipv6, or empty
}
