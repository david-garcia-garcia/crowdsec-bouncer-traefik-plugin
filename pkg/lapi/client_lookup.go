package lapi

import (
	"net"
	"time"
)

// LookupRemediation resolves Ip, header scopes, and Range through the decision store.
// decisionLeft is the time left on the decision the store merge chose (0 = unknown).
func (c *Client) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (kind string, origin string, originID uint16, decisionLeft time.Duration, err error) {
	if c == nil || c.decisionStore == nil {
		return "", "", 0, 0, nil
	}
	return c.decisionStore.LookupRemediation(remoteIP, ipAddr, scopes)
}
