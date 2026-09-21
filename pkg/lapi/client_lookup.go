package lapi

import (
	"net"
)

// LookupRemediation resolves Ip, header scopes, and Range through the decision store.
func (c *Client) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (kind string, origin string, originID uint16, err error) {
	if c == nil || c.decisionStore == nil {
		return "", "", 0, nil
	}
	return c.decisionStore.LookupRemediation(remoteIP, ipAddr, scopes)
}
