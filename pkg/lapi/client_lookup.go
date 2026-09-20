package lapi

import (
	"net"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

// LookupRemediation resolves Ip, header scopes, and Range through the decision store.
func (c *Client) LookupRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (kind string, origin string, originID uint16, err error) {
	if c == nil || c.decisionStore == nil {
		return "", "", 0, decisionstore.ErrMiss
	}
	return c.decisionStore.LookupRemediation(remoteIP, ipAddr, scopes)
}
