package lapi

import (
	"net"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

// LookupStreamRemediation resolves stream/alone Ip, header scopes, and Range through the DecisionStore stream store.
func (c *Client) LookupStreamRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (string, string, uint16, error) {
	if c == nil || c.decisionStore == nil {
		return "", "", 0, cache.ErrMiss
	}
	return c.decisionStore.lookupStreamRemediation(remoteIP, ipAddr, scopes, c.RangeMembership())
}
