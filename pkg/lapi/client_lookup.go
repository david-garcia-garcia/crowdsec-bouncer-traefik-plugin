package lapi

import (
	"net"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// LookupStreamRemediation resolves stream/alone Ip, header scopes, and Range through the decision store.
func (c *Client) LookupStreamRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (string, string, uint16, error) {
	if c == nil || c.decisionStore == nil {
		return "", "", 0, cache.ErrMiss
	}
	return c.decisionStore.LookupRemediation(remoteIP, ipAddr, scopes, c.RangeMembership())
}

// LookupCachedRemediation resolves live/none Ip, header scopes, and Range through the decision-store cache.
func (c *Client) LookupCachedRemediation(remoteIP string, ipAddr net.IP, scopes map[string]string) (string, string, uint16, error) {
	if c == nil {
		return "", "", 0, cache.ErrMiss
	}
	if c.decisionStore != nil {
		return c.decisionStore.LookupCached(remoteIP, ipAddr, scopes, c.RangeMembership())
	}
	return decisionscope.LookupCachedRemediation(c.cacheClient, remoteIP, ipAddr, scopes, c.RangeMembership())
}
