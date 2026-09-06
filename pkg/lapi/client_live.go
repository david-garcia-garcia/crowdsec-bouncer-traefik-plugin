package lapi

import (
	"errors"
	"fmt"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// LiveLookup queries LAPI for one IP and mapped header scopes (none/live mode).
func (c *Client) LiveLookup(remoteIP string, scopes map[string]string) (string, error) {
	return c.handleNoStreamCache(remoteIP, scopes)
}

func (c *Client) handleNoStreamCache(remoteIP string, scopes map[string]string) (string, error) {
	isLiveMode := c.crowdsecMode == configuration.LiveMode
	chosen, parsedDuration, err := c.queryLiveDecisions(fmt.Sprintf("ip=%v", remoteIP))
	if err != nil {
		return "", err
	}
	for scope, identifier := range scopes {
		chosen, parsedDuration = c.mergeLiveScope(chosen, parsedDuration, scope, identifier, isLiveMode)
	}
	if !decisionscope.IsActiveRemediation(chosen) {
		if isLiveMode && c.defaultDecisionTimeout > 0 {
			_ = c.cacheClient.Set(remoteIP, cache.NoBannedValue, c.defaultDecisionTimeout)
		}
		return cache.NoBannedValue, nil
	}
	if isLiveMode && c.defaultDecisionTimeout > 0 {
		_ = c.cacheClient.Set(remoteIP, chosen, c.liveCacheTTL(parsedDuration))
	}
	return chosen, errors.New("handleNoStreamCache:banned")
}
