package lapi

import (
	"errors"
	"fmt"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// LiveLookup queries LAPI for one IP and mapped header scopes (none/live mode).
// defaultDecisionSeconds is the live-cache TTL the caller wants for this lookup.
func (c *Client) LiveLookup(remoteIP string, scopes map[string]string, defaultDecisionSeconds int64) (string, error) {
	return c.handleNoStreamCache(remoteIP, scopes, defaultDecisionSeconds)
}

func (c *Client) handleNoStreamCache(remoteIP string, scopes map[string]string, defaultDecisionSeconds int64) (string, error) {
	isLiveMode := c.crowdsecMode == configuration.LiveMode
	chosen, parsedDuration, err := c.queryLiveDecisions(fmt.Sprintf("ip=%v", remoteIP))
	if err != nil {
		return "", err
	}
	for scope, identifier := range scopes {
		chosen, parsedDuration = c.mergeLiveScope(chosen, parsedDuration, scope, identifier, isLiveMode, defaultDecisionSeconds)
	}
	if !decisionscope.IsActiveRemediation(chosen) {
		if isLiveMode && defaultDecisionSeconds > 0 {
			c.cacheClient.Set(remoteIP, decisionscope.NoBannedValue, defaultDecisionSeconds)
		}
		return decisionscope.NoBannedValue, nil
	}
	if isLiveMode && defaultDecisionSeconds > 0 {
		c.cacheClient.Set(remoteIP, chosen, liveCacheTTL(parsedDuration, defaultDecisionSeconds))
	}
	return chosen, errors.New("handleNoStreamCache:banned")
}
