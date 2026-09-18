package lapi

import (
	"errors"
	"fmt"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// LiveLookup queries LAPI for one IP and mapped header scopes (none/live mode).
// defaultDecisionSeconds is the live-cache TTL the caller wants for this lookup.
//
// The returned error carries two different meanings and the caller separates them by the
// remediation kind, never by the error alone:
//
//	active remediation + non-nil error  -> a real decision; remediate it
//	non-active remediation + non-nil error -> LAPI failed; apply CrowdsecLapiFailureAction
//
// Any query this lookup makes can fail that way: the IP query and every header-scope query.
func (c *Client) LiveLookup(remoteIP string, scopes map[string]string, defaultDecisionSeconds int64) (string, error) {
	return c.handleNoStreamCache(remoteIP, scopes, defaultDecisionSeconds)
}

func (c *Client) handleNoStreamCache(remoteIP string, scopes map[string]string, defaultDecisionSeconds int64) (string, error) {
	isLiveMode := c.crowdsecMode == configuration.LiveMode
	// The request path reads this memo back through IPLookupCacheKey, so it is written under the
	// canonical spelling of the address, not the verbatim header text. The LAPI query below keeps
	// the raw text: LAPI matches numerically and does not care about spelling.
	ipKey := decisionscope.IPCacheKey(remoteIP)
	chosen, parsedDuration, err := c.queryLiveDecisions(fmt.Sprintf("ip=%v", remoteIP))
	if err != nil {
		return "", err
	}
	// Keep the first scope failure. Every failing scope is already named by its own WARN line,
	// and an active remediation below still outranks all of them.
	var scopeErr error
	for scope, identifier := range scopes {
		scopeChosen, scopeDuration, mergeErr := c.mergeLiveScope(chosen, parsedDuration, scope, identifier, isLiveMode, defaultDecisionSeconds)
		chosen, parsedDuration = scopeChosen, scopeDuration
		if mergeErr != nil && scopeErr == nil {
			scopeErr = mergeErr
		}
	}
	// An active remediation is a real decision, so it outranks a scope failure and comes back with
	// the "banned" error. A scope failure must never downgrade or mask it.
	if decisionscope.IsActiveRemediation(chosen) {
		if isLiveMode && defaultDecisionSeconds > 0 {
			c.cacheClient.Set(ipKey, chosen, liveCacheTTL(parsedDuration, defaultDecisionSeconds))
		}
		return chosen, errors.New("handleNoStreamCache:banned")
	}
	// A failed scope query is not "no decision". Report it the way a failed IP query is already
	// reported - empty remediation plus the error - so the caller applies
	// CrowdsecLapiFailureAction. Caching the unverified allow would outlive the outage.
	if scopeErr != nil {
		return "", scopeErr
	}
	if isLiveMode && defaultDecisionSeconds > 0 {
		c.cacheClient.Set(ipKey, decisionscope.NoBannedValue, defaultDecisionSeconds)
	}
	return decisionscope.NoBannedValue, nil
}
