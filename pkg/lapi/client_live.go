package lapi

import (
	"errors"
	"fmt"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
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
func (c *Client) LiveLookup(remoteIP string, scopes map[string]string, defaultDecisionSeconds int64) (string, string, error) {
	return c.handleNoStreamCache(remoteIP, scopes, defaultDecisionSeconds)
}

// handleNoStreamCache queries LAPI for the client address and each mapped header, writes the
// IP query result to the client-address cache key, and returns the PreferRemediation merge.
func (c *Client) handleNoStreamCache(remoteIP string, scopes map[string]string, defaultDecisionSeconds int64) (string, string, error) {
	isLiveMode := c.crowdsecMode == configuration.LiveMode
	// remoteIP is already canonical on clientRequest. Do not re-parse it for the memo key.
	// LAPI ?ip= matches numerically and does not care about spelling.
	chosen, err := c.queryLiveDecisions(fmt.Sprintf("ip=%v", remoteIP))
	if err != nil {
		return "", "", err
	}
	// Keep the IP query result for the client-address slot. Header merge mutates chosen.
	ipResult := chosen
	// Keep the first scope failure. Every failing scope is already named by its own WARN line,
	// and an active remediation below still outranks all of them.
	var scopeErr error
	for scope, identifier := range scopes {
		scopeChosen, mergeErr := c.mergeLiveScope(chosen, scope, identifier, isLiveMode, defaultDecisionSeconds)
		chosen = scopeChosen
		if mergeErr != nil && scopeErr == nil {
			scopeErr = mergeErr
		}
	}
	// The IP slot stores the IP query result. Header remediations stay on HeaderScopeKey.
	// A clean IP result is not written when a header query failed (fail-closed).
	if isLiveMode && defaultDecisionSeconds > 0 {
		if decisionscope.IsActiveRemediation(ipResult.kind) {
			c.memoLive(decisionscope.ScopeIP, remoteIP, ipResult.kind, ipResult.origin, liveCacheTTL(ipResult.duration, defaultDecisionSeconds))
		} else if scopeErr == nil {
			c.memoLive(decisionscope.ScopeIP, remoteIP, decisionscope.NoBannedValue, "", defaultDecisionSeconds)
		}
	}
	// An active remediation is a real decision, so it outranks a scope failure and comes back with
	// the "banned" error. A scope failure must never downgrade or mask it.
	if decisionscope.IsActiveRemediation(chosen.kind) {
		return chosen.kind, chosen.origin, errors.New("handleNoStreamCache:banned")
	}
	// A failed scope query is not "no decision". Report it the way a failed IP query is already
	// reported - empty remediation plus the error - so the caller applies
	// CrowdsecLapiFailureAction. Caching the unverified allow would outlive the outage.
	if scopeErr != nil {
		return "", "", scopeErr
	}
	return decisionscope.NoBannedValue, "", nil
}
