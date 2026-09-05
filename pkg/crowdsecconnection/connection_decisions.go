package crowdsecconnection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// streamQuery is the LAPI/CAPI stream RawQuery. LAPI adds scopes= when this is not CAPI.
func (c *CrowdsecConnection) streamQuery() string {
	query := fmt.Sprintf("startup=%t", !c.isCrowdsecStreamHealthy || c.isCrowdsecStreamStartup)
	if c.crowdsecStreamRoute != crowdsecLapiStreamRoute {
		return query
	}
	return query + "&scopes=" + decisionscope.StreamScopeList(c.decisionScopeHeaders)
}

// storeStreamDecision writes one non-Range stream decision into the cache.
func (c *CrowdsecConnection) storeStreamDecision(item Decision, duration int64) {
	value := decisionscope.RemediationValue(item.Type)
	if value == "" {
		c.log.Debug("handleStreamCache:unknownType " + item.Type)
		return
	}
	origin := MetricsOrigin(item.Origin, item.Scenario)
	stored := cache.RemediationWithOrigin(value, origin)
	scope := decisionscope.NormalizeScope(item.Scope)
	switch scope {
	case decisionscope.ScopeIP, "":
		slot := decisionscope.IPCacheKey(item.Value)
		c.cacheClient.Set(slot, stored, duration)
		c.rememberActiveDecision(slot, origin, item.Value)
	case decisionscope.ScopeRange:
		return
	default:
		if _, ok := c.decisionScopeHeaders[scope]; !ok {
			c.log.Debug("handleStreamCache:ignoredScope " + item.Scope)
			return
		}
		identifier := decisionscope.NormalizeHeaderScopeValue(scope, item.Value)
		if identifier == "" {
			return
		}
		slot := decisionscope.HeaderScopeKey(scope, identifier)
		c.cacheClient.Set(slot, stored, duration)
		c.rememberActiveDecision(slot, origin, item.Value)
	}
}

// deleteStreamDecision drops one non-Range stream decision from the cache.
func (c *CrowdsecConnection) deleteStreamDecision(item Decision) {
	scope := decisionscope.NormalizeScope(item.Scope)
	switch scope {
	case decisionscope.ScopeIP, "":
		slot := decisionscope.IPCacheKey(item.Value)
		c.forgetActiveDecision(slot)
		c.cacheClient.Delete(slot)
		c.cacheClient.Delete(item.Value)
	case decisionscope.ScopeRange:
		return
	default:
		identifier := decisionscope.NormalizeHeaderScopeValue(scope, item.Value)
		if identifier != "" {
			slot := decisionscope.HeaderScopeKey(scope, identifier)
			c.forgetActiveDecision(slot)
			c.cacheClient.Delete(slot)
		}
	}
}

// queryLiveDecisions GETs LAPI decisions for rawQuery and returns the strongest remediation.
func (c *CrowdsecConnection) queryLiveDecisions(rawQuery string) (string, time.Duration, error) {
	routeURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + crowdsecLapiRoute,
		RawQuery: rawQuery,
	}
	body, err := c.crowdsecQuery(routeURL.String(), nil)
	if err != nil {
		return "", 0, err
	}
	if bytes.Equal(body, []byte("null")) {
		return cache.NoBannedValue, 0, nil
	}
	var items []Decision
	err = json.Unmarshal(body, &items)
	if err != nil {
		return "", 0, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(items) == 0 {
		return cache.NoBannedValue, 0, nil
	}
	picked := strongestLiveDecision(items)
	if picked == nil {
		return cache.NoBannedValue, 0, nil
	}
	parsedDuration, err := time.ParseDuration(picked.Duration)
	if err != nil {
		return "", 0, fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	value := decisionscope.RemediationValue(picked.Type)
	if value == "" {
		return cache.NoBannedValue, 0, nil
	}
	return cache.RemediationWithOrigin(value, MetricsOrigin(picked.Origin, picked.Scenario)), parsedDuration, nil
}

// strongestLiveDecision returns the first ban in items, else the first captcha.
func strongestLiveDecision(items []Decision) *Decision {
	var fallback *Decision
	for i := range items {
		if items[i].Type == "ban" {
			return &items[i]
		}
		if items[i].Type == "captcha" {
			fallback = &items[i]
		}
	}
	return fallback
}

// mergeLiveScope queries one header-mapped scope and keeps ban over the current live remediation.
func (c *CrowdsecConnection) mergeLiveScope(chosen string, parsedDuration time.Duration, scope, identifier string, isLiveMode bool) (string, time.Duration) {
	if identifier == "" {
		return chosen, parsedDuration
	}
	headerChosen, headerDuration, headerErr := c.queryLiveDecisions("scope=" + url.QueryEscape(scope) + "&value=" + url.QueryEscape(identifier))
	if headerErr != nil {
		c.log.Debug("handleNoStreamCache:scopeQuery " + scope + " " + headerErr.Error())
		return chosen, parsedDuration
	}
	c.cacheLiveScope(decisionscope.HeaderScopeKey(scope, identifier), headerChosen, headerDuration, isLiveMode)
	next := decisionscope.PreferRemediation(chosen, headerChosen)
	if next != chosen {
		return next, headerDuration
	}
	return chosen, parsedDuration
}

// cacheLiveScope stores a live/none header-scope result when live caching is on.
func (c *CrowdsecConnection) cacheLiveScope(key, value string, parsedDuration time.Duration, isLiveMode bool) {
	if !isLiveMode || c.defaultDecisionTimeout <= 0 {
		return
	}
	if !decisionscope.IsActiveRemediation(value) {
		c.cacheClient.Set(key, cache.NoBannedValue, c.defaultDecisionTimeout)
		return
	}
	c.cacheClient.Set(key, value, c.liveCacheTTL(parsedDuration))
}

// liveCacheTTL is the live-mode cache TTL: min(decision duration, defaultDecisionTimeout).
func (c *CrowdsecConnection) liveCacheTTL(parsedDuration time.Duration) int64 {
	durationSecond := int64(parsedDuration.Seconds())
	if durationSecond <= 0 || c.defaultDecisionTimeout < durationSecond {
		return c.defaultDecisionTimeout
	}
	return durationSecond
}
