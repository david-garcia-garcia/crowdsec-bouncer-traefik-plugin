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

func (c *CrowdsecConnection) storeStreamDecision(item Decision, duration int64) {
	value := decisionscope.RemediationValue(item.Type)
	if value == "" {
		c.log.Debug("handleStreamCache:unknownType " + item.Type)
		return
	}
	scope := decisionscope.NormalizeScope(item.Scope)
	switch scope {
	case decisionscope.ScopeIP, "":
		c.cacheClient.Set(decisionscope.IPCacheKey(item.Value), value, duration)
	case decisionscope.ScopeRange:
		decisionscope.AddRange(c.cacheClient, item.Value, value, duration)
	default:
		if _, ok := c.decisionScopeHeaders[scope]; !ok {
			c.log.Debug("handleStreamCache:ignoredScope " + item.Scope)
			return
		}
		identifier := decisionscope.NormalizeHeaderScopeValue(scope, item.Value)
		if identifier == "" {
			return
		}
		c.cacheClient.Set(decisionscope.HeaderScopeKey(scope, identifier), value, duration)
	}
}

func (c *CrowdsecConnection) deleteStreamDecision(item Decision) {
	scope := decisionscope.NormalizeScope(item.Scope)
	switch scope {
	case decisionscope.ScopeIP, "":
		c.cacheClient.Delete(decisionscope.IPCacheKey(item.Value))
		c.cacheClient.Delete(item.Value)
	case decisionscope.ScopeRange:
		decisionscope.RemoveRange(c.cacheClient, item.Value)
	default:
		identifier := decisionscope.NormalizeHeaderScopeValue(scope, item.Value)
		if identifier != "" {
			c.cacheClient.Delete(decisionscope.HeaderScopeKey(scope, identifier))
		}
	}
}

func (c *CrowdsecConnection) queryLiveDecisions(rawQuery string) (string, time.Duration, error) {
	routeURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + crowdsecLapiRoute,
		RawQuery: rawQuery,
	}
	body, err := c.crowdsecQuery(routeURL.String(), nil)
	if err != nil {
		return cache.BannedValue, 0, err
	}
	if bytes.Equal(body, []byte("null")) {
		return cache.NoBannedValue, 0, nil
	}
	var items []Decision
	err = json.Unmarshal(body, &items)
	if err != nil {
		return cache.BannedValue, 0, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(items) == 0 {
		return cache.NoBannedValue, 0, nil
	}
	picked := pickDecision(items)
	if picked == nil {
		return cache.NoBannedValue, 0, nil
	}
	parsedDuration, err := time.ParseDuration(picked.Duration)
	if err != nil {
		return cache.BannedValue, 0, fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	value := decisionscope.RemediationValue(picked.Type)
	if value == "" {
		return cache.NoBannedValue, 0, nil
	}
	return value, parsedDuration, nil
}

func pickDecision(items []Decision) *Decision {
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

func (c *CrowdsecConnection) liveCacheTTL(parsedDuration time.Duration) int64 {
	durationSecond := int64(parsedDuration.Seconds())
	if durationSecond <= 0 || c.defaultDecisionTimeout < durationSecond {
		return c.defaultDecisionTimeout
	}
	return durationSecond
}
