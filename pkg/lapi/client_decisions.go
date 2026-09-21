package lapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

// streamStartup is whether this poll asks LAPI for the full decision set (startup=true).
func (c *Client) streamStartup() bool {
	return atomic.LoadInt64(&c.isCrowdsecStreamHealthy) == 0 || atomic.LoadInt64(&c.isCrowdsecStreamStartup) != 0
}

// streamQuery is the LAPI/CAPI stream RawQuery. LAPI adds scopes= when this is not CAPI.
func (c *Client) streamQuery() string {
	query := fmt.Sprintf("startup=%t", c.streamStartup())
	if c.crowdsecStreamRoute != crowdsecLapiStreamRoute {
		return query
	}
	return query + "&scopes=" + decisionscope.StreamScopeList(c.snapshotLiveHeaderScopes())
}

// storeStreamDecision Puts one non-Range stream decision into the DecisionStore.
func (c *Client) storeStreamDecision(item Decision, duration int64) {
	stored, ok := c.streamPutItem(item, duration)
	if !ok {
		return
	}
	c.decisionStore.PutMany([]decisionstore.Decision{stored})
}

// streamPutItem is the Ip/header stream New item to store, or false when the decision is skipped.
func (c *Client) streamPutItem(item Decision, duration int64) (decisionstore.Decision, bool) {
	origin := MetricsOrigin(item.Origin, item.Scenario)
	kind := c.remediationKind(item.Type, origin)
	if kind == "" {
		c.log.Debug("handleStreamCache:unknownType", "type", item.Type)
		return decisionstore.Decision{}, false
	}
	scope := decisionscope.NormalizeScope(item.Scope)
	if scope == decisionscope.ScopeRange {
		return decisionstore.Decision{}, false
	}
	if scope != decisionscope.ScopeIP && scope != "" {
		if _, ok := c.snapshotLiveHeaderScopes()[scope]; !ok {
			c.log.Debug("handleStreamCache:ignoredScope", "scope", item.Scope)
			return decisionstore.Decision{}, false
		}
	}
	if decisionstore.SlotKey(scope, item.Value) == "" {
		return decisionstore.Decision{}, false
	}
	return decisionstore.Decision{
		Scope: scope, Value: item.Value, Kind: kind, Origin: origin, DurationSec: duration,
	}, true
}

// deleteStreamDecision Deletes one non-Range stream decision from the DecisionStore.
func (c *Client) deleteStreamDecision(item Decision) {
	stored, ok := c.streamDeleteItem(item)
	if !ok {
		return
	}
	c.decisionStore.DeleteMany([]decisionstore.Decision{stored})
}

// streamDeleteItem is the Ip/header stream Deleted item to drop, or false when the decision is skipped.
func (c *Client) streamDeleteItem(item Decision) (decisionstore.Decision, bool) {
	scope := decisionscope.NormalizeScope(item.Scope)
	if scope == decisionscope.ScopeRange {
		return decisionstore.Decision{}, false
	}
	return decisionstore.Decision{Scope: scope, Value: item.Value}, true
}

// queryLiveDecisions GETs LAPI decisions for rawQuery and returns the strongest kind and origin.
func (c *Client) queryLiveDecisions(rawQuery string) (liveResult, error) {
	routeURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + crowdsecLapiRoute,
		RawQuery: rawQuery,
	}
	body, err := c.crowdsecQuery(routeURL.String(), nil)
	if err != nil {
		return liveResult{}, err
	}
	if bytes.Equal(body, []byte("null")) {
		return liveResult{kind: decisionscope.NoBannedValue}, nil
	}
	var items []Decision
	err = json.Unmarshal(body, &items)
	if err != nil {
		return liveResult{}, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(items) == 0 {
		return liveResult{kind: decisionscope.NoBannedValue}, nil
	}
	picked := c.strongestLiveDecision(items)
	if picked == nil {
		return liveResult{kind: decisionscope.NoBannedValue}, nil
	}
	parsedDuration, err := time.ParseDuration(picked.Duration)
	if err != nil {
		return liveResult{}, fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	origin := MetricsOrigin(picked.Origin, picked.Scenario)
	kind := c.remediationKind(picked.Type, origin)
	if kind == "" {
		return liveResult{kind: decisionscope.NoBannedValue}, nil
	}
	return liveResult{
		kind:     kind,
		origin:   origin,
		duration: parsedDuration,
	}, nil
}

// liveResult is one live/none LAPI query: kind, metrics origin, and decision TTL.
type liveResult struct {
	kind     string
	origin   string
	duration time.Duration
}

// preferLiveResult keeps ban over captcha over empty and the winner's origin and duration.
func preferLiveResult(current, incoming liveResult) liveResult {
	if decisionscope.PreferRemediation(current.kind, incoming.kind) != current.kind {
		return incoming
	}
	if current.kind == "" {
		return incoming
	}
	return current
}

// OriginName is a thin store forward. Unknown id is empty.
func (c *Client) OriginName(id uint16) string {
	if c == nil || c.decisionStore == nil {
		return ""
	}
	return c.decisionStore.OriginName(id)
}

// strongestLiveDecision returns the first still-ban after OriginBasedDecisionRemap, else the first captcha.
func (c *Client) strongestLiveDecision(items []Decision) *Decision {
	var fallback *Decision
	for i := range items {
		origin := MetricsOrigin(items[i].Origin, items[i].Scenario)
		kind := c.remediationKind(items[i].Type, origin)
		if kind == decisionscope.BannedValue {
			return &items[i]
		}
		if kind == decisionscope.CaptchaValue && fallback == nil {
			fallback = &items[i]
		}
	}
	return fallback
}

// mergeLiveScope queries one header-mapped scope and keeps ban over the current live remediation.
// A query failure is returned alongside the caller's unchanged verdict so the caller can fail
// closed instead of reading it as "this scope has no decision". It is logged at WARN because an
// operator must see a scope path that stopped answering.
func (c *Client) mergeLiveScope(chosen liveResult, scope, identifier string, isLiveMode bool, defaultDecisionSeconds int64) (liveResult, error) {
	if identifier == "" {
		return chosen, nil
	}
	headerChosen, headerErr := c.queryLiveDecisions("scope=" + url.QueryEscape(scope) + "&value=" + url.QueryEscape(identifier))
	if headerErr != nil {
		c.log.Warn("handleNoStreamCache:scopeQuery", "scope", scope, "error", headerErr)
		return chosen, headerErr
	}
	c.cacheLiveScope(scope, identifier, headerChosen, isLiveMode, defaultDecisionSeconds)
	return preferLiveResult(chosen, headerChosen), nil
}

// cacheLiveScope stores a live/none header-scope result when live caching is on.
func (c *Client) cacheLiveScope(scope, identifier string, result liveResult, isLiveMode bool, defaultDecisionSeconds int64) {
	if !isLiveMode || defaultDecisionSeconds <= 0 {
		return
	}
	if !decisionscope.IsActiveRemediation(result.kind) {
		c.memoLive(scope, identifier, decisionscope.NoBannedValue, "", defaultDecisionSeconds)
		return
	}
	c.memoLive(scope, identifier, result.kind, result.origin, liveCacheTTL(result.duration, defaultDecisionSeconds))
}

// memoLive writes a live/none TTL slot through the decision store.
func (c *Client) memoLive(scope, value, kind, origin string, durationSec int64) {
	if c == nil || c.decisionStore == nil {
		return
	}
	c.decisionStore.Put(decisionstore.Decision{
		Scope: scope, Value: value, Kind: kind, Origin: origin, DurationSec: durationSec,
	})
}

// liveCacheTTL is the live-mode cache TTL: min(decision duration, defaultDecisionSeconds).
func liveCacheTTL(duration time.Duration, defaultDecisionSeconds int64) int64 {
	durationSecond := int64(duration.Seconds())
	if durationSecond <= 0 || defaultDecisionSeconds < durationSecond {
		return defaultDecisionSeconds
	}
	return durationSecond
}
