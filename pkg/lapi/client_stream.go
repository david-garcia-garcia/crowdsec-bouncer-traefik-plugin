package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const cacheTimeoutKey = "updated"

// Stream is the body returned from Crowdsec Stream LAPI.
type Stream struct {
	Deleted []Decision `json:"deleted"`
	New     []Decision `json:"new"`
}

// startStream starts the stream ticker and initial poll for stream and alone modes.
func (c *Client) startStream(config *configuration.Config, log *slog.Logger) error {
	if config.CrowdsecMode != configuration.StreamMode && config.CrowdsecMode != configuration.AloneMode {
		return nil
	}
	if config.CrowdsecMode == configuration.AloneMode {
		if err := c.getToken(); err != nil {
			c.log.Error("startStream:getToken", "error", err)
			return err
		}
	}
	c.hydrateRangeMembership()
	if config.StreamStartupBlock {
		c.handleStreamTicker()
	} else {
		go c.handleStreamTicker()
	}
	c.streamStop = startTicker("stream", config.UpdateIntervalSeconds, log, func() {
		c.handleStreamTicker()
	})
	return nil
}

func (c *Client) handleStreamTicker() {
	if !atomic.CompareAndSwapInt64(&c.streamPollInFlight, 0, 1) {
		return
	}
	defer atomic.StoreInt64(&c.streamPollInFlight, 0)

	if err := c.handleStreamCache(); err != nil {
		updateFailure := atomic.LoadInt64(&c.updateFailure)
		healthy := atomic.LoadInt64(&c.isCrowdsecStreamHealthy) != 0
		c.log.Warn("handleStreamTicker", "updateFailure", updateFailure, "isCrowdsecStreamHealthy", healthy, "error", err)
		if c.updateMaxFailure != -1 && updateFailure >= c.updateMaxFailure && healthy {
			atomic.StoreInt64(&c.isCrowdsecStreamHealthy, 0)
			c.logInfo(MsgStreamUnhealthy, "unhealthy")
			c.log.Error("handleStreamTicker:error", "updateFailure", updateFailure, "error", err)
		}
		atomic.AddInt64(&c.updateFailure, 1)
	} else {
		if atomic.LoadInt64(&c.isCrowdsecStreamHealthy) == 0 {
			c.logInfo(MsgStreamHealthy, "healthy")
		}
		atomic.StoreInt64(&c.isCrowdsecStreamHealthy, 1)
		atomic.StoreInt64(&c.updateFailure, 0)
	}
}

func (c *Client) handleStreamCache() error {
	leaseDuration := c.updateInterval - 1
	if leaseDuration < 1 {
		leaseDuration = 1
	}
	// One acquire: Redis Eval or memory mutex. Do not Get-then-Set.
	won, err := c.Cache().Acquire(context.Background(), cacheTimeoutKey, decisionscope.NoBannedValue, leaseDuration)
	if err != nil {
		return err
	}
	if !won {
		c.log.Debug("handleStreamCache:alreadyUpdated")
		c.hydrateRangeMembership()
		atomic.StoreInt64(&c.isCrowdsecStreamStartup, 0)
		return nil
	}
	if pollErr := c.fetchAndApplyStreamDecisions(); pollErr != nil {
		// This tick owned the lease and did not finish, so the store was not updated. Drop the
		// key: the next tick retries now instead of waiting out max(updateInterval-1, 1) seconds.
		c.Cache().Delete(cacheTimeoutKey)
		return pollErr
	}
	c.log.Debug("handleStreamCache:updated")
	atomic.StoreInt64(&c.isCrowdsecStreamStartup, 0)
	return nil
}

// fetchAndApplyStreamDecisions GETs the CrowdSec stream delta and writes it into the DecisionStore.
// It does not own the stream lease; handleStreamCache does. Deleted is applied before New so a
// same-window replacement for the same IP or CIDR stays active.
func (c *Client) fetchAndApplyStreamDecisions() error {
	streamRouteURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + c.crowdsecStreamRoute,
		RawQuery: c.streamQuery(),
	}
	atomic.AddInt64(&c.streamFetches, 1)
	body, err := c.crowdsecQuery(streamRouteURL.String(), nil)
	if err != nil {
		return err
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		return fmt.Errorf("handleStreamCache:parsingBody %w", err)
	}
	rangeUpserts := make(map[string]string)
	var rangeRemovals []string
	for _, decision := range stream.Deleted {
		if decisionscope.NormalizeScope(decision.Scope) == decisionscope.ScopeRange {
			if cidr := strings.TrimSpace(decision.Value); cidr != "" {
				rangeRemovals = append(rangeRemovals, cidr)
				c.forgetActiveDecision("range:" + cidr)
			}
			continue
		}
		c.deleteStreamDecision(decision)
	}
	for _, decision := range stream.New {
		duration, parseErr := time.ParseDuration(decision.Duration)
		if parseErr != nil {
			continue
		}
		if decisionscope.NormalizeScope(decision.Scope) == decisionscope.ScopeRange {
			value := decisionscope.RemediationValue(decision.Type)
			cidr := strings.TrimSpace(decision.Value)
			if value != "" && cidr != "" {
				origin := MetricsOrigin(decision.Origin, decision.Scenario)
				rangeUpserts[cidr] = c.rangeIndexRemediation(value, origin)
				c.rememberActiveDecision("range:"+cidr, origin, cidr)
			}
			continue
		}
		// Sub-second CrowdSec durations become 0; stream write TTL is not clamped.
		c.storeStreamDecision(decision, int64(duration.Seconds()))
	}
	// A range apply that could not read the shared index is a poll that did not finish. Returning
	// the error releases the lease, so the next tick retries; because the tick failed,
	// isCrowdsecStreamStartup is left set and that retry asks for the full set again.
	if err := decisionscope.ApplyRangeBatch(c.Cache(), rangeUpserts, rangeRemovals); err != nil {
		return fmt.Errorf("handleStreamCache:rangeIndex %w", err)
	}
	c.hydrateRangeMembership()
	return nil
}
