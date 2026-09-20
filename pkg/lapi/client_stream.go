package lapi

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
)

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
	if c.decisionStore != nil {
		c.decisionStore.HydrateRange()
	}
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

// handleStreamTicker runs one stream poll unless the store already owns a poll.
// Skip is session-scoped on DecisionStore (cursor+applied cache), not this Client.
func (c *Client) handleStreamTicker() {
	if c.decisionStore == nil || !c.decisionStore.TryBeginStreamPoll() {
		c.log.Warn("handleStreamTicker:skip", "sessionKey", c.sessionKey, "reason", "inFlight")
		return
	}
	defer c.decisionStore.EndStreamPoll()

	started := time.Now()
	startup := c.streamStartup()
	c.log.Debug("handleStreamTicker:poll",
		"sessionKey", c.sessionKey,
		"startup", startup,
		"interval", c.updateInterval,
	)
	if err := c.handleStreamCache(); err != nil {
		updateFailure := atomic.LoadInt64(&c.updateFailure)
		healthy := atomic.LoadInt64(&c.isCrowdsecStreamHealthy) != 0
		c.log.Warn("handleStreamTicker",
			"sessionKey", c.sessionKey,
			"startup", startup,
			"updateFailure", updateFailure,
			"isCrowdsecStreamHealthy", healthy,
			"durationMs", time.Since(started).Milliseconds(),
			"error", err,
		)
		if c.updateMaxFailure != -1 && updateFailure >= c.updateMaxFailure && healthy {
			atomic.StoreInt64(&c.isCrowdsecStreamHealthy, 0)
			c.logInfo(MsgStreamUnhealthy, "unhealthy")
			c.log.Error("handleStreamTicker:error", "sessionKey", c.sessionKey, "updateFailure", updateFailure, "error", err)
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

// handleStreamCache GETs stream, applies the payload, and logs the finish line at DEBUG.
func (c *Client) handleStreamCache() error {
	started := time.Now()
	startup := c.streamStartup()
	newCount, deletedCount, pollErr := c.fetchAndApplyStreamDecisions()
	if pollErr != nil {
		return pollErr
	}
	c.log.Debug("handleStreamCache:updated",
		"sessionKey", c.sessionKey,
		"startup", startup,
		"new", newCount,
		"deleted", deletedCount,
		"durationMs", time.Since(started).Milliseconds(),
		"fetches", atomic.LoadInt64(&c.streamFetches),
	)
	atomic.StoreInt64(&c.isCrowdsecStreamStartup, 0)
	c.decisionStore.MarkStreamReady()
	return nil
}

// fetchAndApplyStreamDecisions GETs the CrowdSec stream delta and writes it into the DecisionStore.
// Deleted is applied before New so a same-window replacement for the same IP or CIDR stays active.
// newCount and deletedCount are decisions written into the store, not raw payload length.
func (c *Client) fetchAndApplyStreamDecisions() (int, int, error) {
	streamRouteURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + c.crowdsecStreamRoute,
		RawQuery: c.streamQuery(),
	}
	atomic.AddInt64(&c.streamFetches, 1)
	body, err := c.crowdsecQuery(streamRouteURL.String(), nil)
	if err != nil {
		return 0, 0, err
	}
	var stream Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		return 0, 0, fmt.Errorf("handleStreamCache:parsingBody %w", err)
	}
	c.decisionStore.BeginTick()
	defer c.decisionStore.PublishTick(decisionstore.ElapsedNow())
	rangeUpserts := make(map[string]string)
	var rangeRemovals []string
	deletes := make([]decisionstore.Decision, 0)
	deletedCount := 0
	for _, decision := range stream.Deleted {
		if decisionscope.NormalizeScope(decision.Scope) == decisionscope.ScopeRange {
			if cidr := strings.TrimSpace(decision.Value); cidr != "" {
				rangeRemovals = append(rangeRemovals, cidr)
				deletedCount++
			}
			continue
		}
		stored, ok := c.streamDeleteItem(decision)
		if !ok {
			continue
		}
		deletedCount++
		deletes = append(deletes, stored)
		if len(deletes) >= decisionstore.PutManyChunk {
			c.decisionStore.DeleteMany(deletes)
			deletes = deletes[:0]
		}
	}
	c.decisionStore.DeleteMany(deletes)
	puts := make([]decisionstore.Decision, 0)
	newCount := 0
	for _, decision := range stream.New {
		duration, parseErr := time.ParseDuration(decision.Duration)
		if parseErr != nil {
			continue
		}
		if decisionscope.NormalizeScope(decision.Scope) == decisionscope.ScopeRange {
			kind := decisionscope.RemediationValue(decision.Type)
			cidr := strings.TrimSpace(decision.Value)
			if kind != "" && cidr != "" {
				origin := MetricsOrigin(decision.Origin, decision.Scenario)
				rangeUpserts[cidr] = decisionstore.KindOriginString(kind, origin)
				newCount++
			}
			continue
		}
		// Sub-second CrowdSec durations become 0; stream write TTL is not clamped.
		stored, ok := c.streamPutItem(decision, int64(duration.Seconds()))
		if !ok {
			continue
		}
		newCount++
		puts = append(puts, stored)
		if len(puts) >= decisionstore.PutManyChunk {
			c.decisionStore.PutMany(puts)
			puts = puts[:0]
		}
	}
	c.decisionStore.PutMany(puts)
	// A range apply that could not read the shared index is a poll that did not finish.
	// isCrowdsecStreamStartup stays set so the retry asks for the full set again.
	if err := c.decisionStore.ApplyRangeBatch(rangeUpserts, rangeRemovals); err != nil {
		return 0, 0, fmt.Errorf("handleStreamCache:rangeIndex %w", err)
	}
	return newCount, deletedCount, nil
}
