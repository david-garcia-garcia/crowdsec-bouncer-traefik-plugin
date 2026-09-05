package crowdsecconnection

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

const cacheTimeoutKey = "updated"

// Stream is the body returned from Crowdsec Stream LAPI.
type Stream struct {
	Deleted []Decision `json:"deleted"`
	New     []Decision `json:"new"`
}

// startStream starts the stream ticker and initial poll for stream and alone modes.
func (c *CrowdsecConnection) startStream(config *configuration.Config, log *slog.Logger) error {
	if config.CrowdsecMode != configuration.StreamMode && config.CrowdsecMode != configuration.AloneMode {
		return nil
	}
	if config.CrowdsecMode == configuration.AloneMode {
		if err := c.getToken(); err != nil {
			c.log.Error("startStream:getToken " + err.Error())
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

func (c *CrowdsecConnection) handleStreamTicker() {
	if err := c.handleStreamCache(); err != nil {
		c.log.Warn(fmt.Sprintf("handleStreamTicker updateFailure:%d isCrowdsecStreamHealthy:%t %s", c.updateFailure, c.isCrowdsecStreamHealthy, err.Error()))
		if c.updateMaxFailure != -1 && c.updateFailure >= c.updateMaxFailure && c.isCrowdsecStreamHealthy {
			c.isCrowdsecStreamHealthy = false
			c.log.Error(fmt.Sprintf("handleStreamTicker:error updateFailure:%d %s", c.updateFailure, err.Error()))
		}
		c.updateFailure++
	} else {
		c.isCrowdsecStreamHealthy = true
		c.updateFailure = 0
	}
}

func (c *CrowdsecConnection) handleStreamCache() error {
	_, err := c.cacheClient.Get(cacheTimeoutKey)
	if err == nil {
		c.log.Debug("handleStreamCache:alreadyUpdated")
		c.hydrateRangeMembership()
		c.isCrowdsecStreamStartup = false
		return nil
	}
	if err.Error() != cache.CacheMiss {
		return err
	}
	leaseDuration := c.updateInterval - 1
	if leaseDuration < 1 {
		leaseDuration = 1
	}
	c.cacheClient.Set(cacheTimeoutKey, cache.NoBannedValue, leaseDuration)
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
	for _, decision := range stream.New {
		duration, parseErr := time.ParseDuration(decision.Duration)
		if parseErr != nil {
			continue
		}
		if decisionscope.NormalizeScope(decision.Scope) == decisionscope.ScopeRange {
			value := decisionscope.RemediationValue(decision.Type)
			cidr := strings.TrimSpace(decision.Value)
			if value != "" && cidr != "" {
				rangeUpserts[cidr] = value
			}
			continue
		}
		c.storeStreamDecision(decision, int64(duration.Seconds()))
	}
	for _, decision := range stream.Deleted {
		if decisionscope.NormalizeScope(decision.Scope) == decisionscope.ScopeRange {
			if cidr := strings.TrimSpace(decision.Value); cidr != "" {
				rangeRemovals = append(rangeRemovals, cidr)
			}
			continue
		}
		c.deleteStreamDecision(decision)
	}
	decisionscope.ApplyRangeBatch(c.cacheClient, rangeUpserts, rangeRemovals)
	c.hydrateRangeMembership()
	c.log.Debug("handleStreamCache:updated")
	c.isCrowdsecStreamStartup = false
	return nil
}
