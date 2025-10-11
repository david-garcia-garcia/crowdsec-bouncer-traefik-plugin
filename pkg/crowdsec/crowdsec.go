/*TODO: NEEDS HUMAN REVIEW*/
package crowdsec

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecclient"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decision"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/metrics"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/types"
)

// Config contains configuration for the CrowdSec component
type Config struct {
	// Connection settings
	Scheme string
	Host   string
	Path   string
	Key    string
	Mode   string

	// CAPI settings (for alone mode)
	MachineID string
	Password  string
	Scenarios []string

	// Update settings
	UpdateIntervalSeconds int64
	UpdateMaxFailure      int64

	// Metrics settings
	MetricsUpdateIntervalSeconds int64

	// Header settings for Country/ASN
	CountryHeader string
	ASNHeader     string

	// AppSec settings
	AppSecConfig *decision.AppSecConfig

	// HTTP client
	HTTPClient *http.Client
}

// Component manages CrowdSec integration and decision providers
type Component struct {
	mu               sync.RWMutex
	config           *Config
	log              *logger.Log
	metricsCollector *metrics.MetricsCollector

	// API clients
	crowdsecClient *crowdsecclient.Client
	appsecClient   *crowdsecclient.AppSecClient

	// Decision providers
	ipProvider      decision.DecisionProvider
	rangeProvider   decision.DecisionProvider
	countryProvider decision.DecisionProvider
	asnProvider     decision.DecisionProvider
	appsecProvider  *decision.AppSecDecisionProvider

	// Stream management
	streamTicker    chan bool
	metricsTicker   chan bool
	isStreamHealthy bool
	updateFailure   int64
	isStartup       bool
}

// Login struct moved to crowdsecclient package

// NewComponent creates a new CrowdSec component
func NewComponent(ctx context.Context, config *Config, log *logger.Log) (*Component, error) {
	// Create CrowdSec API client
	crowdsecClientConfig := &crowdsecclient.Config{
		Scheme:     config.Scheme,
		Host:       config.Host,
		Path:       config.Path,
		Key:        config.Key,
		Mode:       config.Mode,
		MachineID:  config.MachineID,
		Password:   config.Password,
		Scenarios:  config.Scenarios,
		HTTPClient: config.HTTPClient,
	}
	crowdsecClient := crowdsecclient.NewClient(crowdsecClientConfig, log)

	// Create AppSec client if enabled
	var appsecClient *crowdsecclient.AppSecClient
	if config.AppSecConfig != nil && config.AppSecConfig.Enabled {
		appsecClientConfig := &crowdsecclient.AppSecConfig{
			Enabled:          config.AppSecConfig.Enabled,
			Host:             config.AppSecConfig.Host,
			Path:             config.AppSecConfig.Path,
			Scheme:           config.Scheme,
			Key:              config.Key,
			BodyLimit:        config.AppSecConfig.BodyLimit,
			FailureBlock:     config.AppSecConfig.FailureBlock,
			UnreachableBlock: config.AppSecConfig.UnreachableBlock,
			HTTPClient:       config.HTTPClient,
		}
		appsecClient = crowdsecclient.NewAppSecClient(appsecClientConfig, log)
	}

	// Create metrics collector
	metricsConfig := &metrics.Config{
		ReportingEnabled: config.MetricsUpdateIntervalSeconds > 0,
		CrowdsecClient:   crowdsecClient,
	}
	metricsCollector := metrics.NewMetricsCollector(log, metricsConfig)

	// Create decision providers (we'll need to get cache client from bouncer)
	// These will be updated when we have the cache client available
	var ipProvider decision.DecisionProvider
	var rangeProvider decision.DecisionProvider
	var countryProvider decision.DecisionProvider
	var asnProvider decision.DecisionProvider

	var appsecProvider *decision.AppSecDecisionProvider
	if config.AppSecConfig != nil && config.AppSecConfig.Enabled {
		appsecProvider = decision.NewAppSecDecisionProvider(log, config.AppSecConfig)
	}

	component := &Component{
		config:           config,
		log:              log,
		metricsCollector: metricsCollector,
		crowdsecClient:   crowdsecClient,
		appsecClient:     appsecClient,
		ipProvider:       ipProvider,
		rangeProvider:    rangeProvider,
		countryProvider:  countryProvider,
		asnProvider:      asnProvider,
		appsecProvider:   appsecProvider,
		isStreamHealthy:  true,
		isStartup:        true,
	}

	// Initialize clients
	if err := crowdsecClient.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize CrowdSec client: %w", err)
	}

	// Start stream ticker for stream and alone modes
	if config.Mode == "stream" || config.Mode == "alone" {
		component.handleStreamTicker()
		component.isStartup = false
		component.streamTicker = component.startTicker("stream", config.UpdateIntervalSeconds, func() {
			component.handleStreamTicker()
		})
	}

	// Start metrics ticker if enabled
	if config.MetricsUpdateIntervalSeconds > 0 {
		component.handleMetricsTicker()
		component.metricsTicker = component.startTicker("metrics", config.MetricsUpdateIntervalSeconds, func() {
			component.handleMetricsTicker()
		})
	}

	log.Debug(fmt.Sprintf("CrowdSec component initialized in mode: %s", config.Mode))

	return component, nil
}

// InitializeProviders initializes the decision providers with the cache client
func (c *Component) InitializeProviders(cacheClient *cache.Client) error {
	c.ipProvider = decision.NewIPDecisionProvider(c.log, cacheClient)
	c.rangeProvider = decision.NewRangeDecisionProvider(c.log)
	c.countryProvider = decision.NewCountryDecisionProvider(c.log, cacheClient, c.config.CountryHeader != "")
	c.asnProvider = decision.NewASNDecisionProvider(c.log, cacheClient, c.config.ASNHeader != "")

	c.log.Debug("Decision providers initialized with cache client")
	return nil
}

// CheckDecision checks if a request should be blocked (mode specified in request)
func (c *Component) CheckDecision(req *decision.DecisionRequest) (*decision.DecisionResult, error) {
	// Handle different modes based on request parameter
	switch req.Mode {
	case "none":
		return c.checkNoneMode(req)
	case "live":
		return c.checkLiveMode(req)
	case "stream", "alone":
		return c.checkStreamMode(req)
	case "appsec":
		// AppSec mode only checks AppSec provider
		return c.checkAppSecProvider(req)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", req.Mode)
	}
}

// checkNoneMode queries CrowdSec API for every request
func (c *Component) checkNoneMode(req *decision.DecisionRequest) (*decision.DecisionResult, error) {
	if req.IP == nil {
		return &decision.DecisionResult{Blocked: false}, nil
	}

	// Query CrowdSec API directly for this IP
	decisions, err := c.crowdsecClient.GetDecisions(req.IPString)
	if err != nil {
		return nil, fmt.Errorf("failed to get decisions for IP %s: %w", req.IPString, err)
	}

	if len(decisions) == 0 {
		return &decision.DecisionResult{Blocked: false}, nil
	}

	// Find the most restrictive decision (ban > captcha)
	var selectedDecision *types.CrowdSecDecision
	for _, d := range decisions {
		if selectedDecision == nil || d.Type == "ban" {
			selectedDecision = &d
			if d.Type == "ban" {
				break // Ban is most restrictive
			}
		}
	}

	var decisionType decision.DecisionType
	switch selectedDecision.Type {
	case "ban":
		decisionType = decision.TypeBan
	case "captcha":
		decisionType = decision.TypeCaptcha
	default:
		decisionType = decision.TypeBan
	}

	result := &decision.DecisionResult{
		Blocked:   true,
		Type:      decisionType,
		Scenario:  selectedDecision.Scenario,
		Value:     req.IPString,
		MatchedBy: decision.ScopeIP,
	}

	c.metricsCollector.RecordBlockedRequest(result)
	return result, nil
}

// checkLiveMode uses cache with fallback to API
func (c *Component) checkLiveMode(req *decision.DecisionRequest) (*decision.DecisionResult, error) {
	// First check cache (providers handle cache internally)
	result, err := c.checkProviders(req)
	if err != nil {
		return nil, err
	}
	if result.Blocked {
		return result, nil
	}

	// Cache miss - query API and cache result
	decisions, err := c.crowdsecClient.GetDecisions(req.IPString)
	if err != nil {
		return nil, fmt.Errorf("failed to get decisions for IP %s: %w", req.IPString, err)
	}

	if len(decisions) == 0 {
		// No decision - cache the negative result
		if c.ipProvider != nil {
			c.ipProvider.AddDecision(decision.ScopeIP, req.IPString, &decision.DecisionInfo{
				Type:      decision.TypeAllow,
				Source:    decision.SourceCrowdSec,
				Scenario:  "live_mode_allow",
				ExpiresAt: time.Now().Add(time.Duration(c.config.UpdateIntervalSeconds) * time.Second),
				Value:     req.IPString,
			})
		}
		return &decision.DecisionResult{Blocked: false}, nil
	}

	// Process the decision and cache it
	selectedDecision := &decisions[0]
	for _, d := range decisions {
		if d.Type == "ban" {
			selectedDecision = &d
			break
		}
	}

	duration, err := time.ParseDuration(selectedDecision.Duration)
	if err != nil {
		duration = time.Duration(c.config.UpdateIntervalSeconds) * time.Second
	}

	var decisionType decision.DecisionType
	switch selectedDecision.Type {
	case "ban":
		decisionType = decision.TypeBan
	case "captcha":
		decisionType = decision.TypeCaptcha
	default:
		decisionType = decision.TypeBan
	}

	// Cache the decision
	decisionInfo := &decision.DecisionInfo{
		Type:      decisionType,
		Source:    decision.SourceCrowdSec,
		Scenario:  selectedDecision.Scenario,
		ExpiresAt: time.Now().Add(duration),
		Value:     req.IPString,
	}

	if c.ipProvider != nil {
		c.ipProvider.AddDecision(decision.ScopeIP, req.IPString, decisionInfo)
	}

	result = &decision.DecisionResult{
		Blocked:   true,
		Type:      decisionType,
		Scenario:  selectedDecision.Scenario,
		Value:     req.IPString,
		MatchedBy: decision.ScopeIP,
	}

	c.metricsCollector.RecordBlockedRequest(result)
	return result, nil
}

// checkStreamMode uses cached decisions from stream updates
func (c *Component) checkStreamMode(req *decision.DecisionRequest) (*decision.DecisionResult, error) {
	// Check if stream is healthy (only for stream and alone modes)
	if (req.Mode == "stream" || req.Mode == "alone") && !c.IsStreamHealthy() {
		return nil, fmt.Errorf("stream is unhealthy for mode %s", req.Mode)
	}

	// Check all providers (they contain decisions from stream updates)
	return c.checkProviders(req)
}

// checkProviders checks all decision providers in order of specificity
func (c *Component) checkProviders(req *decision.DecisionRequest) (*decision.DecisionResult, error) {
	// Check providers in order of specificity (most specific first)

	// 1. Check IP first (most specific)
	if c.ipProvider != nil {
		if result, err := c.ipProvider.Check(req); err != nil {
			return nil, err
		} else if result.Blocked {
			c.metricsCollector.RecordBlockedRequest(result)
			return result, nil
		}
	}

	// 2. Check IP ranges
	if c.rangeProvider != nil {
		if result, err := c.rangeProvider.Check(req); err != nil {
			return nil, err
		} else if result.Blocked {
			c.metricsCollector.RecordBlockedRequest(result)
			return result, nil
		}
	}

	// 3. Check country (if enabled and country provided)
	if c.countryProvider != nil {
		if result, err := c.countryProvider.Check(req); err != nil {
			return nil, err
		} else if result.Blocked {
			c.metricsCollector.RecordBlockedRequest(result)
			return result, nil
		}
	}

	// 4. Check ASN (if enabled and ASN provided)
	if c.asnProvider != nil {
		if result, err := c.asnProvider.Check(req); err != nil {
			return nil, err
		} else if result.Blocked {
			c.metricsCollector.RecordBlockedRequest(result)
			return result, nil
		}
	}

	// 5. Check AppSec (if enabled and HTTP request provided)
	if c.appsecProvider != nil && req.HTTPReq != nil {
		if result, err := c.appsecProvider.CheckHTTPRequest(req.IPString, req.HTTPReq); err != nil {
			return nil, err
		} else if result.Blocked {
			c.metricsCollector.RecordBlockedRequest(result)
			return result, nil
		}
	}

	return &decision.DecisionResult{Blocked: false}, nil
}

// checkAppSecProvider checks only the AppSec provider (for appsec mode)
func (c *Component) checkAppSecProvider(req *decision.DecisionRequest) (*decision.DecisionResult, error) {
	if c.appsecProvider == nil || req.HTTPReq == nil {
		return &decision.DecisionResult{Blocked: false}, nil
	}

	result, err := c.appsecProvider.CheckHTTPRequest(req.IPString, req.HTTPReq)
	if err != nil {
		return nil, err
	}

	if result.Blocked {
		c.metricsCollector.RecordBlockedRequest(result)
	}

	return result, nil
}

// CheckAppSec method removed - AppSec now integrated as a provider in CheckDecision

// IsStreamHealthy returns whether the stream is healthy
func (c *Component) IsStreamHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isStreamHealthy
}

// GetStats returns statistics from the component
func (c *Component) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"stream_healthy":  c.IsStreamHealthy(),
		"update_failures": c.updateFailure,
		"metrics":         c.metricsCollector.GetMetricsSummary(),
	}
}

// Shutdown gracefully shuts down the component
func (c *Component) Shutdown() {
	c.log.Debug("Shutting down CrowdSec component")

	if c.streamTicker != nil {
		close(c.streamTicker)
	}

	if c.metricsTicker != nil {
		close(c.metricsTicker)
	}
}

// handleStreamTicker handles stream updates
func (c *Component) handleStreamTicker() {
	if err := c.handleStreamCache(); err != nil {
		c.log.Debug(fmt.Sprintf("Stream update failed (failure %d, healthy: %t): %s",
			c.updateFailure, c.isStreamHealthy, err.Error()))

		if c.config.UpdateMaxFailure != -1 && c.updateFailure >= c.config.UpdateMaxFailure && c.isStreamHealthy {
			c.mu.Lock()
			c.isStreamHealthy = false
			c.mu.Unlock()
			c.log.Error(fmt.Sprintf("Stream marked unhealthy after %d failures: %s", c.updateFailure, err.Error()))
		}
		c.updateFailure++
	} else {
		c.mu.Lock()
		c.isStreamHealthy = true
		c.updateFailure = 0
		c.mu.Unlock()
	}
}

// handleMetricsTicker handles metrics reporting
func (c *Component) handleMetricsTicker() {
	if err := c.metricsCollector.ReportMetrics(); err != nil {
		c.log.Error("Failed to report metrics: " + err.Error())
	}
}

// startTicker starts a ticker for periodic tasks
func (c *Component) startTicker(name string, intervalSeconds int64, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
	stop := make(chan bool, 1)

	go func() {
		defer c.log.Debug(name + "_ticker:stopped")
		for {
			select {
			case <-ticker.C:
				go work()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()

	return stop
}

// Token management moved to crowdsecclient package

// handleStreamCache handles stream cache updates
func (c *Component) handleStreamCache() error {
	stream, err := c.crowdsecClient.GetDecisionStream(!c.isStreamHealthy || c.isStartup)
	if err != nil {
		return err
	}

	// Process new decisions
	for _, csDecision := range stream.New {
		decisionInfo, err := c.convertCrowdSecDecision(&csDecision)
		if err != nil {
			c.log.Error(fmt.Sprintf("Failed to convert decision: %s", err.Error()))
			continue
		}

		scope := decision.DecisionScope(csDecision.Scope)
		if err := c.addDecisionToProvider(scope, csDecision.Value, decisionInfo); err != nil {
			c.log.Error(fmt.Sprintf("Failed to add decision: %s", err.Error()))
		}
	}

	// Process deleted decisions
	for _, csDecision := range stream.Deleted {
		scope := decision.DecisionScope(csDecision.Scope)
		if err := c.removeDecisionFromProvider(scope, csDecision.Value); err != nil {
			c.log.Error(fmt.Sprintf("Failed to remove decision: %s", err.Error()))
		}
	}

	c.log.Debug(fmt.Sprintf("Stream updated: %d new, %d deleted decisions",
		len(stream.New), len(stream.Deleted)))

	return nil
}

// convertCrowdSecDecision converts a CrowdSec decision to our internal format
func (c *Component) convertCrowdSecDecision(csDecision *types.CrowdSecDecision) (*decision.DecisionInfo, error) {
	duration, err := time.ParseDuration(csDecision.Duration)
	if err != nil {
		return nil, fmt.Errorf("invalid duration %s: %w", csDecision.Duration, err)
	}

	var decisionType decision.DecisionType
	switch csDecision.Type {
	case "ban":
		decisionType = decision.TypeBan
	case "captcha":
		decisionType = decision.TypeCaptcha
	default:
		decisionType = decision.TypeBan // Default to ban for unknown types
	}

	return &decision.DecisionInfo{
		Type:      decisionType,
		Source:    decision.SourceCrowdSec,
		Scenario:  csDecision.Scenario,
		ExpiresAt: time.Now().Add(duration),
		Value:     csDecision.Value,
	}, nil
}

// addDecisionToProvider adds a decision to the appropriate provider
func (c *Component) addDecisionToProvider(scope decision.DecisionScope, value string, decisionInfo *decision.DecisionInfo) error {
	switch scope {
	case decision.ScopeIP:
		return c.ipProvider.AddDecision(scope, value, decisionInfo)
	case decision.ScopeRange:
		return c.rangeProvider.AddDecision(scope, value, decisionInfo)
	case decision.ScopeCountry:
		return c.countryProvider.AddDecision(scope, value, decisionInfo)
	case decision.ScopeAS:
		return c.asnProvider.AddDecision(scope, value, decisionInfo)
	default:
		return fmt.Errorf("unsupported decision scope: %s", scope)
	}
}

// removeDecisionFromProvider removes a decision from the appropriate provider
func (c *Component) removeDecisionFromProvider(scope decision.DecisionScope, value string) error {
	switch scope {
	case decision.ScopeIP:
		return c.ipProvider.RemoveDecision(scope, value)
	case decision.ScopeRange:
		return c.rangeProvider.RemoveDecision(scope, value)
	case decision.ScopeCountry:
		return c.countryProvider.RemoveDecision(scope, value)
	case decision.ScopeAS:
		return c.asnProvider.RemoveDecision(scope, value)
	default:
		return fmt.Errorf("unsupported decision scope: %s", scope)
	}
}

// HTTP communication moved to crowdsecclient package
