// Package crowdsecconnection is the reclaim value for one Crowdsec LAPI/CAPI identity.
package crowdsecconnection

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	crowdsecAppsecIPHeader   = "X-Crowdsec-Appsec-Ip"
	crowdsecAppsecURIHeader  = "X-Crowdsec-Appsec-Uri"
	crowdsecAppsecHostHeader = "X-Crowdsec-Appsec-Host"
	crowdsecAppsecVerbHeader = "X-Crowdsec-Appsec-Verb"
	crowdsecAppsecHeader     = "X-Crowdsec-Appsec-Api-Key"
	crowdsecAppsecUserAgent  = "X-Crowdsec-Appsec-User-Agent"
	crowdsecLapiHeader       = "X-Api-Key"
	crowdsecLapiRoute        = "v1/decisions"
	crowdsecLapiStreamRoute  = "v1/decisions/stream"
	crowdsecLapiMetricsRoute = "v1/usage-metrics"
	crowdsecCapiHost         = "api.crowdsec.net"
	crowdsecCapiHeader       = "Authorization"
	crowdsecCapiLoginRoute   = "v2/watchers/login"
	crowdsecCapiStreamRoute  = "v2/decisions/stream"
	cacheTimeoutKey          = "updated"
)

// Decision is the body returned from Crowdsec LAPI.
type Decision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

// Stream is the body returned from Crowdsec Stream LAPI.
type Stream struct {
	Deleted []Decision `json:"deleted"`
	New     []Decision `json:"new"`
}

// Login is the body returned from Crowdsec Login CAPI.
type Login struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

// AppsecPolicy is per-route AppSec drop behavior. The HTTP client and host live on CrowdsecConnection.
type AppsecPolicy struct {
	FailureBlock        bool
	UnreachableBlock    bool
	UnreadableBodyBlock bool
}

// CrowdsecConnection owns stream ticker, isolated cache, LAPI/CAPI HTTP, metrics, and AppSec HTTP client.
type CrowdsecConnection struct {
	mu     sync.Mutex
	closed bool

	crowdsecScheme         string
	crowdsecHost           string
	crowdsecPath           string
	crowdsecKey            string
	crowdsecMode           string
	crowdsecMachineID      string
	crowdsecPassword       string
	crowdsecScenarios      []string
	updateInterval         int64
	updateMaxFailure       int64
	defaultDecisionTimeout int64
	crowdsecStreamRoute    string
	crowdsecHeader         string
	redisUnreachableBlock  bool

	appsecScheme    string
	appsecHost      string
	appsecPath      string
	appsecKey       string
	appsecBodyLimit int64

	httpClient       *http.Client
	httpAppsecClient *http.Client
	cacheClient      *cache.Client
	log              *slog.Logger

	isCrowdsecStreamStartup bool
	isCrowdsecStreamHealthy bool
	updateFailure           int64
	streamStop              chan bool
	metricsStop             chan bool
	lastMetricsPush         time.Time
	blockedRequests         int64
	streamFetches           int64
}

// Prepare resolves secrets and CAPI/LAPI routing on cfg. Call before Key and New.
func Prepare(cfg *configuration.Config, log *slog.Logger) error {
	if cfg.CrowdsecMode == configuration.AloneMode {
		cfg.CrowdsecCapiMachineID, _ = configuration.GetVariable(cfg, "CrowdsecCapiMachineID")
		cfg.CrowdsecCapiPassword, _ = configuration.GetVariable(cfg, "CrowdsecCapiPassword")
		cfg.CrowdsecLapiScheme = configuration.HTTPS
		cfg.CrowdsecLapiHost = crowdsecCapiHost
		cfg.CrowdsecLapiPath = "/"
		cfg.UpdateIntervalSeconds = 7200
	} else {
		apiKey, errKey := configuration.GetVariable(cfg, "CrowdsecLapiKey")
		if errKey == nil {
			cfg.CrowdsecLapiKey = apiKey
		}
		if cfg.CrowdsecAppsecKey == "" {
			cfg.CrowdsecAppsecKey = cfg.CrowdsecLapiKey
		}
	}
	if cfg.CrowdsecAppsecEnabled {
		if cfg.CrowdsecAppsecScheme == "" {
			cfg.CrowdsecAppsecScheme = cfg.CrowdsecLapiScheme
		}
		apiAppsecKey, errAppsecKey := configuration.GetVariable(cfg, "CrowdsecAppsecKey")
		if errAppsecKey != nil {
			log.Info("Prepare:crowdsecAppsecKey fail to get CrowdsecAppsecKey and no client certificate setup " + errAppsecKey.Error())
		} else {
			cfg.CrowdsecAppsecKey = apiAppsecKey
		}
	}
	cfg.RedisCachePassword, _ = configuration.GetVariable(cfg, "RedisCachePassword")
	return nil
}

// New constructs a CrowdsecConnection and starts tickers. Call Prepare first. Close stops them.
func New(config *configuration.Config, log *slog.Logger) (*CrowdsecConnection, error) {
	var err error
	var tlsAppsecConfig *tls.Config
	if config.CrowdsecAppsecEnabled {
		tlsAppsecConfig, err = configuration.GetTLSConfigCrowdsec(config, log, true)
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig " + err.Error())
			return nil, err
		}
	}

	crowdsecStreamRoute := ""
	crowdsecHeader := ""
	var tlsConfig *tls.Config
	if config.CrowdsecMode == configuration.AloneMode {
		crowdsecStreamRoute = crowdsecCapiStreamRoute
		crowdsecHeader = crowdsecCapiHeader
	} else {
		crowdsecStreamRoute = crowdsecLapiStreamRoute
		crowdsecHeader = crowdsecLapiHeader
		tlsConfig, err = configuration.GetTLSConfigCrowdsec(config, log, false)
		if err != nil {
			log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig " + err.Error())
			return nil, err
		}
		if config.CrowdsecLapiKey == "" && len(tlsConfig.Certificates) == 0 {
			log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup")
			return nil, errors.New("CrowdsecLapiKey is missing")
		}
	}

	conn := &CrowdsecConnection{
		crowdsecMode:            config.CrowdsecMode,
		appsecScheme:            config.CrowdsecAppsecScheme,
		appsecHost:              config.CrowdsecAppsecHost,
		appsecPath:              config.CrowdsecAppsecPath,
		appsecKey:               config.CrowdsecAppsecKey,
		appsecBodyLimit:         config.CrowdsecAppsecBodyLimit,
		crowdsecScheme:          config.CrowdsecLapiScheme,
		crowdsecHost:            config.CrowdsecLapiHost,
		crowdsecPath:            config.CrowdsecLapiPath,
		crowdsecKey:             config.CrowdsecLapiKey,
		crowdsecMachineID:       config.CrowdsecCapiMachineID,
		crowdsecPassword:        config.CrowdsecCapiPassword,
		crowdsecScenarios:       config.CrowdsecCapiScenarios,
		updateInterval:          config.UpdateIntervalSeconds,
		updateMaxFailure:        config.UpdateMaxFailure,
		defaultDecisionTimeout:  config.DefaultDecisionSeconds,
		redisUnreachableBlock:   config.RedisCacheUnreachableBlock,
		crowdsecStreamRoute:     crowdsecStreamRoute,
		crowdsecHeader:          crowdsecHeader,
		log:                     log,
		isCrowdsecStreamStartup: true,
		isCrowdsecStreamHealthy: true,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsConfig,
			},
			Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		httpAppsecClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsAppsecConfig,
			},
			Timeout: time.Duration(config.HTTPTimeoutSeconds) * time.Second,
		},
		cacheClient: &cache.Client{},
	}
	if config.CrowdsecMode == configuration.AppsecMode {
		return conn, nil
	}
	conn.cacheClient.New(
		log,
		config.RedisCacheEnabled,
		config.RedisCacheHost,
		config.RedisCacheReadHosts,
		config.RedisCachePassword,
		config.RedisCacheDatabase,
		IdentityHex(config),
	)

	if err := conn.startStream(config, log); err != nil {
		return nil, err
	}

	if config.MetricsUpdateIntervalSeconds > 0 {
		conn.lastMetricsPush = time.Now()
		go conn.handleMetricsTicker()
		conn.metricsStop = startTicker("metrics", config.MetricsUpdateIntervalSeconds, log, func() {
			conn.handleMetricsTicker()
		})
	}

	conn.log.Debug("CrowdsecConnection initialized mode:" + config.CrowdsecMode)
	return conn, nil
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

// Close stops tickers and idle HTTP connections. Safe to call more than once.
func (c *CrowdsecConnection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	stopTicker(c.streamStop)
	stopTicker(c.metricsStop)
	c.streamStop = nil
	c.metricsStop = nil
	closeIdle(c.httpClient)
	closeIdle(c.httpAppsecClient)
}

func stopTicker(stop chan bool) {
	if stop == nil {
		return
	}
	select {
	case stop <- true:
	default:
	}
}

func closeIdle(client *http.Client) {
	if client == nil {
		return
	}
	if t, ok := client.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

// Cache is this connection's isolated cache Client.
func (c *CrowdsecConnection) Cache() *cache.Client {
	return c.cacheClient
}

// Mode is the Crowdsec mode for this connection.
func (c *CrowdsecConnection) Mode() string {
	return c.crowdsecMode
}

// StreamHealthy is true while stream polling is succeeding.
func (c *CrowdsecConnection) StreamHealthy() bool {
	return c.isCrowdsecStreamHealthy
}

// RedisUnreachableBlock is the redis fail-closed flag for this connection.
func (c *CrowdsecConnection) RedisUnreachableBlock() bool {
	return c.redisUnreachableBlock
}

// StreamFetches is how many times this connection actually called the stream endpoint.
func (c *CrowdsecConnection) StreamFetches() int64 {
	return atomic.LoadInt64(&c.streamFetches)
}

// IncBlocked increments the dropped-request metric.
func (c *CrowdsecConnection) IncBlocked() {
	atomic.AddInt64(&c.blockedRequests, 1)
}

// LiveLookup queries LAPI for one IP (none/live mode) and may write this connection's cache.
func (c *CrowdsecConnection) LiveLookup(remoteIP string) (string, error) {
	return c.handleNoStreamCache(remoteIP)
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

func (c *CrowdsecConnection) handleMetricsTicker() {
	if err := c.reportMetrics(); err != nil {
		c.log.Error("handleMetricsTicker:reportMetrics " + err.Error())
	}
}

func startTicker(name string, updateInterval int64, log *slog.Logger, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(updateInterval) * time.Second)
	stop := make(chan bool, 1)
	go func() {
		defer log.Debug(name + "_ticker:stopped")
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

func (c *CrowdsecConnection) handleNoStreamCache(remoteIP string) (string, error) {
	isLiveMode := c.crowdsecMode == configuration.LiveMode
	routeURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + crowdsecLapiRoute,
		RawQuery: "ip=" + remoteIP,
	}
	body, err := c.crowdsecQuery(routeURL.String(), nil)
	if err != nil {
		return cache.BannedValue, err
	}

	if bytes.Equal(body, []byte("null")) {
		if isLiveMode {
			c.cacheClient.Set(remoteIP, cache.NoBannedValue, c.defaultDecisionTimeout)
		}
		return cache.NoBannedValue, nil
	}

	var decisions []Decision
	err = json.Unmarshal(body, &decisions)
	if err != nil {
		return cache.BannedValue, fmt.Errorf("handleNoStreamCache:parseBody %w", err)
	}
	if len(decisions) == 0 {
		if isLiveMode {
			c.cacheClient.Set(remoteIP, cache.NoBannedValue, c.defaultDecisionTimeout)
		}
		return cache.NoBannedValue, nil
	}
	var decision Decision
	for _, d := range decisions {
		decision = d
		if decision.Type == "ban" {
			break
		}
	}
	duration, err := time.ParseDuration(decision.Duration)
	if err != nil {
		return cache.BannedValue, fmt.Errorf("handleNoStreamCache:parseDuration %w", err)
	}
	var value string
	switch decision.Type {
	case "ban":
		value = cache.BannedValue
	case "captcha":
		value = cache.CaptchaValue
	default:
		c.log.Info("handleNoStreamCache:unknownType " + decision.Type)
	}
	if isLiveMode && c.defaultDecisionTimeout > 0 {
		durationSecond := int64(duration.Seconds())
		if c.defaultDecisionTimeout < durationSecond {
			durationSecond = c.defaultDecisionTimeout
		}
		c.cacheClient.Set(remoteIP, value, durationSecond)
	}
	return value, errors.New("handleNoStreamCache:banned")
}

func (c *CrowdsecConnection) getToken() error {
	loginURL := url.URL{
		Scheme: c.crowdsecScheme,
		Host:   c.crowdsecHost,
		Path:   crowdsecCapiLoginRoute,
	}
	loginData := []byte(fmt.Sprintf(
		`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
		c.crowdsecMachineID,
		c.crowdsecPassword,
		strings.Join(c.crowdsecScenarios, `","`),
	))
	body, err := c.crowdsecQuery(loginURL.String(), loginData)
	if err != nil {
		return err
	}
	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		return fmt.Errorf("getToken:parsingBody %w", err)
	}
	if login.Code == http.StatusOK && len(login.Token) > 0 {
		c.crowdsecKey = login.Token
		return nil
	}
	c.log.Warn("getToken statusCode:" + strconv.Itoa(login.Code))
	return errors.New("getToken statusCode:" + strconv.Itoa(login.Code))
}

func (c *CrowdsecConnection) handleStreamCache() error {
	_, err := c.cacheClient.Get(cacheTimeoutKey)
	if err == nil {
		c.log.Debug("handleStreamCache:alreadyUpdated")
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
	startup := "startup=false"
	if !c.isCrowdsecStreamHealthy || c.isCrowdsecStreamStartup {
		startup = "startup=true"
	}
	streamRouteURL := url.URL{
		Scheme:   c.crowdsecScheme,
		Host:     c.crowdsecHost,
		Path:     c.crowdsecPath + c.crowdsecStreamRoute,
		RawQuery: startup,
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
	for _, decision := range stream.New {
		duration, err := time.ParseDuration(decision.Duration)
		if err == nil {
			var value string
			switch decision.Type {
			case "ban":
				value = cache.BannedValue
			case "captcha":
				value = cache.CaptchaValue
			default:
				c.log.Info("handleStreamCache:unknownType " + decision.Type)
			}
			c.cacheClient.Set(decision.Value, value, int64(duration.Seconds()))
		}
	}
	for _, decision := range stream.Deleted {
		c.cacheClient.Delete(decision.Value)
	}
	c.log.Debug("handleStreamCache:updated")
	c.isCrowdsecStreamStartup = false
	return nil
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}

func (c *CrowdsecConnection) crowdsecQuery(stringURL string, data []byte) ([]byte, error) {
	var req *http.Request
	if len(data) > 0 {
		req, _ = http.NewRequest(http.MethodPost, stringURL, bytes.NewBuffer(data))
	} else {
		req, _ = http.NewRequest(http.MethodGet, stringURL, nil)
	}
	req.Header.Set(c.crowdsecHeader, c.crowdsecKey)
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+Version)

	res, err := c.httpClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		return nil, fmt.Errorf("crowdsecQuery:unreachable url:%s %w", stringURL, err)
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			c.log.Error("crowdsecQuery:closeBody " + err.Error())
		}
	}()
	if res.StatusCode == http.StatusUnauthorized && c.crowdsecMode == configuration.AloneMode {
		if errToken := c.getToken(); errToken != nil {
			return nil, fmt.Errorf("crowdsecQuery:renewToken url:%s %w", stringURL, errToken)
		}
		return c.crowdsecQuery(stringURL, nil)
	}

	statusStr := strconv.Itoa(res.StatusCode)
	if len(statusStr) < 1 || statusStr[0] != '2' {
		return nil, fmt.Errorf("crowdsecQuery method:%s url:%s, statusCode:%d (expected: 2xx)", req.Method, stringURL, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("crowdsecQuery:readBody %w", err)
	}
	return body, nil
}

func isBodyUnreadable(httpReq *http.Request) bool {
	return httpReq.Body != nil && httpReq.Body != http.NoBody && httpReq.ProtoMajor >= 2 && httpReq.ContentLength < 0
}

func isMethodWithBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// AppsecQuery forwards the request to this connection's AppSec HTTP client.
func (c *CrowdsecConnection) AppsecQuery(ip string, httpReq *http.Request, pol AppsecPolicy) error {
	routeURL := url.URL{
		Scheme: c.appsecScheme,
		Host:   c.appsecHost,
		Path:   c.appsecPath,
	}
	var req *http.Request
	switch {
	case isBodyUnreadable(httpReq):
		if pol.UnreadableBodyBlock && isMethodWithBody(httpReq.Method) {
			return errors.New("appsecQuery:unreadableBody dropped")
		}
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	case c.appsecBodyLimit > 0 && httpReq.Body != nil:
		var bodyBuffer bytes.Buffer
		limitedReader := io.LimitReader(httpReq.Body, c.appsecBodyLimit)
		teeReader := io.TeeReader(limitedReader, &bodyBuffer)
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			return fmt.Errorf("appsecQuery:GetBody %w", err)
		}
		httpReq.Body = io.NopCloser(io.MultiReader(&bodyBuffer, httpReq.Body))
		req, _ = http.NewRequest(http.MethodPost, routeURL.String(), bytes.NewBuffer(bodyBytes))
	default:
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	}

	for key, headers := range httpReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set(crowdsecAppsecHeader, c.appsecKey)
	req.Header.Set(crowdsecAppsecIPHeader, ip)
	req.Header.Set(crowdsecAppsecVerbHeader, httpReq.Method)
	req.Header.Set(crowdsecAppsecHostHeader, httpReq.Host)
	req.Header.Set(crowdsecAppsecURIHeader, httpReq.URL.String())
	req.Header.Set(crowdsecAppsecUserAgent, httpReq.Header.Get("User-Agent"))
	req.Header.Set("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/"+Version)

	res, err := c.httpAppsecClient.Do(req)
	if err != nil || isReverseProxyError(res.StatusCode) {
		c.log.Error("appsecQuery:unreachable")
		if pol.UnreachableBlock {
			return fmt.Errorf("appsecQuery:unreachable %w", err)
		}
		return nil
	}
	defer func() {
		if _, errDrain := io.Copy(io.Discard, res.Body); errDrain != nil {
			c.log.Debug("appsecQuery:drainBody " + errDrain.Error())
		}
		if err = res.Body.Close(); err != nil {
			c.log.Error("appsecQuery:closeBody " + err.Error())
		}
	}()
	if res.StatusCode == http.StatusInternalServerError {
		c.log.Info("appsecQuery:failure")
		if pol.FailureBlock {
			return errors.New("appsecQuery statusCode:500")
		}
		return nil
	}
	if res.StatusCode != http.StatusOK {
		return errors.New("appsecQuery statusCode:" + strconv.Itoa(res.StatusCode))
	}
	return nil
}

func (c *CrowdsecConnection) reportMetrics() error {
	now := time.Now()
	currentCount := atomic.LoadInt64(&c.blockedRequests)
	windowSizeSeconds := int(now.Sub(c.lastMetricsPush).Seconds())

	c.log.Debug(fmt.Sprintf("reportMetrics: blocked_requests=%d window_size=%ds", currentCount, windowSizeSeconds))

	metrics := map[string]interface{}{
		"remediation_components": []map[string]interface{}{
			{
				"version": Version,
				"type":    "bouncer",
				"name":    "traefik_plugin",
				"metrics": []map[string]interface{}{
					{
						"items": []map[string]interface{}{
							{
								"name":  "dropped",
								"value": currentCount,
								"unit":  "request",
								"labels": map[string]string{
									"type": "traefik_plugin",
								},
							},
						},
						"meta": map[string]interface{}{
							"window_size_seconds": windowSizeSeconds,
							"utc_now_timestamp":   now.Unix(),
						},
					},
				},
				"utc_startup_timestamp": time.Now().Unix(),
				"feature_flags":         []string{},
				"os": map[string]string{
					"name":    "unknown",
					"version": "unknown",
				},
			},
		},
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("reportMetrics:marshal %w", err)
	}

	metricsURL := url.URL{
		Scheme: c.crowdsecScheme,
		Host:   c.crowdsecHost,
		Path:   c.crowdsecPath + crowdsecLapiMetricsRoute,
	}

	_, err = c.crowdsecQuery(metricsURL.String(), data)
	if err != nil {
		return fmt.Errorf("reportMetrics:query %w", err)
	}

	atomic.StoreInt64(&c.blockedRequests, 0)
	c.lastMetricsPush = now
	return nil
}
