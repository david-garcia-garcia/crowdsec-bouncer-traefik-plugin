// Package lapi is the reclaim value for one CrowdSec LAPI/CAPI decisions backend.
package lapi

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/instance"
)

// Operator-visible lifecycle and stream-health lines (stable for log grep).
const (
	MsgConnectionStarted  = "crowdsec lapi instance started"
	MsgConnectionSleeping = "crowdsec lapi instance sleeping"
	MsgConnectionWaking   = "crowdsec lapi instance waking"
	MsgConnectionClosed   = "crowdsec lapi instance closed"
	MsgStreamUnhealthy    = "crowdsec stream became unhealthy"
	MsgStreamHealthy      = "crowdsec stream became healthy"
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

// Client owns stream ticker, a reclaimed DecisionStore, LAPI/CAPI HTTP, and metrics.
type Client struct {
	mu       sync.Mutex
	closed   bool
	sleeping bool // last reclaim holder gone; tickers stopped until Wake or Close

	crowdsecScheme       string
	crowdsecHost         string
	crowdsecPath         string
	crowdsecMode         string
	crowdsecMachineID    string
	crowdsecPassword     string
	crowdsecScenarios    []string
	updateInterval       int64
	metricsInterval      int64
	updateMaxFailure     int64
	crowdsecStreamRoute  string
	decisionScopeHeaders map[string]string // write-once first-create residue; not the live union
	sessionKey           string            // ownership Open key
	streamScopeQuery     string            // opener crowdsecLapiStreamScopes plus ip,range
	streamScopeSet       map[string]struct{}
	middlewareName       string
	instanceName         string
	lastPublishedName    string
	incarnation          string
	lapiKey              string

	transport     atomic.Value // *transport; not atomic.Pointer[T] (Yaegi v0.16)
	decisionStore *decisionstore.Store
	log           *slog.Logger
	pluginVersion string

	// int64 0/1 published with atomic.LoadInt64/StoreInt64 (Yaegi v0.16: not atomic.Bool / atomic.Int64 / atomic.Pointer[T]).
	isCrowdsecStreamStartup int64
	isCrowdsecStreamHealthy int64
	updateFailure           int64
	streamStop              chan bool
	metricsStop             chan bool
	metricsReporter         *MetricsReporter
	streamFetches           int64
}

// Prepare resolves secrets and CAPI/LAPI routing on cfg. Call before Key and New.
func Prepare(cfg *configuration.Config, _ *slog.Logger) error {
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
	}
	if cfg.RedisCacheEnabled {
		cfg.RedisCachePassword, _ = configuration.GetVariable(cfg, "RedisCachePassword")
	}
	return nil
}

// New constructs a Client and starts tickers. store is the reclaimed DecisionStore for this cursor.
// Call Prepare first. middlewareName and bindKey are stored before tickers start so stream logs
// do not race the Open callback. Close stops tickers and HTTP only; it does not Close the shared store.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string, store *decisionstore.Store, middlewareName, bindKey string) (*Client, error) {
	crowdsecStreamRoute := crowdsecLapiStreamRoute
	if config.CrowdsecMode == configuration.AloneMode {
		crowdsecStreamRoute = crowdsecCapiStreamRoute
	}
	next, err := newTransport(config, log)
	if err != nil {
		log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig", "error", err)
		return nil, err
	}
	if config.CrowdsecMode != configuration.AloneMode && config.CrowdsecLapiKey == "" && next.clientCertCount() == 0 {
		log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup")
		return nil, errors.New("CrowdsecLapiKey is missing")
	}
	if store == nil {
		return nil, errors.New("decision store is required")
	}

	startup := int64(1)
	if store.StreamReady() != 0 {
		startup = 0
	}

	scopeQuery := decisionscope.StreamScopeQuery(config.CrowdsecLapiStreamScopes)
	scopeSet := make(map[string]struct{}, 8)
	for _, name := range decisionscope.CanonicalStreamScopes(config.CrowdsecLapiStreamScopes) {
		scopeSet[name] = struct{}{}
		scopeSet[strings.ToLower(name)] = struct{}{}
	}

	client := &Client{
		crowdsecMode:            config.CrowdsecMode,
		crowdsecScheme:          config.CrowdsecLapiScheme,
		crowdsecHost:            config.CrowdsecLapiHost,
		crowdsecPath:            config.CrowdsecLapiPath,
		crowdsecMachineID:       config.CrowdsecCapiMachineID,
		crowdsecPassword:        config.CrowdsecCapiPassword,
		crowdsecScenarios:       config.CrowdsecCapiScenarios,
		updateInterval:          config.UpdateIntervalSeconds,
		metricsInterval:         config.MetricsUpdateIntervalSeconds,
		updateMaxFailure:        config.UpdateMaxFailure,
		decisionScopeHeaders:    decisionscope.NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		crowdsecStreamRoute:     crowdsecStreamRoute,
		streamScopeQuery:        scopeQuery,
		streamScopeSet:          scopeSet,
		sessionKey:              bindKey,
		middlewareName:          middlewareName,
		instanceName:            config.CrowdsecLapiInstanceName,
		lapiKey:                 config.CrowdsecLapiKey,
		log:                     log,
		pluginVersion:           pluginVersion,
		isCrowdsecStreamStartup: startup,
		isCrowdsecStreamHealthy: 1,
		decisionStore:           store,
	}
	client.incarnation = fmt.Sprintf("%p", client)
	client.metricsReporter = newMetricsReporter(client, time.Now())
	client.transport.Store(next)

	if err := client.startStream(config, log); err != nil {
		return nil, err
	}

	if config.MetricsUpdateIntervalSeconds > 0 {
		client.metricsReporter.lastMetricsPush = time.Now()
		go client.handleMetricsTicker()
		client.metricsStop = startTicker("metrics", client.metricsInterval, log, func() {
			client.handleMetricsTicker()
		})
	}

	client.logLifecycle(MsgConnectionStarted, "started", false)
	return client, nil
}

// Close stops tickers and idle LAPI HTTP. Safe to call more than once.
// Remaining usage-metrics are POSTed to LAPI before HTTP is torn down.
// Does not Close the shared DecisionStore; only the store's reclaim Close hook does.
// Does not cancel an in-flight stream GET; that poll may finish apply after Close starts.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.sleeping = false
	stopTicker(c.streamStop)
	stopTicker(c.metricsStop)
	c.streamStop = nil
	c.metricsStop = nil
	c.mu.Unlock()

	c.drainMetrics()

	c.mu.Lock()
	defer c.mu.Unlock()
	if current := c.currentTransport(); current != nil {
		closeIdle(current.httpClient)
	}
	c.logLifecycle(MsgConnectionClosed, "closed", false)
	dropStreamOwner(c.crowdsecHost, c.lapiKey, c.middlewareName)
	instance.Clear(instance.LegLAPI, c, c.middlewareName)
}

// Sleep stops stream and metrics tickers and keeps HTTP, the DecisionStore, and the LAPI
// cursor. Reclaim calls this when the last constructor ctx is gone. Not Close.
// Does not wait for an in-flight stream GET and does not cancel it.
// Remaining usage-metrics are POSTed asynchronously so the reclaim table lock is not held on LAPI.
func (c *Client) Sleep() {
	c.mu.Lock()
	if c.closed || c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = true
	stopTicker(c.streamStop)
	stopTicker(c.metricsStop)
	c.streamStop = nil
	c.metricsStop = nil
	c.mu.Unlock()
	c.logLifecycle(MsgConnectionSleeping, "sleeping", true)
	go c.drainMetrics()
}

// Wake starts stream and metrics tickers again after Sleep. startup=false: the
// DecisionStore is still warm; CrowdSec still holds stream_cursor on the bouncer row.
func (c *Client) Wake() {
	c.mu.Lock()
	if c.closed || !c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = false
	resumeStream := c.crowdsecMode == configuration.StreamMode || c.crowdsecMode == configuration.AloneMode
	if resumeStream && c.streamStop == nil {
		c.streamStop = startTicker("stream", c.updateInterval, c.log, func() {
			c.handleStreamTicker()
		})
	}
	if c.metricsInterval > 0 && c.metricsStop == nil {
		c.metricsStop = startTicker("metrics", c.metricsInterval, c.log, func() {
			c.handleMetricsTicker()
		})
	}
	c.mu.Unlock()
	c.logLifecycle(MsgConnectionWaking, "waking", true)
	if resumeStream {
		go c.handleStreamTicker()
	}
}

// Mode is the fetch strategy this Client was opened with.
func (c *Client) Mode() string {
	if c == nil {
		return ""
	}
	return c.crowdsecMode
}

// Incarnation is unique per Client create.
func (c *Client) Incarnation() string {
	if c == nil {
		return ""
	}
	return c.incarnation
}

func (c *Client) bindIdentity(middlewareName, bindKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.middlewareName == "" {
		c.middlewareName = middlewareName
	}
	if c.sessionKey == "" {
		c.sessionKey = bindKey
	}
}

// StreamScopes are the opener extra names this Client polls (canonical ip,range plus extras).
func (c *Client) StreamScopes() []string {
	if c == nil {
		return nil
	}
	names := make([]string, 0, len(c.streamScopeSet))
	for name := range c.streamScopeSet {
		names = append(names, name)
	}
	return names
}

// LastPublishedName is the slot this Client last published, kept across Sleep.
func (c *Client) LastPublishedName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPublishedName
}

// SetPublishedName records the slot this Client just published.
func (c *Client) SetPublishedName(name string) {
	c.mu.Lock()
	c.lastPublishedName = name
	c.mu.Unlock()
}

// logInfo writes stream-health lines with host and reclaim key.
func (c *Client) logInfo(msg, reason string) {
	if c.log == nil {
		return
	}
	c.log.Info(msg, "mode", c.crowdsecMode, "host", c.crowdsecHost, "sessionKey", c.sessionKey, "reason", reason)
}

// logLifecycle writes Create/Close at INFO and Sleep/Wake at DEBUG.
func (c *Client) logLifecycle(msg, reason string, debug bool) {
	if c.log == nil {
		return
	}
	if debug {
		c.log.Debug(msg, "leg", instance.LegLAPI, "instanceName", c.instanceName, "incarnation", c.incarnation, "mode", c.crowdsecMode, "host", c.crowdsecHost, "sessionKey", c.sessionKey, "reason", reason)
		return
	}
	c.log.Info(msg, "leg", instance.LegLAPI, "instanceName", c.instanceName, "incarnation", c.incarnation, "mode", c.crowdsecMode, "host", c.crowdsecHost, "sessionKey", c.sessionKey, "reason", reason)
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

func startTicker(name string, updateInterval int64, log *slog.Logger, work func()) chan bool {
	ticker := time.NewTicker(time.Duration(updateInterval) * time.Second)
	stop := make(chan bool, 1)
	go func() {
		log.Debug("ticker:started", "name", name, "interval", updateInterval)
		defer log.Debug("ticker:stopped", "name", name)
		for {
			select {
			case <-ticker.C:
				work()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return stop
}

// StreamHealthy is true while stream polling is succeeding.
func (c *Client) StreamHealthy() bool {
	return atomic.LoadInt64(&c.isCrowdsecStreamHealthy) != 0
}

// StreamFetches is how many times this connection actually called the stream endpoint.
func (c *Client) StreamFetches() int64 {
	return atomic.LoadInt64(&c.streamFetches)
}

// openerCoversScope reports whether the stream poll asked for this decision scope.
func (c *Client) openerCoversScope(scope string) bool {
	if c.streamScopeSet == nil {
		return false
	}
	if _, ok := c.streamScopeSet[scope]; ok {
		return true
	}
	_, ok := c.streamScopeSet[strings.ToLower(scope)]
	return ok
}
