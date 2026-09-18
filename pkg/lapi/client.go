// Package lapi is the reclaim value for one CrowdSec LAPI/CAPI decisions backend.
package lapi

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	cache "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

// Operator-visible lifecycle and stream-health lines (stable for log grep).
const (
	MsgConnectionStarted  = "crowdsec connection started"
	MsgConnectionSleeping = "crowdsec connection sleeping"
	MsgConnectionWaking   = "crowdsec connection waking"
	MsgConnectionClosed   = "crowdsec connection closed"
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

// Client owns stream ticker, a reclaimed DecisionStore, in-process Range membership, LAPI/CAPI HTTP, and metrics.
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
	sessionKey           string            // reclaim SessionKey (stream/alone) or Key (live/none)
	liveHeaderScopes     liveHeaderScopes  // live constructor ctx → normalized header scopes

	transport       atomic.Value // *transport; not atomic.Pointer[T] (Yaegi v0.16)
	decisionStore   *DecisionStore
	cacheClient     *cache.Client // alias of store.Cache(); tests may set this without a store
	rangeMembership atomic.Value  // *decisionscope.RangeMembership rebuilt from range-index
	lastRangeIndex  atomic.Value  // string of the blob last used to build membership
	log             *slog.Logger
	pluginVersion   string

	// int64 0/1 published with atomic.LoadInt64/StoreInt64 (Yaegi v0.16: not atomic.Bool / atomic.Int64 / atomic.Pointer[T]).
	isCrowdsecStreamStartup int64
	isCrowdsecStreamHealthy int64
	updateFailure           int64
	streamPollInFlight      int64
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
	cfg.RedisCachePassword, _ = configuration.GetVariable(cfg, "RedisCachePassword")
	return nil
}

// New constructs a Client and starts tickers. store is the reclaimed DecisionStore for this cursor.
// Call Prepare first. Close stops tickers and HTTP only; it does not Close the shared store.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string, store *DecisionStore) (*Client, error) {
	crowdsecStreamRoute := crowdsecLapiStreamRoute
	if config.CrowdsecMode == configuration.AloneMode {
		crowdsecStreamRoute = crowdsecCapiStreamRoute
	}
	next, err := newTransport(config, log)
	if err != nil {
		log.Error("New:getTLSConfigCrowdsec fail to get tlsConfig " + err.Error())
		return nil, err
	}
	if config.CrowdsecMode != configuration.AloneMode && config.CrowdsecLapiKey == "" && next.clientCertCount() == 0 {
		log.Error("New:crowdsecLapiKey fail to get CrowdsecLapiKey and no client certificate setup")
		return nil, errors.New("CrowdsecLapiKey is missing")
	}
	if store == nil || store.Cache() == nil {
		return nil, errors.New("decision store is required")
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
		sessionKey:              reclaimSessionKey(config),
		log:                     log,
		pluginVersion:           pluginVersion,
		isCrowdsecStreamStartup: 1,
		isCrowdsecStreamHealthy: 1,
		decisionStore:           store,
		cacheClient:             store.Cache(),
	}
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

	client.logInfo(MsgConnectionStarted, "started")
	return client, nil
}

// Close stops tickers and idle LAPI HTTP. Safe to call more than once.
// Remaining usage-metrics are POSTed to LAPI before HTTP is torn down.
// Does not Close the shared DecisionStore; only the store's reclaim Close hook does.
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
	c.logInfo(MsgConnectionClosed, "closed")
}

// Sleep stops stream and metrics tickers and keeps HTTP, cache, and the LAPI
// cursor. Reclaim calls this when the last constructor ctx is gone. Not Close.
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
	c.logInfo(MsgConnectionSleeping, "sleeping")
	go c.drainMetrics()
}

// Wake starts stream and metrics tickers again after Sleep. startup=false: the
// cache is still warm; CrowdSec still holds stream_cursor on the bouncer row.
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
	c.logInfo(MsgConnectionWaking, "waking")
	if resumeStream {
		go c.handleStreamTicker()
	}
}

// logInfo writes an operator-visible line with mode, host, reclaim key, and reason.
func (c *Client) logInfo(msg, reason string) {
	if c.log == nil {
		return
	}
	c.log.Info(msg, "mode", c.crowdsecMode, "host", c.crowdsecHost, "sessionKey", c.sessionKey, "reason", reason)
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
		defer log.Debug(name + "_ticker:stopped")
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

// Cache is the shared DecisionStore cache, or the test-assigned cacheClient.
func (c *Client) Cache() *cache.Client {
	if c.decisionStore != nil {
		return c.decisionStore.Cache()
	}
	return c.cacheClient
}

// RangeMembership is the current in-process Range lookup, or nil before the first hydrate.
func (c *Client) RangeMembership() *decisionscope.RangeMembership {
	stored := c.rangeMembership.Load()
	if stored == nil {
		return nil
	}
	membership, _ := stored.(*decisionscope.RangeMembership)
	return membership
}

// hydrateRangeMembership rebuilds Range membership from the shared blob when the raw string changed.
func (c *Client) hydrateRangeMembership() {
	index, err := c.Cache().Get(decisionscope.RangeIndexKey)
	if err != nil {
		if !errors.Is(err, cache.ErrMiss) {
			return
		}
		index = ""
	}
	c.storeRangeMembership(index)
}

// storeRangeMembership replaces the in-process trees when index differs from the last hydrate.
func (c *Client) storeRangeMembership(index string) {
	previous, _ := c.lastRangeIndex.Load().(string)
	if c.rangeMembership.Load() != nil && previous == index {
		return
	}
	c.rangeMembership.Store(decisionscope.MembershipFromIndex(index))
	c.lastRangeIndex.Store(index)
}

// StreamHealthy is true while stream polling is succeeding.
func (c *Client) StreamHealthy() bool {
	return atomic.LoadInt64(&c.isCrowdsecStreamHealthy) != 0
}

// StreamFetches is how many times this connection actually called the stream endpoint.
func (c *Client) StreamFetches() int64 {
	return atomic.LoadInt64(&c.streamFetches)
}

// registerLiveHeaderScopes records this New ctx’s headers and drops them when ctx is Done.
func (c *Client) registerLiveHeaderScopes(ctx context.Context, headers map[string]string) {
	c.mu.Lock()
	c.liveHeaderScopes.register(ctx, headers)
	c.mu.Unlock()
	context.AfterFunc(ctx, func() {
		c.mu.Lock()
		c.liveHeaderScopes.unregister(ctx)
		c.mu.Unlock()
	})
}

// snapshotLiveHeaderScopes is the live-router union, or first-create residue when none are registered yet.
func (c *Client) snapshotLiveHeaderScopes() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.liveHeaderScopes.headerScopesByCtx) == 0 {
		return c.decisionScopeHeaders
	}
	return c.liveHeaderScopes.union()
}
