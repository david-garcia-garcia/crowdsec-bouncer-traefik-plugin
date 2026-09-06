// Package lapi is the reclaim value for one CrowdSec LAPI/CAPI decisions backend.
package lapi

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/health"
)

// ReclaimGraceDuration is the wait after the last constructor ctx for a Client slot.
const ReclaimGraceDuration = 30 * time.Second

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

// Client owns stream ticker, isolated cache, in-process Range membership, LAPI/CAPI HTTP, and metrics.
type Client struct {
	mu       sync.Mutex
	closed   bool
	sleeping bool // last reclaim holder gone; tickers stopped until Wake or Close

	crowdsecScheme         string
	crowdsecHost           string
	crowdsecPath           string
	crowdsecKey            string
	crowdsecMode           string
	crowdsecMachineID      string
	crowdsecPassword       string
	crowdsecScenarios      []string
	updateInterval         int64
	metricsInterval        int64
	updateMaxFailure       int64
	lapiFailureAction      string
	defaultDecisionTimeout int64
	crowdsecStreamRoute    string
	crowdsecHeader         string
	redisUnreachableBlock  bool
	decisionScopeHeaders   map[string]string // CrowdSec header scope → request header

	httpClient      *http.Client
	cacheClient     *cache.Client
	failureTracker  *health.Tracker
	rangeMembership atomic.Value // *decisionscope.RangeMembership rebuilt from range-index
	lastRangeIndex  atomic.Value // string of the blob last used to build membership
	log             *slog.Logger
	pluginVersion   string

	isCrowdsecStreamStartup bool
	isCrowdsecStreamHealthy bool
	updateFailure           int64
	streamStop              chan bool
	metricsStop             chan bool
	lastMetricsPush         time.Time
	startedAt               time.Time
	metricsMu               sync.Mutex
	reportMu                sync.Mutex               // one usage-metrics POST at a time (ticker, Sleep drain, Close drain)
	windowCounters          map[usageMetricKey]int64 // dropped counters for the current push window
	processedIPv4           int64                    // processed ipv4; atomic on the request path
	processedIPv6           int64
	processedUnknown        int64 // processed when Family is empty
	activeDecisions         map[usageMetricKey]int64
	activeDecisionSlots     map[string]usageMetricKey
	streamFetches           int64
	streamOwner             string         // first middleware New that created this stream session
	streamSettings          streamSettings // knobs that must not start a second poller; warn-and-wire if a joiner differs
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

// New constructs a Client and starts tickers. Call Prepare first. Close stops them.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string) (*Client, error) {
	var err error
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

	client := &Client{
		crowdsecMode:            config.CrowdsecMode,
		crowdsecScheme:          config.CrowdsecLapiScheme,
		crowdsecHost:            config.CrowdsecLapiHost,
		crowdsecPath:            config.CrowdsecLapiPath,
		crowdsecKey:             config.CrowdsecLapiKey,
		crowdsecMachineID:       config.CrowdsecCapiMachineID,
		crowdsecPassword:        config.CrowdsecCapiPassword,
		crowdsecScenarios:       config.CrowdsecCapiScenarios,
		updateInterval:          config.UpdateIntervalSeconds,
		metricsInterval:         config.MetricsUpdateIntervalSeconds,
		updateMaxFailure:        config.UpdateMaxFailure,
		lapiFailureAction:       configuration.EffectiveFailureAction(config.CrowdsecLapiFailureAction),
		defaultDecisionTimeout:  config.DefaultDecisionSeconds,
		redisUnreachableBlock:   config.RedisCacheUnreachableBlock,
		decisionScopeHeaders:    decisionscope.NormalizeDecisionScopeHeaders(config.DecisionScopeHeaders),
		crowdsecStreamRoute:     crowdsecStreamRoute,
		crowdsecHeader:          crowdsecHeader,
		log:                     log,
		pluginVersion:           pluginVersion,
		startedAt:               time.Now(),
		windowCounters:          make(map[usageMetricKey]int64),
		activeDecisions:         make(map[usageMetricKey]int64),
		activeDecisionSlots:     make(map[string]usageMetricKey),
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
		cacheClient:    &cache.Client{},
		failureTracker: health.NewFromSeconds(config.LapiFailureBackoffTimeout, config.LapiFailureBackoffBucketWindow, config.LapiFailureBackoffBucketThreshold, log),
	}
	// Stream/alone prefix is SessionHex (LAPI URL+key), not IdentityHex.
	// IdentityHex still includes intervals, so two middlewares on one key
	// used to get two prefixes and two incomplete caches while sharing one
	// CrowdSec stream cursor. Warn-and-wire must read the same keys.
	client.cacheClient.New(
		log,
		config.RedisCacheEnabled,
		config.RedisCacheHost,
		config.RedisCacheReadHosts,
		config.RedisCachePassword,
		config.RedisCacheDatabase,
		CachePrefix(config),
	)

	if err := client.startStream(config, log); err != nil {
		return nil, err
	}

	if config.MetricsUpdateIntervalSeconds > 0 {
		client.lastMetricsPush = time.Now()
		go client.handleMetricsTicker()
		client.metricsStop = startTicker("metrics", client.metricsInterval, log, func() {
			client.handleMetricsTicker()
		})
	}

	client.logInfo(MsgConnectionStarted)
	return client, nil
}

// Close stops tickers, idle HTTP connections, and the cache Redis pool. Safe to call more than once.
// Remaining usage-metrics are POSTed to LAPI before HTTP is torn down.
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
	closeIdle(c.httpClient)
	if c.cacheClient != nil {
		c.cacheClient.Close()
	}
	c.logInfo(MsgConnectionClosed)
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
	c.logInfo(MsgConnectionSleeping)
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
	c.logInfo(MsgConnectionWaking)
	if resumeStream {
		go c.handleStreamTicker()
	}
}

// logInfo writes an operator-visible lifecycle line with mode and LAPI host.
func (c *Client) logInfo(msg string) {
	if c.log == nil {
		return
	}
	c.log.Info(msg, "mode", c.crowdsecMode, "host", c.crowdsecHost)
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
				go work()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return stop
}

// Cache is this connection's isolated cache Client.
func (c *Client) Cache() *cache.Client {
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
	index, err := c.cacheClient.Get(decisionscope.RangeIndexKey)
	if err != nil {
		if err.Error() != cache.CacheMiss {
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
	return c.isCrowdsecStreamHealthy
}

// LapiFailureAction is the fallback when LAPI does not return a usable verdict.
func (c *Client) LapiFailureAction() string {
	return c.lapiFailureAction
}

// RedisUnreachableBlock is the redis fail-closed flag for this connection.
func (c *Client) RedisUnreachableBlock() bool {
	return c.redisUnreachableBlock
}

// StreamFetches is how many times this connection actually called the stream endpoint.
func (c *Client) StreamFetches() int64 {
	return atomic.LoadInt64(&c.streamFetches)
}
