// Package appsec is the reclaim value for one CrowdSec AppSec listener.
package appsec

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	configuration "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// ReclaimGraceDuration is the wait after the last constructor ctx for an AppSec Client slot.
const ReclaimGraceDuration = 30 * time.Second

// Client owns the AppSec HTTP round-trip for one listener identity.
type Client struct {
	mu sync.Mutex

	appsecScheme    string
	appsecHost      string
	appsecPath      string
	appsecKey       string
	appsecBodyLimit int64
	httpClient      *http.Client
	log             *slog.Logger
	pluginVersion   string
}

// Prepare resolves AppSec secrets on cfg. Call lapi.Prepare first so an empty AppSec key can copy the LAPI key.
func Prepare(cfg *configuration.Config, log *slog.Logger) error {
	if cfg.CrowdsecAppsecKey == "" {
		cfg.CrowdsecAppsecKey = cfg.CrowdsecLapiKey
	}
	if !cfg.CrowdsecAppsecEnabled {
		return nil
	}
	if cfg.CrowdsecAppsecScheme == "" {
		cfg.CrowdsecAppsecScheme = cfg.CrowdsecLapiScheme
	}
	apiAppsecKey, errAppsecKey := configuration.GetVariable(cfg, "CrowdsecAppsecKey")
	if errAppsecKey != nil {
		log.Info("Prepare:crowdsecAppsecKey fail to get CrowdsecAppsecKey and no client certificate setup " + errAppsecKey.Error())
	} else {
		cfg.CrowdsecAppsecKey = apiAppsecKey
	}
	return nil
}

// New constructs an AppSec Client. Call Prepare first. Close releases idle HTTP.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string) (*Client, error) {
	tlsAppsecConfig, err := configuration.GetTLSConfigCrowdsec(config, log, true)
	if err != nil {
		log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig " + err.Error())
		return nil, err
	}
	return &Client{
		appsecScheme:    config.CrowdsecAppsecScheme,
		appsecHost:      config.CrowdsecAppsecHost,
		appsecPath:      config.CrowdsecAppsecPath,
		appsecKey:       config.CrowdsecAppsecKey,
		appsecBodyLimit: config.CrowdsecAppsecBodyLimit,
		log:             log,
		pluginVersion:   pluginVersion,
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
				TLSClientConfig:     tlsAppsecConfig,
			},
			Timeout: configuration.EffectiveAppsecTimeout(config),
		},
	}, nil
}

// Close releases idle AppSec HTTP connections. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	closeIdle(c.httpClient)
}

// Sleep is a reclaim no-op: AppSec has no tickers.
func (c *Client) Sleep() {}

// Wake is a reclaim no-op: AppSec has no tickers.
func (c *Client) Wake() {}

func closeIdle(httpClient *http.Client) {
	if httpClient == nil {
		return
	}
	if t, ok := httpClient.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}
