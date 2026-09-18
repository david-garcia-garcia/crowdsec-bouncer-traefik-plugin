// Package appsec is the reclaim value for one CrowdSec AppSec listener.
package appsec

import (
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

// Client owns the AppSec HTTP round-trip for one listener identity.
type Client struct {
	mu sync.Mutex

	appsecScheme    string
	appsecHost      string
	appsecPath      string
	appsecBodyLimit int64
	transport       atomic.Value // *transport; not atomic.Pointer[T] (Yaegi v0.16)
	log             *slog.Logger
	pluginVersion   string
	gate            *backendbackoff.Gate
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
	next, err := newTransport(config, log)
	if err != nil {
		log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig " + err.Error())
		return nil, err
	}
	gate, gateErr := backendbackoff.New(config.BackendBackoffConfig())
	if gateErr != nil {
		return nil, gateErr
	}
	client := &Client{
		appsecScheme:    config.CrowdsecAppsecScheme,
		appsecHost:      config.CrowdsecAppsecHost,
		appsecPath:      config.CrowdsecAppsecPath,
		appsecBodyLimit: config.CrowdsecAppsecBodyLimit,
		log:             log,
		pluginVersion:   pluginVersion,
		gate:            gate,
	}
	client.transport.Store(next)
	return client, nil
}

// Close releases idle AppSec HTTP connections. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gate != nil {
		c.gate.Close()
	}
	current := c.currentTransport()
	if current != nil {
		closeIdle(current.httpClient)
	}
}

// backendURLStem is scheme+host+path for Allow/Report.
func (c *Client) backendURLStem() string {
	stem := url.URL{
		Scheme: c.appsecScheme,
		Host:   c.appsecHost,
		Path:   c.appsecPath,
	}
	return stem.String()
}

// Sleep is a reclaim no-op: AppSec has no tickers.
func (c *Client) Sleep() {}

// Wake is a reclaim no-op: AppSec has no tickers.
func (c *Client) Wake() {}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}
