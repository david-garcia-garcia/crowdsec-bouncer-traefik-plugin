// Package appsec is the reclaim value for one CrowdSec AppSec listener.
package appsec

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/instance"
)

const (
	MsgInstanceStarted  = "crowdsec appsec instance started"
	MsgInstanceSleeping = "crowdsec appsec instance sleeping"
	MsgInstanceWaking   = "crowdsec appsec instance waking"
	MsgInstanceClosed   = "crowdsec appsec instance closed"
)

// Client owns the AppSec HTTP round-trip for one listener identity.
type Client struct {
	mu sync.Mutex

	appsecScheme      string
	appsecHost        string
	appsecPath        string
	appsecBodyLimit   int64
	transport         atomic.Value // *transport; not atomic.Pointer[T] (Yaegi v0.16)
	log               *slog.Logger
	pluginVersion     string
	middlewareName    string
	instanceName      string
	lastPublishedName string
	incarnation       string
	sessionKey        string
	closed            bool
	sleeping          bool
}

// Prepare resolves AppSec secrets on cfg when AppSec is enabled. Empty key/scheme copy from LAPI.
func Prepare(cfg *configuration.Config, log *slog.Logger) error {
	if !cfg.CrowdsecAppsecEnabled {
		return nil
	}
	if cfg.CrowdsecAppsecKey == "" {
		cfg.CrowdsecAppsecKey = cfg.CrowdsecLapiKey
	}
	if cfg.CrowdsecAppsecScheme == "" {
		cfg.CrowdsecAppsecScheme = cfg.CrowdsecLapiScheme
	}
	apiAppsecKey, errAppsecKey := configuration.GetVariable(cfg, "CrowdsecAppsecKey")
	if errAppsecKey != nil {
		log.Info("Prepare:crowdsecAppsecKey fail to get CrowdsecAppsecKey and no client certificate setup", "error", errAppsecKey)
	} else {
		cfg.CrowdsecAppsecKey = apiAppsecKey
	}
	return nil
}

// New constructs an AppSec Client. Call Prepare first. Close releases idle HTTP.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string) (*Client, error) {
	next, err := newTransport(config, log)
	if err != nil {
		log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig", "error", err)
		return nil, err
	}
	client := &Client{
		appsecScheme:    config.CrowdsecAppsecScheme,
		appsecHost:      config.CrowdsecAppsecHost,
		appsecPath:      config.CrowdsecAppsecPath,
		appsecBodyLimit: config.CrowdsecAppsecBodyLimit,
		instanceName:    config.CrowdsecAppsecInstanceName,
		log:             log,
		pluginVersion:   pluginVersion,
	}
	client.incarnation = fmt.Sprintf("%p", client)
	client.transport.Store(next)
	client.logLifecycle(MsgInstanceStarted, "started", false)
	return client, nil
}

// Close releases idle AppSec HTTP connections. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.sleeping = false
	current := c.currentTransport()
	c.mu.Unlock()
	if current != nil {
		closeIdle(current.httpClient)
	}
	c.logLifecycle(MsgInstanceClosed, "closed", false)
	instance.Clear(instance.LegAppSec, c, c.middlewareName)
}

// Sleep logs DEBUG and marks the incarnation asleep. AppSec has no tickers.
func (c *Client) Sleep() {
	c.mu.Lock()
	if c.closed || c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = true
	c.mu.Unlock()
	c.logLifecycle(MsgInstanceSleeping, "sleeping", true)
}

// Wake logs DEBUG after Sleep. AppSec has no tickers.
func (c *Client) Wake() {
	c.mu.Lock()
	if c.closed || !c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = false
	c.mu.Unlock()
	c.logLifecycle(MsgInstanceWaking, "waking", true)
}

// Incarnation is unique per Client create.
func (c *Client) Incarnation() string {
	if c == nil {
		return ""
	}
	return c.incarnation
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
	c.instanceName = name
	c.mu.Unlock()
}

func (c *Client) logLifecycle(msg, reason string, debug bool) {
	if c.log == nil {
		return
	}
	if debug {
		c.log.Debug(msg, "leg", instance.LegAppSec, "instanceName", c.instanceName, "incarnation", c.incarnation, "sessionKey", c.sessionKey, "reason", reason)
		return
	}
	c.log.Info(msg, "leg", instance.LegAppSec, "instanceName", c.instanceName, "incarnation", c.incarnation, "sessionKey", c.sessionKey, "reason", reason)
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}
