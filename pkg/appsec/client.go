// Package appsec is the reclaim value for one CrowdSec AppSec listener.
package appsec

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
)

const (
	// MsgInstanceStarted is the INFO create line for one AppSec Client incarnation.
	MsgInstanceStarted = "crowdsec appsec instance started"
	// MsgInstanceSleeping is the DEBUG line when the last subscriber leaves.
	MsgInstanceSleeping = "crowdsec appsec instance sleeping"
	// MsgInstanceWaking is the DEBUG line when a subscriber binds again.
	MsgInstanceWaking = "crowdsec appsec instance waking"
	// MsgInstanceClosed is the INFO line when the Client incarnation is closed.
	MsgInstanceClosed = "crowdsec appsec instance closed"
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
	middlewareName  string
	instanceName    string
	incarnation     string
	sessionKey      string
	closed          bool
	sleeping        bool
}

// Prepare resolves AppSec secrets on cfg when AppSec is enabled. Empty key/scheme copy from LAPI.
func Prepare(cfg *configuration.Config, log *slog.Logger, traefikName string) error {
	if !cfg.AppsecEnabled {
		return nil
	}
	if strings.TrimSpace(cfg.AppsecInstanceName) == "" {
		cfg.AppsecInstanceName = traefikName
	}
	if cfg.AppsecKey == "" {
		cfg.AppsecKey = cfg.LapiKey
	}
	if cfg.AppsecScheme == "" {
		cfg.AppsecScheme = cfg.LapiScheme
	}
	apiAppsecKey, errAppsecKey := configuration.GetVariable(cfg, "AppsecKey")
	if errAppsecKey != nil {
		log.Info("Prepare:crowdsecAppsecKey fail to get AppsecKey and no client certificate setup", "error", errAppsecKey)
	} else {
		cfg.AppsecKey = apiAppsecKey
	}
	return nil
}

// New constructs an AppSec Client. Call Prepare first. Close releases idle HTTP.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string, middlewareName, bindKey string) (*Client, error) {
	log = log.With(
		"traefikName", middlewareName,
		"instanceName", config.AppsecInstanceName,
		"leg", "appsec",
		"sessionKey", bindKey,
	)
	next, err := newTransport(config, log)
	if err != nil {
		log.Error("New:getTLSConfigCrowdsec fail to get tlsAppsecConfig", "error", err)
		return nil, err
	}
	client := &Client{
		appsecScheme:    config.AppsecScheme,
		appsecHost:      config.AppsecHost,
		appsecPath:      config.AppsecPath,
		appsecBodyLimit: config.AppsecBodyLimit,
		middlewareName:  middlewareName,
		instanceName:    config.AppsecInstanceName,
		sessionKey:      bindKey,
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

func (c *Client) logLifecycle(msg, reason string, debug bool) {
	if c.log == nil {
		return
	}
	if debug {
		c.log.Debug(msg, "incarnation", c.incarnation, "reason", reason)
		return
	}
	c.log.Info(msg, "incarnation", c.incarnation, "reason", reason)
}

func isReverseProxyError(statusCode int) bool {
	return statusCode == http.StatusBadGateway ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout
}
