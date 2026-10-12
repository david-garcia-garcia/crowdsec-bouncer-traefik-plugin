// Package modsecurity is the reclaim value for one OWASP CRS sidecar inspect client.
package modsecurity

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
)

const (
	// MsgInstanceStarted is the INFO create line for one ModSec Client incarnation.
	MsgInstanceStarted = "crowdsec modsec instance started"
	// MsgInstanceSleeping is the DEBUG line when the last subscriber leaves.
	MsgInstanceSleeping = "crowdsec modsec instance sleeping"
	// MsgInstanceWaking is the DEBUG line when a subscriber binds again.
	MsgInstanceWaking = "crowdsec modsec instance waking"
	// MsgInstanceClosed is the INFO line when the Client incarnation is closed.
	MsgInstanceClosed = "crowdsec modsec instance closed"
)

// defaultDenyVerbsWithBody is the omitted/nil deny list.
var defaultDenyVerbsWithBody = []string{"HEAD", "GET", "DELETE", "OPTIONS", "TRACE", "CONNECT"} //nolint:gochecknoglobals

const defaultPoolCap int64 = 5 * 1024 * 1024

// Client is the reclaim value for one CRS sidecar listener.
type Client struct {
	mu sync.Mutex

	bodyBufferPool    *sync.Pool
	bodyLimit         int64
	closed            bool
	denyVerbsWithBody map[string]bool
	gate              *backendbackoff.Gate
	httpClient        *http.Client
	incarnation       string
	instanceName      string
	log               *slog.Logger
	middlewareName    string
	modsecURL         string
	pluginVersion     string
	poolCap           int64
	sessionKey        string
	sleeping          bool
}

// New constructs a ModSec Client. Call Prepare first. Close releases the Gate and idle HTTP.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string, middlewareName, bindKey string) (*Client, error) {
	log = log.With(
		"traefikName", middlewareName,
		"instanceName", config.ModsecInstanceName,
		"leg", "modsec",
		"sessionKey", bindKey,
	)
	gate, err := newAdmissionGate(
		config.ModsecUnhealthyBackOffPeriodSecs,
		config.ModsecUnhealthyMaxBackOffPeriodSecs,
		config.ModsecUnhealthyFailureThreshold,
		config.ModsecUnhealthyFailureRatio,
	)
	if err != nil {
		return nil, err
	}
	client := &Client{
		bodyBufferPool:    newBodyBufferPool(),
		bodyLimit:         config.ModsecBodyLimit,
		denyVerbsWithBody: createMethodSet(config.ModsecDenyVerbsWithBody),
		gate:              gate,
		httpClient:        newHTTPClient(config.ModsecHTTPTimeoutSeconds),
		instanceName:      config.ModsecInstanceName,
		log:               log,
		middlewareName:    middlewareName,
		modsecURL:         strings.TrimSuffix(strings.TrimSpace(config.ModsecURL), "/"),
		pluginVersion:     pluginVersion,
		poolCap:           defaultPoolCap,
		sessionKey:        bindKey,
	}
	client.incarnation = fmt.Sprintf("%p", client)
	client.log.Info(MsgInstanceStarted, "incarnation", client.incarnation, "reason", "started")
	return client, nil
}

// Close releases the admission gate and idle sidecar HTTP. Safe to call more than once.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.sleeping = false
	gate := c.gate
	httpClient := c.httpClient
	c.mu.Unlock()
	if gate != nil {
		gate.Close()
	}
	if httpClient != nil {
		httpClient.CloseIdleConnections()
	}
	c.log.Info(MsgInstanceClosed, "incarnation", c.incarnation, "reason", "closed")
}

// Sleep logs DEBUG and marks the incarnation asleep. ModSec has no tickers.
func (c *Client) Sleep() {
	c.mu.Lock()
	if c.closed || c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = true
	c.mu.Unlock()
	c.log.Debug(MsgInstanceSleeping, "incarnation", c.incarnation, "reason", "sleeping")
}

// Wake logs DEBUG after Sleep. ModSec has no tickers.
func (c *Client) Wake() {
	c.mu.Lock()
	if c.closed || !c.sleeping {
		c.mu.Unlock()
		return
	}
	c.sleeping = false
	c.mu.Unlock()
	c.log.Debug(MsgInstanceWaking, "incarnation", c.incarnation, "reason", "waking")
}

// Incarnation is unique per Client create.
func (c *Client) Incarnation() string {
	if c == nil {
		return ""
	}
	return c.incarnation
}

// GateForTest is the admission gate, or nil when backoff is off.
func (c *Client) GateForTest() *backendbackoff.Gate {
	if c == nil {
		return nil
	}
	return c.gate
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

// createMethodSet converts HTTP methods to an uppercase set. Nil uses the default list; empty denies nothing.
func createMethodSet(methods []string) map[string]bool {
	if methods == nil {
		methods = defaultDenyVerbsWithBody
	}
	set := make(map[string]bool, len(methods))
	for _, method := range methods {
		set[strings.ToUpper(method)] = true
	}
	return set
}
