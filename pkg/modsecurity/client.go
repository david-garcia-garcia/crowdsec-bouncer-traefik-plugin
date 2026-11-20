// Package modsecurity is the reclaim value for one OWASP CRS sidecar inspect client.
package modsecurity

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
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
	// MsgBackoffStarted is the WARN line when the admission gate starts skipping the sidecar.
	MsgBackoffStarted = "crowdsec modsec backoff started"
	// MsgBackoffEnded is the INFO line when a sidecar probe succeeds after a backoff.
	MsgBackoffEnded = "crowdsec modsec backoff ended"
)

// gateKey is the admission leg name and gate key.
const gateKey = "modsec"

// Client is the reclaim value for one CRS sidecar listener.
type Client struct {
	mu sync.Mutex

	bodyLimit      int64
	closed         bool
	gate           *admission.Gate
	httpClient     *http.Client
	incarnation    string
	instanceName   string
	log            *slog.Logger
	middlewareName string
	modsecURL      string
	pluginVersion  string
	sessionKey     string
	sleeping       bool
}

// New constructs a ModSec Client. Call Prepare first. Close releases the Gate and idle HTTP.
func New(config *configuration.Config, log *slog.Logger, pluginVersion string, middlewareName, bindKey string) (*Client, error) {
	log = log.With(
		"traefikName", middlewareName,
		"instanceName", config.ModsecInstanceName,
		"leg", "modsec",
		"sessionKey", bindKey,
	)
	gate, err := admission.New(admission.Config{
		Leg:        gateKey,
		PeriodSecs: config.ModsecUnhealthyBackOffPeriodSecs,
		MsgStarted: MsgBackoffStarted,
		MsgEnded:   MsgBackoffEnded,
	}, log)
	if err != nil {
		return nil, err
	}
	client := &Client{
		bodyLimit:      config.ModsecBodyLimit,
		gate:           gate,
		httpClient:     newHTTPClient(config.ModsecHTTPTimeoutSeconds),
		instanceName:   config.ModsecInstanceName,
		log:            log,
		middlewareName: middlewareName,
		modsecURL:      strings.TrimSuffix(strings.TrimSpace(config.ModsecURL), "/"),
		pluginVersion:  pluginVersion,
		sessionKey:     bindKey,
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
	gate.Close()
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
func (c *Client) GateForTest() *admission.Gate {
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
