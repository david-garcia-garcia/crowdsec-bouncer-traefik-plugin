/*TODO: NEEDS HUMAN REVIEW*/
package crowdsecclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/types"
)

// Config contains configuration for the CrowdSec API client
type Config struct {
	// Connection settings
	Scheme string
	Host   string
	Path   string
	Key    string
	Mode   string

	// CAPI settings (for alone mode)
	MachineID string
	Password  string
	Scenarios []string

	// HTTP client
	HTTPClient *http.Client
}

// Client handles all communications with CrowdSec API
type Client struct {
	config *Config
	log    *logger.Log
	token  string // For CAPI mode
}

// Login response from CrowdSec CAPI
type Login struct {
	Code   int    `json:"code"`
	Token  string `json:"token"`
	Expire string `json:"expire"`
}

// NewClient creates a new CrowdSec API client
func NewClient(config *Config, log *logger.Log) *Client {
	return &Client{
		config: config,
		log:    log,
	}
}

// Initialize performs initial setup for the client (e.g., CAPI login)
func (c *Client) Initialize() error {
	if c.config.Mode == "alone" {
		return c.login()
	}
	return nil
}

// login authenticates with CrowdSec CAPI and obtains a token
func (c *Client) login() error {
	loginURL := url.URL{
		Scheme: c.config.Scheme,
		Host:   c.config.Host,
		Path:   "v2/watchers/login",
	}

	loginData := []byte(fmt.Sprintf(
		`{"machine_id": "%v","password": "%v","scenarios": ["%v"]}`,
		c.config.MachineID,
		c.config.Password,
		strings.Join(c.config.Scenarios, `","`),
	))

	body, err := c.doRequest(http.MethodPost, loginURL.String(), loginData, false)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}

	var login Login
	err = json.Unmarshal(body, &login)
	if err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	if login.Code == 200 && len(login.Token) > 0 {
		c.token = login.Token
		c.config.Key = login.Token // Update the key for subsequent requests
		c.log.Debug(fmt.Sprintf("Successfully obtained CAPI token (code: %d)", login.Code))
		return nil
	}

	return fmt.Errorf("login failed with code: %d", login.Code)
}

// GetDecisions retrieves decisions for a specific IP (for live mode)
func (c *Client) GetDecisions(ip string) ([]types.CrowdSecDecision, error) {
	routeURL := url.URL{
		Scheme:   c.config.Scheme,
		Host:     c.config.Host,
		Path:     c.config.Path + "v1/decisions",
		RawQuery: fmt.Sprintf("ip=%v", ip),
	}

	body, err := c.doRequest(http.MethodGet, routeURL.String(), nil, true)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(body, []byte("null")) {
		return nil, nil
	}

	var decisions []types.CrowdSecDecision
	err = json.Unmarshal(body, &decisions)
	if err != nil {
		return nil, fmt.Errorf("failed to parse decisions response: %w", err)
	}

	return decisions, nil
}

// GetDecisionStream retrieves the decision stream
func (c *Client) GetDecisionStream(startup bool) (*types.Stream, error) {
	var streamRoute string
	if c.config.Mode == "alone" {
		streamRoute = "v2/decisions/stream"
	} else {
		streamRoute = "v1/decisions/stream"
	}

	streamURL := url.URL{
		Scheme:   c.config.Scheme,
		Host:     c.config.Host,
		Path:     c.config.Path + streamRoute,
		RawQuery: fmt.Sprintf("startup=%t", startup),
	}

	body, err := c.doRequest(http.MethodGet, streamURL.String(), nil, true)
	if err != nil {
		return nil, err
	}

	var stream types.Stream
	err = json.Unmarshal(body, &stream)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream response: %w", err)
	}

	return &stream, nil
}

// SendMetrics sends usage metrics to CrowdSec
func (c *Client) SendMetrics(metrics map[string]interface{}) error {
	metricsURL := url.URL{
		Scheme: c.config.Scheme,
		Host:   c.config.Host,
		Path:   c.config.Path + "v1/usage-metrics",
	}

	data, err := json.Marshal(metrics)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	_, err = c.doRequest(http.MethodPost, metricsURL.String(), data, true)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}

	c.log.Debug("Successfully sent metrics to CrowdSec")
	return nil
}

// doRequest performs an HTTP request to the CrowdSec API
func (c *Client) doRequest(method, url string, data []byte, withAuth bool) ([]byte, error) {
	var req *http.Request
	var err error

	if data != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Add("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
	}

	// Add authentication headers
	if withAuth {
		if c.config.Mode == "alone" {
			req.Header.Add("Authorization", c.config.Key)
		} else {
			req.Header.Add("X-Api-Key", c.config.Key)
		}
	}
	req.Header.Add("User-Agent", "Crowdsec-Bouncer-Traefik-Plugin/1.X.X")

	res, err := c.config.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed for %s: %w", url, err)
	}
	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			c.log.Error("Failed to close response body: " + closeErr.Error())
		}
	}()

	// Handle token renewal for CAPI mode
	if res.StatusCode == http.StatusUnauthorized && c.config.Mode == "alone" && withAuth {
		c.log.Debug("Token expired, attempting renewal")
		if loginErr := c.login(); loginErr != nil {
			return nil, fmt.Errorf("failed to renew token for %s: %w", url, loginErr)
		}
		// Retry the request with the new token
		return c.doRequest(method, url, data, withAuth)
	}

	// Check if the status code starts with 2
	statusStr := strconv.Itoa(res.StatusCode)
	if len(statusStr) < 1 || statusStr[0] != '2' {
		return nil, fmt.Errorf("request to %s failed with status %d (expected 2xx)", url, res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// GetConfig returns the client configuration
func (c *Client) GetConfig() *Config {
	return c.config
}

// UpdateKey updates the API key (useful for token renewal)
func (c *Client) UpdateKey(key string) {
	c.config.Key = key
	c.token = key
}
