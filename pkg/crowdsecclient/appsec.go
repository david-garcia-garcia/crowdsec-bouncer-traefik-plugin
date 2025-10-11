/*TODO: NEEDS HUMAN REVIEW*/
package crowdsecclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// AppSecConfig contains configuration for the AppSec client
type AppSecConfig struct {
	Enabled          bool
	Host             string
	Path             string
	Scheme           string
	Key              string
	BodyLimit        int64
	FailureBlock     bool
	UnreachableBlock bool
	HTTPClient       *http.Client
}

// AppSecClient handles communications with CrowdSec AppSec
type AppSecClient struct {
	config *AppSecConfig
	log    *logger.Log
}

// NewAppSecClient creates a new AppSec client
func NewAppSecClient(config *AppSecConfig, log *logger.Log) *AppSecClient {
	return &AppSecClient{
		config: config,
		log:    log,
	}
}

// CheckRequest performs an AppSec check for an HTTP request
func (c *AppSecClient) CheckRequest(ip string, httpReq *http.Request) error {
	if !c.config.Enabled {
		return nil
	}

	routeURL := url.URL{
		Scheme: c.config.Scheme,
		Host:   c.config.Host,
		Path:   c.config.Path,
	}

	var req *http.Request
	if c.config.BodyLimit > 0 && httpReq.Body != nil && httpReq.ContentLength > 0 {
		var bodyBuffer bytes.Buffer
		limitedReader := io.LimitReader(httpReq.Body, c.config.BodyLimit)
		teeReader := io.TeeReader(limitedReader, &bodyBuffer)
		bodyBytes, err := io.ReadAll(teeReader)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		// Conserve body intact after reading it for other middlewares and service
		httpReq.Body = io.NopCloser(io.MultiReader(&bodyBuffer, httpReq.Body))
		req, _ = http.NewRequest(http.MethodPost, routeURL.String(), bytes.NewBuffer(bodyBytes))
	} else {
		req, _ = http.NewRequest(http.MethodGet, routeURL.String(), nil)
	}

	// Copy headers from original request
	for key, headers := range httpReq.Header {
		for _, value := range headers {
			req.Header.Add(key, value)
		}
	}

	// Add CrowdSec AppSec headers
	req.Header.Set("X-Crowdsec-Appsec-Api-Key", c.config.Key)
	req.Header.Set("X-Crowdsec-Appsec-Ip", ip)
	req.Header.Set("X-Crowdsec-Appsec-Verb", httpReq.Method)
	req.Header.Set("X-Crowdsec-Appsec-Host", httpReq.Host)
	req.Header.Set("X-Crowdsec-Appsec-Uri", httpReq.URL.String())
	req.Header.Set("X-Crowdsec-Appsec-User-Agent", httpReq.Header.Get("User-Agent"))

	res, err := c.config.HTTPClient.Do(req)
	if err != nil {
		c.log.Error("AppSec request failed: " + err.Error())
		if c.config.UnreachableBlock {
			return fmt.Errorf("AppSec unreachable: %w", err)
		}
		return nil
	}

	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			c.log.Error("Failed to close AppSec response body: " + closeErr.Error())
		}
	}()

	if res.StatusCode == http.StatusInternalServerError {
		c.log.Info("AppSec returned internal server error")
		if c.config.FailureBlock {
			return fmt.Errorf("AppSec failure (status 500)")
		}
		return nil
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("AppSec blocked request (status %d)", res.StatusCode)
	}

	// Status 200 means allowed
	return nil
}

// IsEnabled returns whether AppSec is enabled
func (c *AppSecClient) IsEnabled() bool {
	return c.config.Enabled
}

// GetConfig returns the AppSec configuration
func (c *AppSecClient) GetConfig() *AppSecConfig {
	return c.config
}
