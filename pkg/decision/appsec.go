/*TODO: NEEDS HUMAN REVIEW*/
package decision

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/crowdsecclient"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// AppSecDecisionProvider handles AppSec-based decisions by querying the AppSec endpoint
type AppSecDecisionProvider struct {
	mu           sync.RWMutex
	log          *logger.Log
	appsecClient *crowdsecclient.AppSecClient
}

// AppSecConfig contains configuration for the AppSec provider
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

// NewAppSecDecisionProvider creates a new AppSec decision provider
func NewAppSecDecisionProvider(log *logger.Log, config *AppSecConfig) *AppSecDecisionProvider {
	// Create AppSec client configuration
	clientConfig := &crowdsecclient.AppSecConfig{
		Enabled:          config.Enabled,
		Host:             config.Host,
		Path:             config.Path,
		Scheme:           config.Scheme,
		Key:              config.Key,
		BodyLimit:        config.BodyLimit,
		FailureBlock:     config.FailureBlock,
		UnreachableBlock: config.UnreachableBlock,
		HTTPClient:       config.HTTPClient,
	}

	appsecClient := crowdsecclient.NewAppSecClient(clientConfig, log)

	return &AppSecDecisionProvider{
		log:          log,
		appsecClient: appsecClient,
	}
}

// Name returns the provider name
func (p *AppSecDecisionProvider) Name() string {
	return "appsec"
}

// Check performs an AppSec query to determine if a request should be blocked
func (p *AppSecDecisionProvider) Check(req *DecisionRequest) (*DecisionResult, error) {
	if !p.appsecClient.IsEnabled() {
		return &DecisionResult{Blocked: false}, nil
	}

	// AppSec requires an HTTP request context, which we don't have in DecisionRequest
	// This method should not be called directly for AppSec
	// Instead, AppSec should be integrated at the HTTP handler level
	return &DecisionResult{Blocked: false}, fmt.Errorf("AppSec provider requires HTTP request context")
}

// CheckHTTPRequest performs an AppSec query with full HTTP request context
func (p *AppSecDecisionProvider) CheckHTTPRequest(ip string, httpReq *http.Request) (*DecisionResult, error) {
	if !p.appsecClient.IsEnabled() {
		return &DecisionResult{Blocked: false}, nil
	}

	err := p.appsecClient.CheckRequest(ip, httpReq)
	if err != nil {
		// AppSec blocked the request
		return &DecisionResult{
			Blocked:   true,
			Type:      TypeBan,
			Scenario:  "appsec_block",
			Value:     ip,
			MatchedBy: ScopeIP,
		}, nil
	}

	// Request allowed
	return &DecisionResult{Blocked: false}, nil
}

// AddDecision is not applicable for AppSec (decisions are made in real-time)
func (p *AppSecDecisionProvider) AddDecision(scope DecisionScope, value string, decision *DecisionInfo) error {
	return fmt.Errorf("AppSec provider does not support adding decisions (decisions are made in real-time)")
}

// RemoveDecision is not applicable for AppSec (decisions are made in real-time)
func (p *AppSecDecisionProvider) RemoveDecision(scope DecisionScope, value string) error {
	return fmt.Errorf("AppSec provider does not support removing decisions (decisions are made in real-time)")
}

// CleanupExpired is not applicable for AppSec (no stored decisions)
func (p *AppSecDecisionProvider) CleanupExpired() error {
	// Nothing to clean up for AppSec
	return nil
}
