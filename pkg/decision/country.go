/*TODO: NEEDS HUMAN REVIEW*/
package decision

import (
	"fmt"
	"strings"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// CountryDecisionProvider handles country-based decisions using the cache abstraction
type CountryDecisionProvider struct {
	cacheClient *cache.Client
	log         *logger.Log
	enabled     bool
}

// NewCountryDecisionProvider creates a new country decision provider
func NewCountryDecisionProvider(log *logger.Log, cacheClient *cache.Client, enabled bool) *CountryDecisionProvider {
	return &CountryDecisionProvider{
		cacheClient: cacheClient,
		log:         log,
		enabled:     enabled,
	}
}

// Name returns the provider name
func (p *CountryDecisionProvider) Name() string {
	return "country"
}

// Check if a country should be blocked
func (p *CountryDecisionProvider) Check(req *DecisionRequest) (*DecisionResult, error) {
	if !p.enabled || req.Country == "" {
		return &DecisionResult{Blocked: false}, nil
	}

	// Normalize country code to uppercase
	countryCode := strings.ToUpper(strings.TrimSpace(req.Country))
	cacheKey := "country:" + countryCode

	value, err := p.cacheClient.Get(cacheKey)
	if err != nil {
		if err.Error() == cache.CacheMiss {
			return &DecisionResult{Blocked: false}, nil
		}
		return nil, fmt.Errorf("cache error for country %s: %w", countryCode, err)
	}

	if value == cache.NoBannedValue {
		return &DecisionResult{Blocked: false}, nil
	}

	// Parse cache value with scenario prefix (format: "t:scenario" or "c:scenario")
	if len(value) < 2 || value[1] != ':' {
		return nil, fmt.Errorf("invalid cache value format for country %s: %s (expected 'x:scenario')", countryCode, value)
	}

	var decisionType DecisionType
	switch value[0] {
	case 't': // ban
		decisionType = TypeBan
	case 'c': // captcha
		decisionType = TypeCaptcha
	case 'f': // not banned (shouldn't happen here)
		return &DecisionResult{Blocked: false}, nil
	default:
		return nil, fmt.Errorf("unknown decision type prefix '%c' for country %s", value[0], countryCode)
	}

	scenario := value[2:] // Everything after "x:"

	return &DecisionResult{
		Blocked:   true,
		Type:      decisionType,
		Scenario:  scenario,
		Value:     countryCode,
		MatchedBy: ScopeCountry,
	}, nil
}

// AddDecision adds a country decision
func (p *CountryDecisionProvider) AddDecision(scope DecisionScope, value string, decision *DecisionInfo) error {
	if scope != ScopeCountry {
		return fmt.Errorf("country provider only handles country scope, got %s", scope)
	}

	if !p.enabled {
		return fmt.Errorf("country provider is disabled")
	}

	// Normalize country code to uppercase
	countryCode := strings.ToUpper(strings.TrimSpace(value))
	if countryCode == "" {
		return fmt.Errorf("empty country code")
	}

	// Basic validation for country code format (2-3 letter codes)
	if len(countryCode) < 2 || len(countryCode) > 3 {
		return fmt.Errorf("invalid country code format: %s (expected 2-3 letters)", countryCode)
	}

	// Convert decision to cache value with scenario prefix (format: "t:scenario" or "c:scenario")
	var cacheValue string
	switch decision.Type {
	case TypeBan:
		cacheValue = "t:" + decision.Scenario
	case TypeCaptcha:
		cacheValue = "c:" + decision.Scenario
	default:
		cacheValue = "t:" + decision.Scenario
	}

	// Calculate duration in seconds
	duration := int64(time.Until(decision.ExpiresAt).Seconds())
	if duration <= 0 {
		duration = 60 // Default to 1 minute if expired
	}

	cacheKey := "country:" + countryCode
	p.cacheClient.Set(cacheKey, cacheValue, duration)

	p.log.Debug(fmt.Sprintf("Country decision added: %s -> %s (expires: %s)",
		countryCode, decision.Type, decision.ExpiresAt.Format(time.RFC3339)))

	return nil
}

// RemoveDecision removes a country decision
func (p *CountryDecisionProvider) RemoveDecision(scope DecisionScope, value string) error {
	if scope != ScopeCountry {
		return fmt.Errorf("country provider only handles country scope, got %s", scope)
	}

	if !p.enabled {
		return nil // Silently ignore if disabled
	}

	// Normalize country code to uppercase
	countryCode := strings.ToUpper(strings.TrimSpace(value))
	cacheKey := "country:" + countryCode

	p.cacheClient.Delete(cacheKey)

	p.log.Debug(fmt.Sprintf("Country decision removed: %s", countryCode))

	return nil
}

// CleanupExpired removes expired decisions (handled automatically by cache TTL)
func (p *CountryDecisionProvider) CleanupExpired() error {
	// Cache handles expiration automatically via TTL
	return nil
}

// Stats helper functions removed - metrics now handled centrally
