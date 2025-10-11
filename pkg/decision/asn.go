/*TODO: NEEDS HUMAN REVIEW*/
package decision

import (
	"fmt"
	"strings"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// ASNDecisionProvider handles ASN-based decisions using the cache abstraction
type ASNDecisionProvider struct {
	cacheClient *cache.Client
	log         *logger.Log
	enabled     bool
}

// NewASNDecisionProvider creates a new ASN decision provider
func NewASNDecisionProvider(log *logger.Log, cacheClient *cache.Client, enabled bool) *ASNDecisionProvider {
	return &ASNDecisionProvider{
		cacheClient: cacheClient,
		log:         log,
		enabled:     enabled,
	}
}

// Name returns the provider name
func (p *ASNDecisionProvider) Name() string {
	return "asn"
}

// Check if an ASN should be blocked
func (p *ASNDecisionProvider) Check(req *DecisionRequest) (*DecisionResult, error) {
	if !p.enabled || req.ASN == "" {
		return &DecisionResult{Blocked: false}, nil
	}

	// Normalize ASN (remove AS prefix if present, convert to uppercase)
	asn := normalizeASN(req.ASN)
	cacheKey := "asn:" + asn

	value, err := p.cacheClient.Get(cacheKey)
	if err != nil {
		if err.Error() == cache.CacheMiss {
			return &DecisionResult{Blocked: false}, nil
		}
		return nil, fmt.Errorf("cache error for ASN %s: %w", asn, err)
	}

	if value == cache.NoBannedValue {
		return &DecisionResult{Blocked: false}, nil
	}

	// Parse cache value with scenario prefix (format: "t:scenario" or "c:scenario")
	if len(value) < 2 || value[1] != ':' {
		return nil, fmt.Errorf("invalid cache value format for ASN %s: %s (expected 'x:scenario')", asn, value)
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
		return nil, fmt.Errorf("unknown decision type prefix '%c' for ASN %s", value[0], asn)
	}

	scenario := value[2:] // Everything after "x:"

	return &DecisionResult{
		Blocked:   true,
		Type:      decisionType,
		Scenario:  scenario,
		Value:     asn,
		MatchedBy: ScopeAS,
	}, nil
}

// AddDecision adds an ASN decision
func (p *ASNDecisionProvider) AddDecision(scope DecisionScope, value string, decision *DecisionInfo) error {
	if scope != ScopeAS {
		return fmt.Errorf("ASN provider only handles AS scope, got %s", scope)
	}

	if !p.enabled {
		return fmt.Errorf("ASN provider is disabled")
	}

	// Normalize ASN
	asn := normalizeASN(value)
	if asn == "" {
		return fmt.Errorf("empty ASN")
	}

	// Basic validation for ASN format
	if err := validateASN(asn); err != nil {
		return fmt.Errorf("invalid ASN format: %s, error: %v", value, err)
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

	cacheKey := "asn:" + asn
	p.cacheClient.Set(cacheKey, cacheValue, duration)

	p.log.Debug(fmt.Sprintf("ASN decision added: %s -> %s (expires: %s)",
		asn, decision.Type, decision.ExpiresAt.Format(time.RFC3339)))

	return nil
}

// RemoveDecision removes an ASN decision
func (p *ASNDecisionProvider) RemoveDecision(scope DecisionScope, value string) error {
	if scope != ScopeAS {
		return fmt.Errorf("ASN provider only handles AS scope, got %s", scope)
	}

	if !p.enabled {
		return nil // Silently ignore if disabled
	}

	// Normalize ASN
	asn := normalizeASN(value)
	cacheKey := "asn:" + asn

	p.cacheClient.Delete(cacheKey)

	p.log.Debug(fmt.Sprintf("ASN decision removed: %s", asn))

	return nil
}

// CleanupExpired removes expired decisions (handled automatically by cache TTL)
func (p *ASNDecisionProvider) CleanupExpired() error {
	// Cache handles expiration automatically via TTL
	return nil
}

// normalizeASN normalizes an ASN string for consistent storage and lookup
func normalizeASN(asn string) string {
	asn = strings.TrimSpace(asn)
	asn = strings.ToUpper(asn)

	// Remove "AS" prefix if present
	asn = strings.TrimPrefix(asn, "AS")

	return asn
}

// validateASN validates that an ASN string is in a valid format
func validateASN(asn string) error {
	if asn == "" {
		return fmt.Errorf("ASN cannot be empty")
	}

	// ASN should be numeric after normalization
	for _, char := range asn {
		if char < '0' || char > '9' {
			return fmt.Errorf("ASN should be numeric, got: %s", asn)
		}
	}

	return nil
}

// Stats helper functions removed - metrics now handled centrally
