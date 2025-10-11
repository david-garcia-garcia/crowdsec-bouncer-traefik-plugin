package decision

import (
	"fmt"
	"net"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// IPDecisionProvider handles IP-based decisions using the cache abstraction
type IPDecisionProvider struct {
	cacheClient *cache.Client
	log         *logger.Log
}

// NewIPDecisionProvider creates a new IP decision provider
func NewIPDecisionProvider(log *logger.Log, cacheClient *cache.Client) *IPDecisionProvider {
	return &IPDecisionProvider{
		cacheClient: cacheClient,
		log:         log,
	}
}

// Name returns the provider name
func (p *IPDecisionProvider) Name() string {
	return "ip"
}

// Check if an IP should be blocked
func (p *IPDecisionProvider) Check(req *DecisionRequest) (*DecisionResult, error) {
	if req.IP == nil || req.IPString == "" {
		return &DecisionResult{Blocked: false}, nil
	}

	value, err := p.cacheClient.Get(req.IPString)
	if err != nil {
		if err.Error() == cache.CacheMiss {
			return &DecisionResult{Blocked: false}, nil
		}
		return nil, fmt.Errorf("cache error for IP %s: %w", req.IPString, err)
	}

	if value == cache.NoBannedValue {
		return &DecisionResult{Blocked: false}, nil
	}

	// Parse cache value with scenario prefix (format: "t:scenario" or "c:scenario")
	if len(value) < 2 || value[1] != ':' {
		return nil, fmt.Errorf("invalid cache value format for IP %s: %s (expected 'x:scenario')", req.IPString, value)
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
		return nil, fmt.Errorf("unknown decision type prefix '%c' for IP %s", value[0], req.IPString)
	}

	scenario := value[2:] // Everything after "x:"

	return &DecisionResult{
		Blocked:   true,
		Type:      decisionType,
		Scenario:  scenario,
		Value:     req.IPString,
		MatchedBy: ScopeIP,
	}, nil
}

// AddDecision adds an IP decision
func (p *IPDecisionProvider) AddDecision(scope DecisionScope, value string, decision *DecisionInfo) error {
	if scope != ScopeIP {
		return fmt.Errorf("IP provider only handles IP scope, got %s", scope)
	}

	// Validate IP
	ip := net.ParseIP(value)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", value)
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

	p.cacheClient.Set(value, cacheValue, duration)

	p.log.Debug(fmt.Sprintf("IP decision added: %s -> %s (expires: %s)",
		value, decision.Type, decision.ExpiresAt.Format(time.RFC3339)))

	return nil
}

// RemoveDecision removes an IP decision
func (p *IPDecisionProvider) RemoveDecision(scope DecisionScope, value string) error {
	if scope != ScopeIP {
		return fmt.Errorf("IP provider only handles IP scope, got %s", scope)
	}

	p.cacheClient.Delete(value)

	p.log.Debug(fmt.Sprintf("IP decision removed: %s", value))

	return nil
}

// CleanupExpired removes expired decisions (handled automatically by cache TTL)
func (p *IPDecisionProvider) CleanupExpired() error {
	// Cache handles expiration automatically via TTL
	return nil
}

// Stats helper functions removed - metrics now handled centrally
