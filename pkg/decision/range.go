/*TODO: NEEDS HUMAN REVIEW*/
package decision

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/iprange"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/types"
)

// RangeDecisionProvider handles CIDR range-based decisions using a radix tree
type RangeDecisionProvider struct {
	mu   sync.RWMutex
	tree *iprange.RadixTree
	log  *logger.Log
}

// Old radix tree implementation removed - now using pkg/iprange

// NewRangeDecisionProvider creates a new range decision provider
func NewRangeDecisionProvider(log *logger.Log) *RangeDecisionProvider {
	return &RangeDecisionProvider{
		tree: iprange.NewRadixTree(),
		log:  log,
	}
}

// Old constructor removed

// Name returns the provider name
func (p *RangeDecisionProvider) Name() string {
	return "range"
}

// Check if an IP should be blocked by any range
func (p *RangeDecisionProvider) Check(req *DecisionRequest) (*DecisionResult, error) {
	if req.IP == nil {
		return &DecisionResult{Blocked: false}, nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	found, data, _ := p.tree.Contains(req.IP)

	if !found || data == nil {
		return &DecisionResult{Blocked: false}, nil
	}

	decisionData, ok := data.(*types.DecisionData)
	if !ok {
		return &DecisionResult{Blocked: false}, nil
	}

	// Convert types.DecisionData to DecisionInfo
	var decisionType DecisionType
	switch decisionData.Type {
	case "ban":
		decisionType = TypeBan
	case "captcha":
		decisionType = TypeCaptcha
	default:
		decisionType = TypeBan
	}

	var source DecisionSource
	switch decisionData.Source {
	case "crowdsec":
		source = SourceCrowdSec
	case "appsec":
		source = SourceAppSec
	default:
		source = SourceCrowdSec
	}

	return &DecisionResult{
		Blocked:   true,
		Type:      decisionType,
		Scenario:  decisionData.Scenario,
		Value:     decisionData.Value,
		MatchedBy: ScopeRange,
	}, nil
}

// AddDecision adds a range decision
func (p *RangeDecisionProvider) AddDecision(scope DecisionScope, value string, decision *DecisionInfo) error {
	if scope != ScopeRange {
		return fmt.Errorf("range provider only handles range scope, got %s", scope)
	}

	// Parse CIDR
	_, cidr, err := net.ParseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid CIDR range: %s, error: %v", value, err)
	}

	// Convert DecisionInfo to types.DecisionData for storage
	decisionData := &types.DecisionData{
		Type:      string(decision.Type),
		Source:    string(decision.Source),
		Scenario:  decision.Scenario,
		ExpiresAt: decision.ExpiresAt,
		Value:     decision.Value,
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.tree.Insert(cidr, decisionData)

	p.log.Debug(fmt.Sprintf("Range decision added: %s -> %s (expires: %s)",
		value, decision.Type, decision.ExpiresAt.Format(time.RFC3339)))

	return nil
}

// RemoveDecision removes a range decision
func (p *RangeDecisionProvider) RemoveDecision(scope DecisionScope, value string) error {
	if scope != ScopeRange {
		return fmt.Errorf("range provider only handles range scope, got %s", scope)
	}

	// Parse CIDR
	_, cidr, err := net.ParseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid CIDR range: %s, error: %v", value, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.tree.Remove(cidr) {
		p.log.Debug(fmt.Sprintf("Range decision removed: %s", value))
	}

	return nil
}

// CleanupExpired removes expired decisions from the radix tree
func (p *RangeDecisionProvider) CleanupExpired() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	removedCount := p.tree.CleanupExpired()
	if removedCount > 0 {
		p.log.Debug(fmt.Sprintf("Cleaned up %d expired range decisions", removedCount))
	}

	return nil
}
