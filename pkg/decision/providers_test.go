/*TODO: NEEDS HUMAN REVIEW*/
package decision

import (
	"net"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestIPDecisionProvider(t *testing.T) {
	log := logger.New("INFO", "")
	provider := NewIPDecisionProvider(log)

	// Test adding a decision
	decision := &DecisionInfo{
		Type:      TypeBan,
		Source:    SourceCrowdSec,
		Scenario:  "test-scenario",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "192.168.1.100",
	}

	err := provider.AddDecision(ScopeIP, "192.168.1.100", decision)
	if err != nil {
		t.Fatalf("Failed to add IP decision: %v", err)
	}

	// Test checking the decision
	req := &DecisionRequest{
		IP: net.ParseIP("192.168.1.100"),
	}

	result, err := provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check IP decision: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected IP to be blocked")
	}

	if result.Decision.Type != TypeBan {
		t.Errorf("Expected ban decision, got %s", result.Decision.Type)
	}

	if result.MatchedBy != ScopeIP {
		t.Errorf("Expected IP scope, got %s", result.MatchedBy)
	}

	// Test removing the decision
	err = provider.RemoveDecision(ScopeIP, "192.168.1.100")
	if err != nil {
		t.Fatalf("Failed to remove IP decision: %v", err)
	}

	// Verify it's no longer blocked
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check IP decision after removal: %v", err)
	}

	if result.Blocked {
		t.Error("Expected IP to not be blocked after removal")
	}
}

func TestRangeDecisionProvider(t *testing.T) {
	log := logger.New("INFO", "")
	provider := NewRangeDecisionProvider(log)

	// Test adding a range decision
	decision := &DecisionInfo{
		Type:      TypeBan,
		Source:    SourceCrowdSec,
		Scenario:  "test-range-scenario",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "192.168.1.0/24",
	}

	err := provider.AddDecision(ScopeRange, "192.168.1.0/24", decision)
	if err != nil {
		t.Fatalf("Failed to add range decision: %v", err)
	}

	// Test checking an IP within the range
	req := &DecisionRequest{
		IP: net.ParseIP("192.168.1.50"),
	}

	result, err := provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check range decision: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected IP in range to be blocked")
	}

	if result.MatchedBy != ScopeRange {
		t.Errorf("Expected range scope, got %s", result.MatchedBy)
	}

	// Test an IP outside the range
	req.IP = net.ParseIP("192.168.2.50")
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check IP outside range: %v", err)
	}

	if result.Blocked {
		t.Error("Expected IP outside range to not be blocked")
	}

	// Test removing the range decision
	err = provider.RemoveDecision(ScopeRange, "192.168.1.0/24")
	if err != nil {
		t.Fatalf("Failed to remove range decision: %v", err)
	}

	// Verify IP in range is no longer blocked
	req.IP = net.ParseIP("192.168.1.50")
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check range after removal: %v", err)
	}

	if result.Blocked {
		t.Error("Expected IP in range to not be blocked after removal")
	}
}

func TestCountryDecisionProvider(t *testing.T) {
	log := logger.New("INFO", "")
	provider := NewCountryDecisionProvider(log, true) // enabled

	// Test adding a country decision
	decision := &DecisionInfo{
		Type:      TypeBan,
		Source:    SourceCrowdSec,
		Scenario:  "test-country-scenario",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "CN",
	}

	err := provider.AddDecision(ScopeCountry, "CN", decision)
	if err != nil {
		t.Fatalf("Failed to add country decision: %v", err)
	}

	// Test checking a request with the blocked country
	req := &DecisionRequest{
		IP:      net.ParseIP("1.2.3.4"),
		Country: "CN",
	}

	result, err := provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check country decision: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected country to be blocked")
	}

	if result.MatchedBy != ScopeCountry {
		t.Errorf("Expected country scope, got %s", result.MatchedBy)
	}

	// Test a different country
	req.Country = "US"
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check different country: %v", err)
	}

	if result.Blocked {
		t.Error("Expected different country to not be blocked")
	}

	// Test case insensitive matching
	req.Country = "cn"
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check lowercase country: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected lowercase country to be blocked (case insensitive)")
	}
}

func TestASNDecisionProvider(t *testing.T) {
	log := logger.New("INFO", "")
	provider := NewASNDecisionProvider(log, true) // enabled

	// Test adding an ASN decision
	decision := &DecisionInfo{
		Type:      TypeBan,
		Source:    SourceCrowdSec,
		Scenario:  "test-asn-scenario",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "AS1234",
	}

	err := provider.AddDecision(ScopeAS, "AS1234", decision)
	if err != nil {
		t.Fatalf("Failed to add ASN decision: %v", err)
	}

	// Test checking a request with the blocked ASN
	req := &DecisionRequest{
		IP:  net.ParseIP("1.2.3.4"),
		ASN: "AS1234",
	}

	result, err := provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check ASN decision: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected ASN to be blocked")
	}

	if result.MatchedBy != ScopeAS {
		t.Errorf("Expected ASN scope, got %s", result.MatchedBy)
	}

	// Test ASN without AS prefix
	req.ASN = "1234"
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check ASN without prefix: %v", err)
	}

	if !result.Blocked {
		t.Error("Expected ASN without prefix to be blocked (normalized)")
	}

	// Test different ASN
	req.ASN = "AS5678"
	result, err = provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check different ASN: %v", err)
	}

	if result.Blocked {
		t.Error("Expected different ASN to not be blocked")
	}
}

func TestDecisionExpiration(t *testing.T) {
	log := logger.New("INFO", "")
	provider := NewIPDecisionProvider(log)

	// Add a decision that expires in 1 millisecond
	decision := &DecisionInfo{
		Type:      TypeBan,
		Source:    SourceCrowdSec,
		Scenario:  "test-expiration",
		ExpiresAt: time.Now().Add(1 * time.Millisecond),
		Value:     "192.168.1.200",
	}

	err := provider.AddDecision(ScopeIP, "192.168.1.200", decision)
	if err != nil {
		t.Fatalf("Failed to add expiring decision: %v", err)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Check that the decision is no longer active
	req := &DecisionRequest{
		IP: net.ParseIP("192.168.1.200"),
	}

	result, err := provider.Check(req)
	if err != nil {
		t.Fatalf("Failed to check expired decision: %v", err)
	}

	if result.Blocked {
		t.Error("Expected expired decision to not block")
	}
}

func TestProviderStats(t *testing.T) {
	log := logger.New("INFO", "")
	provider := NewIPDecisionProvider(log)

	// Check initial stats
	stats := provider.GetStats()
	if stats["total_decisions"] != 0 {
		t.Errorf("Expected 0 total decisions, got %d", stats["total_decisions"])
	}

	// Add some decisions
	banDecision := &DecisionInfo{
		Type:      TypeBan,
		Source:    SourceCrowdSec,
		Scenario:  "test-ban",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "192.168.1.100",
	}

	captchaDecision := &DecisionInfo{
		Type:      TypeCaptcha,
		Source:    SourceCrowdSec,
		Scenario:  "test-captcha",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Value:     "192.168.1.101",
	}

	provider.AddDecision(ScopeIP, "192.168.1.100", banDecision)
	provider.AddDecision(ScopeIP, "192.168.1.101", captchaDecision)

	// Check updated stats
	stats = provider.GetStats()
	if stats["total_decisions"] != 2 {
		t.Errorf("Expected 2 total decisions, got %d", stats["total_decisions"])
	}
	if stats["active_bans"] != 1 {
		t.Errorf("Expected 1 active ban, got %d", stats["active_bans"])
	}
	if stats["active_captchas"] != 1 {
		t.Errorf("Expected 1 active captcha, got %d", stats["active_captchas"])
	}

	// Perform some checks to update check stats
	req := &DecisionRequest{IP: net.ParseIP("192.168.1.100")}
	provider.Check(req)
	req.IP = net.ParseIP("192.168.1.200") // Non-blocked IP
	provider.Check(req)

	stats = provider.GetStats()
	if stats["checks_total"] != 2 {
		t.Errorf("Expected 2 total checks, got %d", stats["checks_total"])
	}
	if stats["checks_blocked"] != 1 {
		t.Errorf("Expected 1 blocked check, got %d", stats["checks_blocked"])
	}
}
