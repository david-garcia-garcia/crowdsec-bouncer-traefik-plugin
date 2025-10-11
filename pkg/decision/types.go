/*TODO: NEEDS HUMAN REVIEW*/
package decision

import (
	"net"
	"net/http"
	"time"
)

// DecisionSource represents where a decision originated from
type DecisionSource string

const (
	SourceBanlist     DecisionSource = "banlist"
	SourceHTTPProbing DecisionSource = "http_admin_probing"
	SourceCrowdSec    DecisionSource = "crowdsec"
	SourceAppSec      DecisionSource = "appsec"
	SourceManual      DecisionSource = "manual"
	SourceCommunity   DecisionSource = "community"
)

// DecisionType represents the type of remediation
type DecisionType string

const (
	TypeBan     DecisionType = "ban"
	TypeCaptcha DecisionType = "captcha"
	TypeAllow   DecisionType = "allow"
)

// DecisionScope represents the scope of a decision
type DecisionScope string

const (
	ScopeIP      DecisionScope = "Ip"
	ScopeRange   DecisionScope = "Range"
	ScopeCountry DecisionScope = "Country"
	ScopeAS      DecisionScope = "AS"
)

// DecisionInfo contains information about a decision
type DecisionInfo struct {
	Type      DecisionType   `json:"type"`
	Source    DecisionSource `json:"source"`
	Scenario  string         `json:"scenario"`
	ExpiresAt time.Time      `json:"expires_at"`
	Value     string         `json:"value"` // The actual IP, range, country, or AS
}

// DecisionRequest represents a request to check for decisions
type DecisionRequest struct {
	IP       net.IP
	IPString string        // String representation of IP to avoid repeated parsing
	Country  string        // From header
	ASN      string        // From header
	Mode     string        // Operating mode (none, live, stream, alone, appsec)
	HTTPReq  *http.Request // HTTP request for AppSec checking
}

// DecisionResult represents the result of a decision check
type DecisionResult struct {
	Blocked   bool
	Type      DecisionType  // The type of decision (ban, captcha, etc.)
	Scenario  string        // The scenario that triggered the decision
	Value     string        // The value that matched (IP, range, country, ASN)
	MatchedBy DecisionScope // Which scope matched (IP, Range, Country, AS)
}

// DecisionProvider is the common interface for all decision providers
type DecisionProvider interface {
	// Check if a request should be blocked
	Check(req *DecisionRequest) (*DecisionResult, error)

	// Add a decision
	AddDecision(scope DecisionScope, value string, decision *DecisionInfo) error

	// Remove a decision
	RemoveDecision(scope DecisionScope, value string) error

	// GetStats method removed - metrics handled centrally

	// Clear expired decisions
	CleanupExpired() error

	// Get provider name for logging/metrics
	Name() string
}

// CrowdSec types moved to pkg/types to avoid import cycles
