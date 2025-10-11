/*TODO: NEEDS HUMAN REVIEW*/
package types

import (
	"time"
)

// CrowdSecDecision represents a decision from CrowdSec API
type CrowdSecDecision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

// Stream represents the stream response from CrowdSec
type Stream struct {
	Deleted []CrowdSecDecision `json:"deleted"`
	New     []CrowdSecDecision `json:"new"`
}

// DecisionData represents decision information with expiration (used in radix tree)
type DecisionData struct {
	Type      string    `json:"type"`
	Source    string    `json:"source"`
	Scenario  string    `json:"scenario"`
	ExpiresAt time.Time `json:"expires_at"`
	Value     string    `json:"value"`
}

// IsExpired checks if the decision data has expired
func (d *DecisionData) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}
