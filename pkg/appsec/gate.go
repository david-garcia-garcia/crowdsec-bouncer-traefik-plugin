package appsec

import (
	"fmt"
	"time"

	"github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff"
)

const gateKey = "appsec"

// newAdmissionGate builds a utilities Gate when backoff seconds are greater than zero.
// Jitter and TTL stay unset so a partial Config disables jitter.
func newAdmissionGate(period, maxPeriod, threshold int64, ratio float64) (*backendbackoff.Gate, error) {
	if period <= 0 {
		return nil, nil //nolint:nilnil // omitted backoff means no gate
	}
	base := time.Duration(period) * time.Second
	maxCooldown := base
	if maxPeriod > 0 {
		maxCooldown = time.Duration(maxPeriod) * time.Second
	}
	gateCfg := backendbackoff.Config{
		TripFailures: int(threshold),
		BaseCooldown: base,
		MaxCooldown:  maxCooldown,
	}
	if ratio > 0 {
		gateCfg.FailureRatio = ratio
	}
	gate, err := backendbackoff.New(gateCfg)
	if err != nil {
		return nil, fmt.Errorf("appsec admission gate: %w", err)
	}
	return gate, nil
}
