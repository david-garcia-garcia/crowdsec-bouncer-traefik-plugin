package configuration

import (
	"testing"
	"time"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestNew_BackendBackoffDefaults(t *testing.T) {
	cfg := New()
	if cfg.BackendBackoffFailureRatio != 0.30 {
		t.Fatalf("FailureRatio %v, want 0.30", cfg.BackendBackoffFailureRatio)
	}
	if cfg.BackendBackoffTripFailures != 5 {
		t.Fatalf("TripFailures %d, want 5", cfg.BackendBackoffTripFailures)
	}
	if cfg.BackendBackoffBaseCooldownSeconds != 1 {
		t.Fatalf("BaseCooldown %d, want 1", cfg.BackendBackoffBaseCooldownSeconds)
	}
	if cfg.BackendBackoffMaxCooldownSeconds != 10 {
		t.Fatalf("MaxCooldown %d, want 10", cfg.BackendBackoffMaxCooldownSeconds)
	}
	if cfg.BackendBackoffJitter != 0.10 {
		t.Fatalf("Jitter %v, want 0.10", cfg.BackendBackoffJitter)
	}
	if cfg.BackendBackoffTTLSeconds != 60 {
		t.Fatalf("TTL %d, want 60", cfg.BackendBackoffTTLSeconds)
	}
	mapped := cfg.BackendBackoffConfig()
	if mapped.BaseCooldown != time.Second || mapped.MaxCooldown != 10*time.Second || mapped.TTL != 60*time.Second {
		t.Fatalf("mapped durations %+v", mapped)
	}
}

func TestValidateParams_BackendBackoffRejects(t *testing.T) {
	log := logger.New("INFO", "")
	ratio := getMinimalConfig()
	ratio.BackendBackoffFailureRatio = 1.5
	if err := ValidateParams(ratio, log); err == nil {
		t.Fatal("FailureRatio 1.5 must fail ValidateParams")
	}

	cooldown := getMinimalConfig()
	cooldown.BackendBackoffBaseCooldownSeconds = 10
	cooldown.BackendBackoffMaxCooldownSeconds = 1
	if err := ValidateParams(cooldown, log); err == nil {
		t.Fatal("MaxCooldown below BaseCooldown must fail ValidateParams")
	}

	jitter := getMinimalConfig()
	jitter.BackendBackoffJitter = 0
	if err := ValidateParams(jitter, log); err != nil {
		t.Fatalf("Jitter 0 must be accepted: %v", err)
	}
}
