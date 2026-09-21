package configuration

import (
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestCrowdsecDecisionHeaderDefaultsEmpty(t *testing.T) {
	cfg := New()
	if cfg.CrowdsecDecisionHeader != "" {
		t.Fatalf("default CrowdsecDecisionHeader=%q, want empty", cfg.CrowdsecDecisionHeader)
	}
	cfg = getMinimalConfig()
	cfg.CrowdsecDecisionHeader = "   "
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err != nil {
		t.Fatalf("whitespace CrowdsecDecisionHeader must not fail ValidateParams: %v", err)
	}
}
