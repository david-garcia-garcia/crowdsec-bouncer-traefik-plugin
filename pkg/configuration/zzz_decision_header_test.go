package configuration

import (
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestCrowdsecDecisionHeaderDefaultsEmpty(t *testing.T) {
	cfg := New()
	if cfg.BouncerDecisionHeader != "" {
		t.Fatalf("default BouncerDecisionHeader=%q, want empty", cfg.BouncerDecisionHeader)
	}
	cfg = getMinimalConfig()
	cfg.BouncerDecisionHeader = "   "
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err != nil {
		t.Fatalf("whitespace BouncerDecisionHeader must not fail ValidateParams: %v", err)
	}
}
