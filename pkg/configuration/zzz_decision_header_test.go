package configuration

import (
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestBouncerActionRulesDefaultEmpty(t *testing.T) {
	cfg := New()
	if len(cfg.BouncerActionRules) != 0 {
		t.Fatalf("default BouncerActionRules=%v, want empty", cfg.BouncerActionRules)
	}
	cfg = getMinimalConfig()
	cfg.BouncerActionRules = nil
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err != nil {
		t.Fatalf("omitted BouncerActionRules must not fail ValidateParams: %v", err)
	}
}
