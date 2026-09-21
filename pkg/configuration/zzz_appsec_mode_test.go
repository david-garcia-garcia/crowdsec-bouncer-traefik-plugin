package configuration

import (
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestValidateParams_SubscribeWithoutLapiKey(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiKey = ""
	cfg.LapiInstance = "shared"
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err != nil {
		t.Fatalf("subscribe without a LAPI key must pass: %v", err)
	}
}

func TestValidateParams_OwnLapiMissingKeyFails(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiKey = ""
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err == nil {
		t.Fatal("own LAPI with empty instance and no secrets must fail")
	}
}

func TestValidateParams_DisabledLapiLeftoverKeyFails(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiEnabled = false
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err == nil {
		t.Fatal("lapiEnabled false with leftover lapiKey must fail")
	}
}

func TestValidateParams_AppsecOnlyWithoutLapiKey(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiEnabled = false
	cfg.LapiKey = ""
	cfg.AppsecEnabled = true
	cfg.AppsecKey = "appsec-test"
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err != nil {
		t.Fatalf("AppSec-only without LAPI key must pass: %v", err)
	}
}

func TestValidateParams_HoldAndBounceFails(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.BouncerEnabled = true
	cfg.BouncerHold = true
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err == nil {
		t.Fatal("bouncerHold with bouncerEnabled must fail")
	}
}
