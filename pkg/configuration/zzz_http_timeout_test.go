package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestEffectiveHTTPTimeoutSeconds_InheritAndOverride(t *testing.T) {
	cfg := New()
	if cfg.CrowdsecLapiHTTPTimeoutSeconds != 0 || cfg.CrowdsecAppsecHTTPTimeoutSeconds != 0 || cfg.CaptchaSiteverifyHTTPTimeoutSeconds != 0 {
		t.Fatalf("New must leave inherit knobs at 0, got lapi=%d appsec=%d captcha=%d",
			cfg.CrowdsecLapiHTTPTimeoutSeconds, cfg.CrowdsecAppsecHTTPTimeoutSeconds, cfg.CaptchaSiteverifyHTTPTimeoutSeconds)
	}
	if got := cfg.EffectiveHTTPTimeoutSeconds(0); got != 10 {
		t.Fatalf("omit/0 inherit: got %d want 10", got)
	}
	cfg.CrowdsecAppsecHTTPTimeoutSeconds = 1
	if got := cfg.EffectiveHTTPTimeoutSeconds(cfg.CrowdsecAppsecHTTPTimeoutSeconds); got != 1 {
		t.Fatalf("positive override: got %d want 1", got)
	}
}

func TestValidateParams_HTTPTimeoutInheritKnobs(t *testing.T) {
	log := logger.New("INFO", "")
	ok := getMinimalConfig()
	if err := ValidateParams(ok, log); err != nil {
		t.Fatalf("zeros inherit: %v", err)
	}

	negative := getMinimalConfig()
	negative.CrowdsecLapiHTTPTimeoutSeconds = -1
	err := ValidateParams(negative, log)
	if err == nil || !strings.Contains(err.Error(), "CrowdsecLapiHTTPTimeoutSeconds") || !strings.Contains(err.Error(), "cannot be less than 0") {
		t.Fatalf("negative knob: %v", err)
	}

	sharedZero := getMinimalConfig()
	sharedZero.HTTPTimeoutSeconds = 0
	err = ValidateParams(sharedZero, log)
	if err == nil || !strings.Contains(err.Error(), "HTTPTimeoutSeconds") || !strings.Contains(err.Error(), "cannot be less than 1") {
		t.Fatalf("shared timeout 0: %v", err)
	}
}
