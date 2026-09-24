package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestNew_TimeoutDefaultsAreTen(t *testing.T) {
	cfg := New()
	if cfg.LapiHTTPTimeoutSeconds != 10 || cfg.AppsecHTTPTimeoutSeconds != 10 || cfg.CaptchaSiteverifyHTTPTimeoutSeconds != 10 {
		t.Fatalf("New must default each timeout knob to 10, got lapi=%d appsec=%d captcha=%d",
			cfg.LapiHTTPTimeoutSeconds, cfg.AppsecHTTPTimeoutSeconds, cfg.CaptchaSiteverifyHTTPTimeoutSeconds)
	}
}

func TestValidateParams_HTTPTimeoutKnobs(t *testing.T) {
	log := logger.New("INFO", "")
	ok := getMinimalConfig()
	if err := ValidateParams(ok, log); err != nil {
		t.Fatalf("defaults: %v", err)
	}

	zero := getMinimalConfig()
	zero.LapiHTTPTimeoutSeconds = 0
	err := ValidateParams(zero, log)
	if err == nil || !strings.Contains(err.Error(), "LapiHTTPTimeoutSeconds") || !strings.Contains(err.Error(), "cannot be less than 1") {
		t.Fatalf("zero knob: %v", err)
	}

	negative := getMinimalConfig()
	negative.AppsecHTTPTimeoutSeconds = -1
	err = ValidateParams(negative, log)
	if err == nil || !strings.Contains(err.Error(), "AppsecHTTPTimeoutSeconds") || !strings.Contains(err.Error(), "cannot be less than 1") {
		t.Fatalf("negative knob: %v", err)
	}
}
