package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestNew_AppsecBodyDefaults(t *testing.T) {
	cfg := New()
	if cfg.AppsecBodyLimit != 10485760 {
		t.Fatalf("appsecBodyLimit default = %d, want 10485760", cfg.AppsecBodyLimit)
	}
	if cfg.AppsecBodyReadTimeoutSeconds != 30 {
		t.Fatalf("appsecBodyReadTimeoutSeconds default = %d, want 30", cfg.AppsecBodyReadTimeoutSeconds)
	}
}

func TestEffectiveAppsecBodyLimit(t *testing.T) {
	cases := []struct {
		limit int64
		want  int64
	}{
		{limit: 0, want: 10485760},
		{limit: -1, want: 10485760},
		{limit: 1, want: 1},
		{limit: 10485760, want: 10485760},
	}
	for _, bodyLimitCase := range cases {
		if got := EffectiveAppsecBodyLimit(bodyLimitCase.limit); got != bodyLimitCase.want {
			t.Errorf("EffectiveAppsecBodyLimit(%d) = %d, want %d", bodyLimitCase.limit, got, bodyLimitCase.want)
		}
	}
}

func TestValidateParams_AppsecBodyKnobs(t *testing.T) {
	log := logger.New("INFO", "")
	if err := ValidateParams(getMinimalConfig(), log); err != nil {
		t.Fatalf("defaults: %v", err)
	}

	zeroTimeout := getMinimalConfig()
	zeroTimeout.AppsecBodyReadTimeoutSeconds = 0
	err := ValidateParams(zeroTimeout, log)
	if err == nil || !strings.Contains(err.Error(), "AppsecBodyReadTimeoutSeconds: cannot be less than 1") {
		t.Fatalf("zero body read timeout: %v", err)
	}

	negativeLimit := getMinimalConfig()
	negativeLimit.AppsecBodyLimit = -1
	if err := ValidateParams(negativeLimit, log); err != nil {
		t.Fatalf("negative appsecBodyLimit must be accepted (it means the default cap): %v", err)
	}

	zeroLimit := getMinimalConfig()
	zeroLimit.AppsecBodyLimit = 0
	if err := ValidateParams(zeroLimit, log); err != nil {
		t.Fatalf("zero appsecBodyLimit must be accepted (it means the default cap): %v", err)
	}
}
