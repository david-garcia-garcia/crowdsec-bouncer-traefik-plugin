package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestNew_AppsecBodyDefaults proves CreateConfig defaults: a 10 MiB body cap and a 30 s body read deadline.
func TestNew_AppsecBodyDefaults(t *testing.T) {
	cfg := New()
	if cfg.AppsecBodyLimit != 10485760 {
		t.Fatalf("appsecBodyLimit default = %d, want 10485760", cfg.AppsecBodyLimit)
	}
	if cfg.AppsecBodyReadTimeoutSeconds != 30 {
		t.Fatalf("appsecBodyReadTimeoutSeconds default = %d, want 30", cfg.AppsecBodyReadTimeoutSeconds)
	}
}

// TestEffectiveAppsecBodyLimit proves a non-positive appsecBodyLimit maps to 10 MiB and a positive one is kept.
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

// TestValidateParams_AppsecBodyKnobs proves the validation of appsecBodyReadTimeoutSeconds (at least 1)
// and that appsecBodyLimit 0 / -1 no longer fail (they mean the default cap).
func TestValidateParams_AppsecBodyKnobs(t *testing.T) {
	log := logger.New("INFO", "")
	// Defaults pass.
	if err := ValidateParams(getMinimalConfig(), log); err != nil {
		t.Fatalf("defaults: %v", err)
	}

	// A zero body read timeout fails like the other *TimeoutSeconds keys.
	zeroTimeout := getMinimalConfig()
	zeroTimeout.AppsecBodyReadTimeoutSeconds = 0
	err := ValidateParams(zeroTimeout, log)
	if err == nil || !strings.Contains(err.Error(), "AppsecBodyReadTimeoutSeconds: cannot be less than 1") {
		t.Fatalf("zero body read timeout: %v", err)
	}

	// A negative body limit is accepted: it means the default cap.
	negativeLimit := getMinimalConfig()
	negativeLimit.AppsecBodyLimit = -1
	if err := ValidateParams(negativeLimit, log); err != nil {
		t.Fatalf("negative appsecBodyLimit must be accepted (it means the default cap): %v", err)
	}

	// A zero body limit is accepted: it means the default cap, not unlimited.
	zeroLimit := getMinimalConfig()
	zeroLimit.AppsecBodyLimit = 0
	if err := ValidateParams(zeroLimit, log); err != nil {
		t.Fatalf("zero appsecBodyLimit must be accepted (it means the default cap): %v", err)
	}
}
