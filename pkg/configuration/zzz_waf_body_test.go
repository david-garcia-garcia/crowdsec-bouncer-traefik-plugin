package configuration

import (
	"encoding/json"
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestNew_WafBodyDefaults pins CreateConfig defaults: a 10 MiB AppSec body cap and a 30 s body read
// deadline on each WAF leg.
func TestNew_WafBodyDefaults(t *testing.T) {
	cfg := New()
	if cfg.AppsecBodyLimit != 10485760 {
		t.Fatalf("appsecBodyLimit default = %d, want 10485760", cfg.AppsecBodyLimit)
	}
	if cfg.AppsecBodyReadTimeoutSeconds != 30 {
		t.Fatalf("appsecBodyReadTimeoutSeconds default = %d, want 30", cfg.AppsecBodyReadTimeoutSeconds)
	}
	if cfg.ModsecBodyReadTimeoutSeconds != 30 {
		t.Fatalf("modsecBodyReadTimeoutSeconds default = %d, want 30", cfg.ModsecBodyReadTimeoutSeconds)
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

// TestValidateParams_WafBodyReadTimeouts proves each leg's body read timeout is at least 1.
func TestValidateParams_WafBodyReadTimeouts(t *testing.T) {
	log := logger.New("INFO", "")
	if err := ValidateParams(getMinimalConfig(), log); err != nil {
		t.Fatalf("defaults: %v", err)
	}

	appsecZero := getMinimalConfig()
	appsecZero.AppsecBodyReadTimeoutSeconds = 0
	err := ValidateParams(appsecZero, log)
	if err == nil || !strings.Contains(err.Error(), "AppsecBodyReadTimeoutSeconds: cannot be less than 1") {
		t.Fatalf("appsecBodyReadTimeoutSeconds 0: %v", err)
	}

	modsecZero := getMinimalConfig()
	modsecZero.ModsecBodyReadTimeoutSeconds = 0
	err = ValidateParams(modsecZero, log)
	if err == nil || !strings.Contains(err.Error(), "ModsecBodyReadTimeoutSeconds: cannot be less than 1") {
		t.Fatalf("modsecBodyReadTimeoutSeconds 0: %v", err)
	}
}

// TestValidateParams_AppsecBodyLimitNotRangeChecked proves 0 and -1 are accepted: both mean the default cap.
func TestValidateParams_AppsecBodyLimitNotRangeChecked(t *testing.T) {
	log := logger.New("INFO", "")
	for _, limit := range []int64{0, -1} {
		cfg := getMinimalConfig()
		cfg.AppsecBodyLimit = limit
		if err := ValidateParams(cfg, log); err != nil {
			t.Fatalf("appsecBodyLimit %d must be accepted (it means the default cap): %v", limit, err)
		}
	}
}

// TestWafBodyReadTimeouts_oneKeyDoesNotMoveTheOther decodes one key the way Traefik does and checks
// the other leg keeps its default.
func TestWafBodyReadTimeouts_oneKeyDoesNotMoveTheOther(t *testing.T) {
	cfg := New()
	if err := json.Unmarshal([]byte(`{"appsecBodyReadTimeoutSeconds":5}`), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.AppsecBodyReadTimeoutSeconds != 5 || cfg.ModsecBodyReadTimeoutSeconds != 30 {
		t.Fatalf("appsec=%d modsec=%d, want 5 and 30", cfg.AppsecBodyReadTimeoutSeconds, cfg.ModsecBodyReadTimeoutSeconds)
	}
}
