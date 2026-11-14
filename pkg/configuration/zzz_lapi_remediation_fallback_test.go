package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestNew_LapiRemediationFallbackDefaultsToBan proves the plugin default is ban.
func TestNew_LapiRemediationFallbackDefaultsToBan(t *testing.T) {
	if got := New().LapiRemediationFallback; got != LapiRemediationFallbackBan {
		t.Fatalf("New LapiRemediationFallback = %q, want %q", got, LapiRemediationFallbackBan)
	}
}

// TestEffectiveLapiRemediationFallback proves empty maps to ban and set values pass through.
func TestEffectiveLapiRemediationFallback(t *testing.T) {
	for _, tc := range []struct {
		configured string
		want       string
	}{
		{"", LapiRemediationFallbackBan},
		{LapiRemediationFallbackBan, LapiRemediationFallbackBan},
		{LapiRemediationFallbackCaptcha, LapiRemediationFallbackCaptcha},
		{LapiRemediationFallbackIgnore, LapiRemediationFallbackIgnore},
	} {
		if got := EffectiveLapiRemediationFallback(tc.configured); got != tc.want {
			t.Fatalf("EffectiveLapiRemediationFallback(%q) = %q, want %q", tc.configured, got, tc.want)
		}
	}
}

// TestValidateParams_LapiRemediationFallback proves the enum accepts ban, captcha, ignore, and empty only.
func TestValidateParams_LapiRemediationFallback(t *testing.T) {
	log := logger.New("ERROR", "")
	for _, tc := range []struct {
		name       string
		configured string
		omit       bool
		wantErr    bool
	}{
		{name: "omitted", omit: true},
		{name: "empty", configured: ""},
		{name: "ban", configured: LapiRemediationFallbackBan},
		{name: "captcha without captcha instance", configured: LapiRemediationFallbackCaptcha},
		{name: "ignore", configured: LapiRemediationFallbackIgnore},
		{name: "allow is rejected", configured: "allow", wantErr: true},
		{name: "passthrough is rejected", configured: FailureActionPassthrough, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := getMinimalConfig()
			cfg.CaptchaEnabled = false
			cfg.CaptchaInstanceName = ""
			if !tc.omit {
				cfg.LapiRemediationFallback = tc.configured
			}
			err := ValidateParams(cfg, log)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("ValidateParams: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "LapiRemediationFallback") {
				t.Fatalf("ValidateParams error = %v, want one naming LapiRemediationFallback", err)
			}
		})
	}
}
