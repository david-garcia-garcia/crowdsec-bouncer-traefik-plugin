package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// TestNew_failureAndBackOffActionDefaults pins the shipped failure and backoff action of every gated
// leg and the three gate cooldowns.
func TestNew_failureAndBackOffActionDefaults(t *testing.T) {
	cfg := New()
	actions := map[string][2]string{
		"BouncerLapiFailureAction":   {cfg.BouncerLapiFailureAction, FailureActionBan},
		"BouncerLapiBackOffAction":   {cfg.BouncerLapiBackOffAction, FailureActionBan},
		"BouncerAppsecFailureAction": {cfg.BouncerAppsecFailureAction, FailureActionPassthrough},
		"BouncerAppsecBackOffAction": {cfg.BouncerAppsecBackOffAction, FailureActionPassthrough},
		"BouncerModsecFailureAction": {cfg.BouncerModsecFailureAction, FailureActionPassthrough},
		"BouncerModsecBackOffAction": {cfg.BouncerModsecBackOffAction, FailureActionPassthrough},
	}
	for name, gotWant := range actions {
		if gotWant[0] != gotWant[1] {
			t.Errorf("%s=%q want %q", name, gotWant[0], gotWant[1])
		}
	}
	periods := map[string]int64{
		"LapiUnhealthyBackOffPeriodSecs":   cfg.LapiUnhealthyBackOffPeriodSecs,
		"AppsecUnhealthyBackOffPeriodSecs": cfg.AppsecUnhealthyBackOffPeriodSecs,
		"ModsecUnhealthyBackOffPeriodSecs": cfg.ModsecUnhealthyBackOffPeriodSecs,
	}
	for name, period := range periods {
		if period != 10 {
			t.Errorf("%s=%d want 10", name, period)
		}
	}
}

// TestEffectiveActions_emptyIsPerLegDefault pins what an empty failure or backoff action means per leg.
func TestEffectiveActions_emptyIsPerLegDefault(t *testing.T) {
	resolvers := []struct {
		name    string
		resolve func(string) string
		empty   string
	}{
		{name: "EffectiveLapiFailureAction", resolve: EffectiveLapiFailureAction, empty: FailureActionBan},
		{name: "EffectiveLapiBackOffAction", resolve: EffectiveLapiBackOffAction, empty: FailureActionBan},
		{name: "EffectiveAppsecFailureAction", resolve: EffectiveAppsecFailureAction, empty: FailureActionPassthrough},
		{name: "EffectiveAppsecBackOffAction", resolve: EffectiveAppsecBackOffAction, empty: FailureActionPassthrough},
		{name: "EffectiveModsecFailureAction", resolve: EffectiveModsecFailureAction, empty: FailureActionPassthrough},
		{name: "EffectiveModsecBackOffAction", resolve: EffectiveModsecBackOffAction, empty: FailureActionPassthrough},
	}
	for _, resolver := range resolvers {
		if got := resolver.resolve(""); got != resolver.empty {
			t.Errorf("%s(\"\")=%q want %q", resolver.name, got, resolver.empty)
		}
		if got := resolver.resolve(FailureActionCaptcha); got != FailureActionCaptcha {
			t.Errorf("%s(captcha)=%q want captcha", resolver.name, got)
		}
	}
}

// TestValidateParams_backOffActionsAndLapiPeriod validates the three backoff keys like the failure
// actions (value set, captcha needs a captcha instance) and the LAPI cooldown like the WAF cooldowns.
func TestValidateParams_backOffActionsAndLapiPeriod(t *testing.T) {
	captchaTemplate := writeCaptchaTemplateFixture(t)
	withCaptchaOwner := func(cfg *Config) {
		cfg.CaptchaEnabled = true
		cfg.CaptchaProvider = HcaptchaProvider
		cfg.CaptchaSiteKey = "site"
		cfg.CaptchaSecretKey = "secret"
		cfg.CaptchaGateSecret = "gate-secret"
		cfg.CaptchaFilePath = captchaTemplate
	}
	setters := map[string]func(*Config, string){
		"BouncerLapiBackOffAction":   func(cfg *Config, action string) { cfg.BouncerLapiBackOffAction = action },
		"BouncerAppsecBackOffAction": func(cfg *Config, action string) { cfg.BouncerAppsecBackOffAction = action },
		"BouncerModsecBackOffAction": func(cfg *Config, action string) { cfg.BouncerModsecBackOffAction = action },
	}
	log := logger.New("ERROR", "")
	for field, set := range setters {
		t.Run(field+" unknown value fails", func(t *testing.T) {
			cfg := getMinimalConfig()
			set(cfg, "block")
			err := ValidateParams(cfg, log)
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("err=%v want one naming %s", err, field)
			}
		})
		t.Run(field+" captcha without a captcha instance fails", func(t *testing.T) {
			cfg := getMinimalConfig()
			set(cfg, FailureActionCaptcha)
			err := ValidateParams(cfg, log)
			if err == nil || !strings.Contains(err.Error(), field+": captcha requires a captcha instance name") {
				t.Fatalf("err=%v want the captcha-instance error for %s", err, field)
			}
		})
		t.Run(field+" captcha on a captcha owner passes", func(t *testing.T) {
			cfg := getMinimalConfig()
			withCaptchaOwner(cfg)
			set(cfg, FailureActionCaptcha)
			if err := ValidateParams(cfg, log); err != nil {
				t.Fatalf("err=%v want nil", err)
			}
		})
		t.Run(field+" empty passes", func(t *testing.T) {
			cfg := getMinimalConfig()
			set(cfg, "")
			if err := ValidateParams(cfg, log); err != nil {
				t.Fatalf("err=%v want nil", err)
			}
		})
	}
	t.Run("negative LAPI period fails", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.LapiUnhealthyBackOffPeriodSecs = -1
		err := ValidateParams(cfg, log)
		if err == nil || !strings.Contains(err.Error(), "LapiUnhealthyBackOffPeriodSecs: cannot be less than 0") {
			t.Fatalf("err=%v want LapiUnhealthyBackOffPeriodSecs below 0", err)
		}
	})
	t.Run("zero LAPI period passes", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.LapiUnhealthyBackOffPeriodSecs = 0
		if err := ValidateParams(cfg, log); err != nil {
			t.Fatalf("err=%v want nil", err)
		}
	})
	t.Run("stream with a LAPI period passes", func(t *testing.T) {
		cfg := getMinimalConfig()
		cfg.LapiMode = StreamMode
		cfg.LapiUnhealthyBackOffPeriodSecs = 30
		if err := ValidateParams(cfg, log); err != nil {
			t.Fatalf("err=%v want nil", err)
		}
	})
}
