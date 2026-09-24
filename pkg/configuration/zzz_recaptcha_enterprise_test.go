package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

// newEnterpriseCaptchaConfig is a valid recaptcha-enterprise owner used by ValidateParams cases.
func newEnterpriseCaptchaConfig(t *testing.T, keyType string) *Config {
	t.Helper()
	cfg := getMinimalConfig()
	cfg.CaptchaEnabled = true
	cfg.CaptchaProvider = RecaptchaEnterpriseProvider
	cfg.CaptchaSiteKey = "site"
	cfg.CaptchaGateSecret = "gate-secret"
	cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
	cfg.CaptchaEnterpriseKeyType = keyType
	cfg.CaptchaEnterpriseProjectID = "my-project"
	cfg.CaptchaEnterpriseAPIKey = "cloud-api-key"
	if keyType == CaptchaEnterpriseKeyTypeScore {
		cfg.CaptchaEnterpriseAction = "login"
		cfg.CaptchaEnterpriseMinScore = "0.5"
	}
	return cfg
}

func TestValidateParams_RecaptchaEnterprise(t *testing.T) {
	log := logger.New("INFO", "")
	tests := []struct {
		name            string
		config          *Config
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "Allowlist accepts recaptcha-enterprise checkbox",
			config:  newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox),
			wantErr: false,
		},
		{
			name:    "Allowlist accepts recaptcha-enterprise score",
			config:  newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore),
			wantErr: false,
		},
		{
			name: "Unknown provider still fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaProvider = "not-a-provider"
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaProvider",
		},
		{
			name: "Missing project id fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaEnterpriseProjectID = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseProjectID",
		},
		{
			name: "Missing API key fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaEnterpriseAPIKey = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseAPIKey",
		},
		{
			name: "Invalid key type fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, "policy")
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseKeyType",
		},
		{
			name: "Score missing action fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseAction = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseAction",
		},
		{
			name: "Score missing min score fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseMinScore",
		},
		{
			name: "Score zero min score fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = "0"
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseMinScore",
		},
		{
			name: "Score negative min score fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = "-0.1"
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseMinScore",
		},
		{
			name: "Score 1.1 min score fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = "1.1"
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseMinScore",
		},
		{
			name: "Score non-numeric min score fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = "high"
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaEnterpriseMinScore",
		},
		{
			name: "Score 1.0 min score passes",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = "1.0"
				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "Score 1 min score passes",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeScore)
				cfg.CaptchaEnterpriseMinScore = "1"
				return cfg
			}(),
			wantErr: false,
		},
		{
			name:    "Checkbox empty action and min score pass",
			config:  newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox),
			wantErr: false,
		},
		{
			name: "Enterprise empty secret passes",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaSecretKey = ""
				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "Leftover enterprise knobs on classic recaptcha are ignored",
			config: func() *Config {
				cfg := getMinimalConfig()
				cfg.CaptchaEnabled = true
				cfg.CaptchaProvider = RecaptchaProvider
				cfg.CaptchaSiteKey = "site"
				cfg.CaptchaSecretKey = "secret"
				cfg.CaptchaGateSecret = "gate-secret"
				cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "Hcaptcha empty secret still fails",
			config: func() *Config {
				cfg := getMinimalConfig()
				cfg.CaptchaEnabled = true
				cfg.CaptchaProvider = HcaptchaProvider
				cfg.CaptchaSiteKey = "site"
				cfg.CaptchaSecretKey = ""
				cfg.CaptchaGateSecret = "gate-secret"
				cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaSecretKey: cannot be empty when CaptchaProvider is set",
		},
		{
			name: "Classic recaptcha empty secret still fails",
			config: func() *Config {
				cfg := getMinimalConfig()
				cfg.CaptchaEnabled = true
				cfg.CaptchaProvider = RecaptchaProvider
				cfg.CaptchaSiteKey = "site"
				cfg.CaptchaSecretKey = ""
				cfg.CaptchaGateSecret = "gate-secret"
				cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaSecretKey: cannot be empty when CaptchaProvider is set",
		},
		{
			name: "Turnstile empty secret still fails",
			config: func() *Config {
				cfg := getMinimalConfig()
				cfg.CaptchaEnabled = true
				cfg.CaptchaProvider = TurnstileProvider
				cfg.CaptchaSiteKey = "site"
				cfg.CaptchaSecretKey = ""
				cfg.CaptchaGateSecret = "gate-secret"
				cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaSecretKey: cannot be empty when CaptchaProvider is set",
		},
		{
			name: "Custom empty secret still fails",
			config: func() *Config {
				cfg := getMinimalConfig()
				cfg.CaptchaEnabled = true
				cfg.CaptchaProvider = CustomProvider
				cfg.CaptchaCustomKey = "wicketkeeper"
				cfg.CaptchaCustomResponse = "wicketkeeper_solution"
				cfg.CaptchaCustomValidateURL = "http://wicketkeeper:8080/v0/siteverify"
				cfg.CaptchaCustomJsURL = "http://wicketkeeper:8080/fast.js"
				cfg.CaptchaSiteKey = "site"
				cfg.CaptchaSecretKey = ""
				cfg.CaptchaGateSecret = "gate-secret"
				cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaSecretKey: cannot be empty when CaptchaProvider is set",
		},
		{
			name: "Enterprise empty site still fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaSiteKey = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaSiteKey: cannot be empty when CaptchaProvider is set",
		},
		{
			name: "Enterprise empty gate still fails",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaGateSecret = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaGateSecret",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.config, log)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContains)) {
				t.Fatalf("ValidateParams() error = %v, want contains %q", err, tt.wantErrContains)
			}
		})
	}
}
