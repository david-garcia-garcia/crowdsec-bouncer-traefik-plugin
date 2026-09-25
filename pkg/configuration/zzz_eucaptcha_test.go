package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func newEucaptchaConfig(t *testing.T) *Config {
	t.Helper()
	cfg := getMinimalConfig()
	cfg.CaptchaEnabled = true
	cfg.CaptchaProvider = EucaptchaProvider
	cfg.CaptchaSiteKey = "site"
	cfg.CaptchaSecretKey = "secret"
	cfg.CaptchaGateSecret = "gate-secret"
	cfg.CaptchaFilePath = writeCaptchaTemplateFixture(t)
	return cfg
}

func TestValidateParams_Eucaptcha(t *testing.T) {
	log := logger.New("INFO", "")
	tests := []struct {
		name            string
		config          *Config
		wantErr         bool
		wantErrContains string
	}{
		{
			name:    "Allowlist accepts eucaptcha",
			config:  newEucaptchaConfig(t),
			wantErr: false,
		},
		{
			name:    "Allowlist still accepts recaptcha-enterprise",
			config:  newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox),
			wantErr: false,
		},
		{
			name: "Unknown provider still fails",
			config: func() *Config {
				cfg := newEucaptchaConfig(t)
				cfg.CaptchaProvider = "not-a-provider"
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaProvider",
		},
		{
			name: "Empty secret fails for eucaptcha",
			config: func() *Config {
				cfg := newEucaptchaConfig(t)
				cfg.CaptchaSecretKey = ""
				return cfg
			}(),
			wantErr:         true,
			wantErrContains: "CaptchaSecretKey: cannot be empty when CaptchaProvider is set",
		},
		{
			name: "Empty secret still passes only for recaptcha-enterprise",
			config: func() *Config {
				cfg := newEnterpriseCaptchaConfig(t, CaptchaEnterpriseKeyTypeCheckbox)
				cfg.CaptchaSecretKey = ""
				return cfg
			}(),
			wantErr: false,
		},
		{
			name: "Leftover enterprise knobs on eucaptcha are ignored",
			config: func() *Config {
				cfg := newEucaptchaConfig(t)
				cfg.CaptchaEnterpriseKeyType = ""
				cfg.CaptchaEnterpriseProjectID = ""
				cfg.CaptchaEnterpriseAPIKey = ""
				return cfg
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams(tt.config, log)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErrContains != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContains)) {
				t.Fatalf("error %v, want contain %q", err, tt.wantErrContains)
			}
		})
	}
}
