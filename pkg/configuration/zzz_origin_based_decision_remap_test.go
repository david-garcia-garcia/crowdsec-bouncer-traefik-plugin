package configuration

import (
	"strings"
	"testing"

	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestValidateOriginBasedDecisionRemap(t *testing.T) {
	log := logger.New("ERROR", "")
	ok := getMinimalConfig()
	ok.BouncerOriginBasedDecisionRemap = map[string]map[string]string{
		"CAPI":                 {"ban": "captcha"},
		"lists:firehol_level1": {"ban": "pass"},
		"crowdsec":             {"captcha": "pass"},
	}
	if err := ValidateParams(ok, log); err != nil {
		t.Fatalf("valid remap must pass: %v", err)
	}

	tests := []struct {
		name  string
		remap map[string]map[string]string
		want  string
	}{
		{
			name: "empty origin",
			remap: func() map[string]map[string]string {
				remap := make(map[string]map[string]string)
				remap["  "] = map[string]string{"ban": "captcha"}
				return remap
			}(),
			want: "origin cannot be empty",
		},
		{
			name:  "empty edges",
			remap: map[string]map[string]string{"CAPI": {}},
			want:  "has no mappings",
		},
		{
			name:  "unknown from",
			remap: map[string]map[string]string{"CAPI": {"mfa": "captcha"}},
			want:  "must be ban or captcha",
		},
		{
			name:  "captcha to ban",
			remap: map[string]map[string]string{"CAPI": {"captcha": "ban"}},
			want:  "cannot map captcha to ban",
		},
		{
			name:  "identity ban",
			remap: map[string]map[string]string{"CAPI": {"ban": "ban"}},
			want:  "cannot map ban to ban",
		},
		{
			name:  "allow is not pass",
			remap: map[string]map[string]string{"CAPI": {"captcha": "allow"}},
			want:  "cannot map captcha to allow",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := getMinimalConfig()
			cfg.BouncerOriginBasedDecisionRemap = tc.remap
			err := ValidateParams(cfg, log)
			if err == nil {
				t.Fatal("want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q want containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateOriginBasedDecisionRemap_DoesNotRequireCaptchaProvider(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.BouncerCaptchaProvider = ""
	cfg.BouncerOriginBasedDecisionRemap = map[string]map[string]string{"CAPI": {"ban": "captcha"}}
	if err := ValidateParams(cfg, logger.New("ERROR", "")); err != nil {
		t.Fatalf("remap must not require captchaProvider: %v", err)
	}
}
