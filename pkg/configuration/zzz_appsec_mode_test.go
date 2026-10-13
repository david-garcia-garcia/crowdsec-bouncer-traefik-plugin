package configuration

import (
	"strings"
	"testing"
)

func TestValidateParams_AppsecModeRejected(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiMode = "appsec"
	err := ValidateParams(cfg, nil)
	if err == nil {
		t.Fatal("crowdsecMode appsec must be rejected")
	}
	if !strings.Contains(err.Error(), "LapiMode") {
		t.Fatalf("error must name LapiMode, got %v", err)
	}
}

func TestValidateParams_AppsecOnlyUsesLapiEnabledFalse(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.LapiEnabled = false
	cfg.LapiKey = ""
	cfg.AppsecEnabled = true
	cfg.AppsecKey = "appsec-key"
	cfg.AppsecHost = "crowdsec:7422"
	if err := ValidateParams(cfg, nil); err != nil {
		t.Fatalf("LAPI-off AppSec-only must validate: %v", err)
	}
}
