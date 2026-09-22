package configuration

import (
	"strings"
	"testing"
)

func TestValidateParams_AppsecModeRejected(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.CrowdsecMode = "appsec"
	err := ValidateParams(cfg, nil)
	if err == nil {
		t.Fatal("crowdsecMode appsec must be rejected")
	}
	if !strings.Contains(err.Error(), "CrowdsecMode") {
		t.Fatalf("error must name CrowdsecMode, got %v", err)
	}
}

func TestValidateParams_AppsecOnlyUsesLapiEnabledFalse(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.CrowdsecLapiEnabled = false
	cfg.CrowdsecLapiKey = ""
	cfg.CrowdsecAppsecEnabled = true
	cfg.CrowdsecAppsecKey = "appsec-key"
	cfg.CrowdsecAppsecHost = "crowdsec:7422"
	if err := ValidateParams(cfg, nil); err != nil {
		t.Fatalf("LAPI-off AppSec-only must validate: %v", err)
	}
}
