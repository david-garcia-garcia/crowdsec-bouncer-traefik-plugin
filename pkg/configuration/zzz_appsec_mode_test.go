package configuration

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// warnedBy runs ValidateParams against a buffered WARN logger and returns what it wrote.
func warnedBy(t *testing.T, cfg *Config) string {
	t.Helper()
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err := ValidateParams(cfg, log); err != nil {
		t.Fatalf("ValidateParams must accept this config: %v", err)
	}
	return logged.String()
}

// TestValidateParams_AppsecModeWithoutAppsecWarns pins the owner's decision: appsec mode with
// AppSec disabled enforces nothing, and that is warned about rather than rejected.
func TestValidateParams_AppsecModeWithoutAppsecWarns(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.CrowdsecMode = AppsecMode
	cfg.CrowdsecAppsecEnabled = false

	warned := warnedBy(t, cfg)
	if warned == "" {
		t.Fatal("appsec mode with AppSec disabled must warn")
	}
	for _, want := range []string{"crowdsecMode", "crowdsecAppsecEnabled"} {
		if !strings.Contains(warned, want) {
			t.Fatalf("warning must name %s, got %q", want, warned)
		}
	}
}

// TestValidateParams_AppsecModeWithAppsecIsSilent checks the warning is specific to the
// do-nothing combination and does not fire on the mode's intended use.
func TestValidateParams_AppsecModeWithAppsecIsSilent(t *testing.T) {
	cfg := getMinimalConfig()
	cfg.CrowdsecMode = AppsecMode
	cfg.CrowdsecAppsecEnabled = true

	if warned := warnedBy(t, cfg); warned != "" {
		t.Fatalf("appsec mode with AppSec enabled must not warn, got %q", warned)
	}
}
