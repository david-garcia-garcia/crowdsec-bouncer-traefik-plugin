package lapi

import (
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestPrepare_AloneModeRewritesCAPIEndpoint(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 1)
	cfg.LapiMode = configuration.AloneMode
	cfg.LapiScheme = configuration.HTTP
	cfg.LapiCapiMachineID = "machine"
	cfg.LapiCapiPassword = "secret"
	cfg.LapiUpdateIntervalSeconds = 60
	if err := Prepare(cfg, nil, "router"); err != nil {
		t.Fatal(err)
	}
	if cfg.LapiHost != crowdsecCapiHost {
		t.Fatalf("LapiHost = %q, want %q", cfg.LapiHost, crowdsecCapiHost)
	}
	if cfg.LapiScheme != configuration.HTTPS || cfg.LapiPath != "/" {
		t.Fatalf("scheme=%q path=%q, want https /", cfg.LapiScheme, cfg.LapiPath)
	}
	if cfg.LapiUpdateIntervalSeconds != 7200 {
		t.Fatalf("update interval = %d, want 7200", cfg.LapiUpdateIntervalSeconds)
	}
	if cfg.LapiCapiMachineID != "machine" || cfg.LapiCapiPassword != "secret" {
		t.Fatalf("CAPI credentials were not kept: id=%q", cfg.LapiCapiMachineID)
	}
}

func TestNew_MissingLapiKey(t *testing.T) {
	cfg := testStreamConfig("lapi.example:8080", 0)
	cfg.LapiKey = ""
	store := decisionstore.NewMemory(logger.New("ERROR", ""))
	_, err := New(cfg, logger.New("ERROR", ""), "test", store, "router", "bind")
	if err == nil || !strings.Contains(err.Error(), "LapiKey") {
		t.Fatalf("New err = %v, want missing LapiKey", err)
	}
}
