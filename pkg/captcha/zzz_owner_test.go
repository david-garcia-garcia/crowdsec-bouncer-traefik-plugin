package captcha

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func testOwnerConfig(t *testing.T, timeout int64) *configuration.Config {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("captcha"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration.New()
	cfg.CaptchaEnabled = true
	cfg.CaptchaProvider = configuration.HcaptchaProvider
	cfg.CaptchaSiteKey = "site"
	cfg.CaptchaSecretKey = "secret"
	cfg.CaptchaGateSecret = "gate-secret"
	cfg.CaptchaFilePath = templatePath
	cfg.CaptchaSiteverifyHTTPTimeoutSeconds = timeout
	return cfg
}

func TestPrepare_OwnerOmitFillsTraefikName(t *testing.T) {
	cfg := configuration.New()
	cfg.CaptchaEnabled = true
	if err := Prepare(cfg, nil, "cs-owner"); err != nil {
		t.Fatal(err)
	}
	if cfg.CaptchaInstanceName != "cs-owner" {
		t.Fatalf("CaptchaInstanceName = %q want cs-owner", cfg.CaptchaInstanceName)
	}
}

func TestPrepare_SubscriberOmitStaysEmpty(t *testing.T) {
	cfg := configuration.New()
	cfg.CaptchaEnabled = false
	cfg.BouncerEnabled = true
	if err := Prepare(cfg, nil, "cs-bounce"); err != nil {
		t.Fatal(err)
	}
	if cfg.CaptchaInstanceName != "" {
		t.Fatalf("subscriber omit must stay empty, got %q", cfg.CaptchaInstanceName)
	}
}

func TestOpen_SiteverifyTimeoutHonorsOverride(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	cfg := testOwnerConfig(t, 1)
	client, err := Open(context.Background(), cfg, logger.New("ERROR", ""), "cs-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	httpClient := client.HTTPClientForTest()
	if httpClient == nil {
		t.Fatal("siteverify client was not stored")
	}
	if httpClient.Timeout != time.Second {
		t.Fatalf("Timeout = %v want 1s", httpClient.Timeout)
	}
}

func TestOpen_SiteverifyTimeoutUsesOwnKnob(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	cfg := testOwnerConfig(t, 10)
	client, err := Open(context.Background(), cfg, logger.New("ERROR", ""), "cs-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := client.HTTPClientForTest().Timeout; got != 10*time.Second {
		t.Fatalf("Timeout = %v want 10s", got)
	}
}

func TestOwnershipKey_ExcludesSlotAndBounce(t *testing.T) {
	left := testOwnerConfig(t, 10)
	right := *left
	left.CaptchaInstanceName = "shared"
	left.BouncerEnabled = true
	left.BouncerLapiFailureAction = configuration.FailureActionCaptcha
	left.BouncerRemediationHeadersCustomName = "X-Owner"
	left.BouncerStartupBlock = true
	right.CaptchaInstanceName = "other"
	right.BouncerEnabled = false
	right.BouncerLapiFailureAction = configuration.FailureActionBan
	right.BouncerRemediationHeadersCustomName = "X-Route"
	right.BouncerStartupBlock = false
	if OwnershipKey(left, "mw") != OwnershipKey(&right, "mw") {
		t.Fatal("slot name, bounce, failure, header, and startup-block must stay off the ownership key")
	}
}
