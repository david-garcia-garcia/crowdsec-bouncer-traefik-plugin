package bouncer

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testCaptchaBouncerConfig(t *testing.T, captchaTimeout int64) *configuration.Config {
	t.Helper()
	templatePath := filepath.Join(t.TempDir(), "captcha.html")
	if err := os.WriteFile(templatePath, []byte("captcha"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := configuration.New()
	cfg.CrowdsecMode = configuration.LiveMode
	cfg.HTTPTimeoutSeconds = 10
	cfg.CaptchaSiteverifyHTTPTimeoutSeconds = captchaTimeout
	cfg.CaptchaProvider = configuration.HcaptchaProvider
	cfg.CaptchaSiteKey = "site"
	cfg.CaptchaSecretKey = "secret"
	cfg.CaptchaGateSecret = "gate-secret"
	cfg.CaptchaFilePath = templatePath
	return cfg
}

func captchaSiteverifyTimeout(t *testing.T, cfg *configuration.Config) time.Duration {
	t.Helper()
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	route, err := New(next, "test", cfg, false, false, logger.New("ERROR", ""))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	httpClient := route.captchaClient.HTTPClientForTest()
	if httpClient == nil {
		t.Fatal("captcha siteverify client was not stored")
	}
	return httpClient.Timeout
}

func TestNew_CaptchaSiteverifyTimeoutHonorsOverride(t *testing.T) {
	got := captchaSiteverifyTimeout(t, testCaptchaBouncerConfig(t, 1))
	if got != time.Second {
		t.Fatalf("captcha Timeout = %v want 1s", got)
	}
}

func TestNew_CaptchaSiteverifyTimeoutInheritsShared(t *testing.T) {
	got := captchaSiteverifyTimeout(t, testCaptchaBouncerConfig(t, 0))
	if got != 10*time.Second {
		t.Fatalf("captcha Timeout = %v want 10s", got)
	}
}
