package bouncer

import (
	"net/http"
	"testing"

	configuration "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestNew_BounceOnlyDoesNotConstructCaptcha(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	cfg := configuration.New()
	cfg.CaptchaProvider = configuration.HcaptchaProvider
	cfg.CaptchaSiteKey = "site"
	cfg.CaptchaSecretKey = "secret"
	cfg.CaptchaGateSecret = "gate-secret"
	route, err := New(next, "test", cfg, false, false, false, logger.New("ERROR", ""))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if route.loadedCaptcha() != nil {
		t.Fatal("bounce-only New must not construct a captcha client")
	}
}
