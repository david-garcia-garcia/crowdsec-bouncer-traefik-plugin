package appsec

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func TestQuery_NilTransportUsesFailureAction(t *testing.T) {
	client := &Client{
		appsecScheme: "http",
		appsecHost:   "appsec.example:7422",
		appsecPath:   "/",
		log:          logger.New("ERROR", ""),
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	decision, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("passthrough nil transport: %v", err)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough nil transport decision = %+v, want allow", decision)
	}

	if _, err := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionBan}); err == nil {
		t.Fatal("ban nil transport must return an error")
	}
	_, err = client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionCaptcha})
	if !errors.Is(err, ErrFailureCaptcha) {
		t.Fatalf("captcha nil transport err = %v", err)
	}
}

func TestAdoptTransport_TimeoutChangeIsReportedOnce(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := testAppsecConfig("appsec.example:7422")
	cfg.AppsecHTTPTimeoutSeconds = 10
	client, err := New(cfg, log, "test", "router", "bind")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	cfg.AppsecHTTPTimeoutSeconds = 3
	replaced, err := client.AdoptTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("timeout change must report the transport replaced")
	}
	replaced, err = client.AdoptTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if replaced {
		t.Fatal("same timeout must not report another replacement")
	}
}
