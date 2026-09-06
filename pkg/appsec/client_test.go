package appsec

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func testAppsecConfig(host string, lapiSeconds, appsecMilliseconds int64) *configuration.Config {
	cfg := configuration.New()
	cfg.CrowdsecAppsecScheme = configuration.HTTP
	cfg.CrowdsecAppsecHost = host
	cfg.CrowdsecAppsecPath = "/"
	cfg.CrowdsecAppsecKey = "test-key"
	cfg.HTTPTimeoutSeconds = lapiSeconds
	cfg.CrowdsecAppsecTimeoutMilliseconds = appsecMilliseconds
	return cfg
}

func TestIdentityHex_EffectiveTimeout(t *testing.T) {
	inherit := testAppsecConfig("appsec.example:7422", 10, 0)
	explicit := testAppsecConfig("appsec.example:7422", 30, 10000)
	if IdentityHex(inherit) != IdentityHex(explicit) {
		t.Fatal("inherit 10s and explicit 10000ms must share AppSec identity")
	}
	short := testAppsecConfig("appsec.example:7422", 10, 200)
	if IdentityHex(inherit) == IdentityHex(short) {
		t.Fatal("different effective AppSec timeouts must be different identities")
	}
}

func TestNew_ShortTimeoutPassthroughOnHang(t *testing.T) {
	appsecServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		<-req.Context().Done()
	}))
	t.Cleanup(appsecServer.Close)
	appsecURL, err := url.Parse(appsecServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testAppsecConfig(appsecURL.Host, 10, 50)
	client, err := New(cfg, logger.New("ERROR", ""), "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	started := time.Now()
	decision, queryErr := client.Query("1.2.3.4", req, Policy{FailureAction: configuration.FailureActionPassthrough})
	elapsed := time.Since(started)
	if queryErr != nil {
		t.Fatalf("passthrough on timeout: %v", queryErr)
	}
	if decision == nil || decision.Action != ActionAllow {
		t.Fatalf("passthrough on timeout want allow, got %#v", decision)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("AppSec timeout waited %v, want well under LAPI 10s", elapsed)
	}
}
