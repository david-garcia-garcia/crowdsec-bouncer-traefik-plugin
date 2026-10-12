package appsec

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

func gatedAppsecClient(t *testing.T, host string, period, threshold int64) *Client {
	t.Helper()
	cfg := testAppsecConfig(host)
	cfg.AppsecUnhealthyBackOffPeriodSecs = period
	cfg.AppsecUnhealthyFailureThreshold = threshold
	cfg.AppsecUnhealthyFailureRatio = configuration.DefaultUnhealthyFailureRatio
	client, err := New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestNew_defaultBackoffBuildsGate(t *testing.T) {
	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecHost = "127.0.0.1:1"
	cfg.AppsecScheme = "http"
	cfg.AppsecTLSInsecureVerify = true
	client, err := New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if cfg.AppsecUnhealthyBackOffPeriodSecs != configuration.DefaultAppsecUnhealthyBackOffPeriodSecs {
		t.Fatalf("period=%d want %d", cfg.AppsecUnhealthyBackOffPeriodSecs, configuration.DefaultAppsecUnhealthyBackOffPeriodSecs)
	}
	if client.GateForTest() == nil {
		t.Fatal("default AppSec backoff 30 must build a gate")
	}
}

func TestNew_zeroBackoffDisablesGate(t *testing.T) {
	client := gatedAppsecClient(t, "127.0.0.1:1", 0, 5)
	if client.GateForTest() != nil {
		t.Fatal("appsecUnhealthyBackOffPeriodSecs 0 must not build a gate")
	}
}

func TestQuery_gateSkipDoesNotCallAppSecOrFailureAction(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client := gatedAppsecClient(t, u.Host, 30, 1)

	_, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan})
	if err == nil {
		t.Fatal("admitted 500 must apply FailureAction")
	}
	if errors.Is(err, ErrGateSkip) {
		t.Fatal("first 500 is an admitted miss, not a gate skip")
	}

	_, skipErr := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan})
	if !errors.Is(skipErr, ErrGateSkip) {
		t.Fatalf("tripped gate want ErrGateSkip, got %v", skipErr)
	}
	if hits != 1 {
		t.Fatalf("AppSec hits=%d want 1", hits)
	}
}

func TestQuery_admittedMissStillUsesFailureAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client := gatedAppsecClient(t, u.Host, 30, 5)

	_, err := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionPassthrough})
	if err != nil {
		t.Fatalf("admitted 500 passthrough: %v", err)
	}
	_, banErr := client.Query(buildTestRequest(), Policy{FailureAction: configuration.FailureActionBan})
	if banErr == nil || errors.Is(banErr, ErrGateSkip) {
		t.Fatalf("admitted miss must use FailureAction, got %v", banErr)
	}
}
