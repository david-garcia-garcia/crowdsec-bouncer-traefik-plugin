package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

func modsecSidecar(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "../etc") {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Closure: Yaegi v0.16 types httptest.Server.Close as a method value with a receiver.
	t.Cleanup(func() { srv.Close() })
	return srv
}

func cfgModsecOwnerAt(sidecarURL, instanceName string) *configuration.Config {
	c := getTestConfig()
	c.LapiEnabled = false
	c.LapiKey = ""
	c.BouncerEnabled = true
	c.ModsecEnabled = true
	c.ModsecURL = sidecarURL
	c.ModsecInstanceName = instanceName
	c.BouncerRemediationHeadersCustomName = "X-Remediation"
	c.BouncerForwardedHeadersTrustedIPs = []string{"127.0.0.1/32"}
	c.BouncerForwardedHeadersCustomName = "X-Forwarded-For"
	return c
}

func TestNew_ModsecOwnerBlocksCRSPath(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sidecar := modsecSidecar(t)

	h, err := New(context.Background(), testNextOK(), cfgModsecOwnerAt(sidecar.URL, "waf"), "modsec-owner")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, reqForIP("203.0.113.40"))
	if rw.Code != http.StatusOK {
		t.Fatalf("allow status=%d", rw.Code)
	}
	block := httptest.NewRecorder()
	req := reqForIP("203.0.113.40")
	req.URL.RawQuery = "test=../etc"
	h.ServeHTTP(block, req)
	if block.Code != http.StatusForbidden {
		t.Fatalf("block status=%d want 403", block.Code)
	}
	if block.Header().Get("X-Remediation") != "ban:modsec" {
		t.Fatalf("header=%q", block.Header().Get("X-Remediation"))
	}
}

func TestNew_ModsecSubscriberUsesOwnerClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sidecar := modsecSidecar(t)

	if _, err := New(context.Background(), testNextOK(), cfgModsecOwnerAt(sidecar.URL, "shared"), "modsec-owner"); err != nil {
		t.Fatal(err)
	}
	sub := cfgModsecOwnerAt(sidecar.URL, "shared")
	sub.ModsecEnabled = false
	h, err := New(context.Background(), testNextOK(), sub, "modsec-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req := reqForIP("203.0.113.40")
	req.URL.RawQuery = "test=../etc"
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("subscriber status=%d want 403", rw.Code)
	}
}

func TestNew_ModsecHolderWithBounceOffStillPublishes(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sidecar := modsecSidecar(t)

	holder := cfgModsecOwnerAt(sidecar.URL, "shared")
	holder.BouncerEnabled = false
	if _, err := New(context.Background(), testNextOK(), holder, "modsec-holder"); err != nil {
		t.Fatal(err)
	}
	sub := cfgModsecOwnerAt(sidecar.URL, "shared")
	sub.ModsecEnabled = false
	h, err := New(context.Background(), testNextOK(), sub, "modsec-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	req := reqForIP("203.0.113.40")
	req.URL.RawQuery = "test=../etc"
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("holder publish status=%d want 403", rw.Code)
	}
}

func TestNew_ModsecInstanceNameCollisionFails(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sidecar := modsecSidecar(t)

	if _, err := New(context.Background(), testNextOK(), cfgModsecOwnerAt(sidecar.URL, "shared"), "modsec-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), testNextOK(), cfgModsecOwnerAt(sidecar.URL, "shared"), "modsec-b"); err == nil {
		t.Fatal("second ModSec publisher on the same name must fail")
	}
}

func TestNew_CaptchaClaimFailureClearsModsecPublisher(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sidecar := modsecSidecar(t)

	if _, err := New(context.Background(), testNextOK(), cfgCaptchaOwnerAt(t, "shared"), "cs-a"); err != nil {
		t.Fatal(err)
	}
	mixed := cfgModsecOwnerAt(sidecar.URL, "waf")
	captcha := cfgCaptchaOwnerAt(t, "shared")
	mixed.CaptchaEnabled = true
	mixed.CaptchaInstanceName = "shared"
	mixed.CaptchaProvider = captcha.CaptchaProvider
	mixed.CaptchaCustomJsURL = captcha.CaptchaCustomJsURL
	mixed.CaptchaCustomKey = captcha.CaptchaCustomKey
	mixed.CaptchaCustomResponse = captcha.CaptchaCustomResponse
	mixed.CaptchaCustomValidateURL = captcha.CaptchaCustomValidateURL
	mixed.CaptchaSiteKey = captcha.CaptchaSiteKey
	mixed.CaptchaSecretKey = captcha.CaptchaSecretKey
	mixed.CaptchaGateSecret = captcha.CaptchaGateSecret
	mixed.CaptchaFilePath = captcha.CaptchaFilePath
	if _, err := New(context.Background(), testNextOK(), mixed, "cs-b"); err == nil {
		t.Fatal("captcha name collision must fail New")
	}
	if _, err := New(context.Background(), testNextOK(), cfgModsecOwnerAt(sidecar.URL, "waf"), "modsec-retry"); err != nil {
		t.Fatalf("captcha-claim rollback must ClearPublisher modsec: %v", err)
	}
}
