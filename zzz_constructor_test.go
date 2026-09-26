package crowdsec_bouncer_traefik_plugin //nolint:revive,stylecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// writeTestFile writes one fixture file under t.TempDir and returns its path.
func writeTestFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// cfgAppsecCaptchaAt is appsec mode with a custom captcha provider and captcha as the
// AppSec failure action: the combination that must serve a challenge, not a ban.
func cfgAppsecCaptchaAt(t *testing.T, appsecHost string) *configuration.Config {
	t.Helper()
	c := getTestConfig()
	c.LapiEnabled = false
	c.LapiKey = ""
	c.AppsecEnabled = true
	c.AppsecKey = "appsec-key"
	c.AppsecScheme = "http"
	c.AppsecHost = appsecHost
	c.AppsecPath = "/"
	c.BouncerAppsecFailureAction = configuration.FailureActionCaptcha
	c.CaptchaEnabled = true
	c.CaptchaProvider = configuration.CustomProvider
	c.CaptchaCustomJsURL = "/captcha.js"
	c.CaptchaCustomKey = "dummy-captcha"
	c.CaptchaCustomResponse = "dummy-captcha-response"
	c.CaptchaCustomValidateURL = "http://127.0.0.1/siteverify"
	c.CaptchaSiteKey = "site"
	c.CaptchaSecretKey = "secret"
	c.CaptchaGateSecret = "gate-secret"
	c.CaptchaFilePath = writeTestFile(t, "captcha.html", "CAPTCHA_CHALLENGE_PAGE")
	c.BouncerRemediationHeadersCustomName = "X-Remediation"
	c.BouncerForwardedHeadersTrustedIPs = []string{"127.0.0.1/32"}
	c.BouncerForwardedHeadersCustomName = "X-Forwarded-For"
	return c
}

// TestNew_FailedConstructorReleasesLapiHolder checks that a constructor which fails after an
// earlier Open succeeded releases that holder. The stream client opens, then appsec.Open fails
// on an unusable client certificate. Without a rollback the stream ticker polls LAPI forever.
func TestNew_FailedConstructorReleasesLapiHolder(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() {
		reclaim.ResetForTest()
	})

	var hits int64
	srv := liveLAPI(t, nil, &hits)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	cfg := cfgStreamAt(u.Host, 1)
	cfg.AppsecEnabled = true
	cfg.AppsecScheme = "https"
	cfg.AppsecHost = u.Host
	cfg.AppsecPath = "/"
	cfg.AppsecTLSInsecureVerify = true
	cfg.AppsecTLSClientCertificate = "not a certificate"
	cfg.AppsecTLSClientKey = "not a key"

	if _, err := New(context.Background(), testNextOK(), cfg, "rollback"); err == nil {
		t.Fatal("New must fail when the AppSec client certificate cannot be loaded")
	}
	time.Sleep(200 * time.Millisecond)
	atStart := atomic.LoadInt64(&hits)
	time.Sleep(2500 * time.Millisecond)
	if grew := atomic.LoadInt64(&hits) - atStart; grew != 0 {
		t.Fatalf("failed New left a stream ticker running: %d further LAPI polls", grew)
	}
}

// TestNew_SuccessfulConstructorKeepsItsHolder guards the other side of the rollback: a New that
// succeeded must keep holding, and Traefik's own context must still be what releases it. With
// zero grace, a rollback that fired on the success path would dispose between these two calls.
func TestNew_SuccessfulConstructorKeepsItsHolder(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() {
		reclaim.ResetForTest()
	})

	var hits int64
	srv := liveLAPI(t, nil, &hits)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	first, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "holder")
	if err != nil {
		t.Fatal(err)
	}
	held := testRoute(t, first).LapiClient()

	second, err := New(ctx, testNextOK(), cfgLiveAt(u.Host), "holder")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, second).LapiClient() != held {
		t.Fatal("a successful New must keep holding its incarnation")
	}

	cancel()
	time.Sleep(150 * time.Millisecond)
	third, err := New(context.Background(), testNextOK(), cfgLiveAt(u.Host), "holder")
	if err != nil {
		t.Fatal(err)
	}
	if testRoute(t, third).LapiClient() == held {
		t.Fatal("canceling the constructor context must release the holder")
	}
}

// TestNew_AppsecModeWithoutAppsecWarns checks the operator gets a warning, in the log they
// configured, when appsec mode is combined with AppSec disabled — a middleware that enforces
// nothing. It must still start.
func TestNew_AppsecOwnedWithoutKeyFails(t *testing.T) {
	cfg := getTestConfig()
	cfg.LapiEnabled = false
	cfg.LapiKey = ""
	cfg.AppsecEnabled = true
	cfg.LogFormat = "common"
	if _, err := New(context.Background(), testNextOK(), cfg, "appsec-no-waf"); err == nil {
		t.Fatal("AppSec owned without a key must fail Open")
	}
}

func TestNew_AppsecCaptchaFailureActionServesChallenge(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() {
		reclaim.ResetForTest()
	})

	appsecSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(func() { appsecSrv.Close() })
	au, _ := url.Parse(appsecSrv.URL)

	h, err := New(context.Background(), testNextOK(), cfgAppsecCaptchaAt(t, au.Host), "appsec-captcha")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, reqForIP("203.0.113.7"))

	if got := rw.Header().Get("X-Remediation"); got != "captcha:appsec-failure" {
		t.Fatalf("remediation %q want captcha:appsec-failure, body: %s", got, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("captcha challenge not served, body: %s", rw.Body.String())
	}
}

// TestNew_DoesNotMutateCallerConfig checks New works on a snapshot: Traefik's own struct must not
// come back normalised, and must not come back carrying the resolved LAPI secret.
func TestNew_DoesNotMutateCallerConfig(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() {
		reclaim.ResetForTest()
	})

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	cfg := cfgLiveAt(u.Host)
	cfg.LogLevel = "info"
	cfg.LapiKey = ""
	cfg.LapiKeyFile = writeTestFile(t, "lapi.key", "resolved-lapi-key")

	if _, err := New(context.Background(), testNextOK(), cfg, "snapshot"); err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("New normalised the caller's logLevel to %q", cfg.LogLevel)
	}
	if cfg.LapiKey != "" {
		t.Fatalf("New wrote the resolved LAPI secret into the caller's config: %q", cfg.LapiKey)
	}
}

func cfgCaptchaOwnerAt(t *testing.T, instanceName string) *configuration.Config {
	t.Helper()
	c := getTestConfig()
	c.LapiEnabled = false
	c.LapiKey = ""
	c.BouncerEnabled = true
	c.CaptchaEnabled = true
	c.CaptchaInstanceName = instanceName
	c.CaptchaProvider = configuration.CustomProvider
	c.CaptchaCustomJsURL = "/captcha.js"
	c.CaptchaCustomKey = "dummy-captcha"
	c.CaptchaCustomResponse = "dummy-captcha-response"
	c.CaptchaCustomValidateURL = "http://127.0.0.1/siteverify"
	c.CaptchaSiteKey = "site"
	c.CaptchaSecretKey = "secret"
	c.CaptchaGateSecret = "gate-secret"
	c.CaptchaFilePath = writeTestFile(t, "captcha.html", "CAPTCHA_CHALLENGE_PAGE")
	c.BouncerDecisionHeader = "X-Crowdsec-Decision"
	c.BouncerRemediationHeadersCustomName = "X-Remediation"
	c.BouncerForwardedHeadersTrustedIPs = []string{"127.0.0.1/32"}
	c.BouncerForwardedHeadersCustomName = "X-Forwarded-For"
	return c
}

func captchaForceReq() *http.Request {
	req := reqForIP("203.0.113.8")
	req.Header.Set("X-Crowdsec-Decision", "c")
	return req
}

func TestNew_CaptchaOwnerServesChallenge(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	h, err := New(context.Background(), testNextOK(), cfgCaptchaOwnerAt(t, "shared"), "cs-owner")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, captchaForceReq())
	if got := rw.Header().Get("X-Remediation"); got != "captcha:decision-header" {
		t.Fatalf("remediation %q want captcha:decision-header, body: %s", got, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("owner must serve captcha, body: %s", rw.Body.String())
	}
}

func TestNew_CaptchaOwnerOmitFillsTraefikName(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ownerCfg := cfgCaptchaOwnerAt(t, "")
	if _, err := New(context.Background(), testNextOK(), ownerCfg, "cs-owner"); err != nil {
		t.Fatal(err)
	}
	sub := cfgCaptchaOwnerAt(t, "cs-owner")
	sub.CaptchaEnabled = false
	h, err := New(context.Background(), testNextOK(), sub, "cs-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, captchaForceReq())
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("subscriber of filled Traefik name must serve captcha, body: %s", rw.Body.String())
	}
}

func TestNew_CaptchaSubscriberBeforePublishBans(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	sub := cfgCaptchaOwnerAt(t, "shared")
	sub.CaptchaEnabled = false
	sub.BouncerStartupBlock = false
	h, err := New(context.Background(), testNextOK(), sub, "cs-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, captchaForceReq())
	if rw.Code != http.StatusForbidden {
		t.Fatalf("unpublished captcha verdict must ban, status=%d body=%s", rw.Code, rw.Body.String())
	}
	if strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatal("unpublished captcha must not serve the challenge")
	}
}

func TestNew_CaptchaSubscriberBeforePublishBlocks(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	sub := cfgCaptchaOwnerAt(t, "shared")
	sub.CaptchaEnabled = false
	sub.BouncerStartupBlock = true
	h, err := New(context.Background(), testNextOK(), sub, "cs-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, captchaForceReq())
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("unpublished subscribed captcha with startup block must 503, status=%d body=%s", rw.Code, rw.Body.String())
	}
}

func TestNew_CaptchaSubscriberUsesRouterHeader(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	ownerCfg := cfgCaptchaOwnerAt(t, "shared")
	ownerCfg.BouncerRemediationHeadersCustomName = "X-Owner"
	if _, err := New(context.Background(), testNextOK(), ownerCfg, "cs-owner"); err != nil {
		t.Fatal(err)
	}
	sub := cfgCaptchaOwnerAt(t, "shared")
	sub.CaptchaEnabled = false
	sub.BouncerRemediationHeadersCustomName = "X-Route"
	h, err := New(context.Background(), testNextOK(), sub, "cs-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, captchaForceReq())
	if got := rw.Header().Get("X-Route"); got != "captcha:decision-header" {
		t.Fatalf("subscriber remediation %q want captcha:decision-header on X-Route, body: %s", got, rw.Body.String())
	}
	if got := rw.Header().Get("X-Owner"); got != "" {
		t.Fatalf("subscriber must not write owner's X-Owner, got %q", got)
	}
}

func TestNew_CaptchaHolderWithBounceOffStillPublishes(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	holder := cfgCaptchaOwnerAt(t, "shared")
	holder.BouncerEnabled = false
	if _, err := New(context.Background(), testNextOK(), holder, "cs-holder"); err != nil {
		t.Fatal(err)
	}
	sub := cfgCaptchaOwnerAt(t, "shared")
	sub.CaptchaEnabled = false
	h, err := New(context.Background(), testNextOK(), sub, "cs-bounce")
	if err != nil {
		t.Fatal(err)
	}
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, captchaForceReq())
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("holder with bounce off must still publish, body: %s", rw.Body.String())
	}
}

func TestNew_CaptchaInstanceNameCollisionFails(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	if _, err := New(context.Background(), testNextOK(), cfgCaptchaOwnerAt(t, "shared"), "cs-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(context.Background(), testNextOK(), cfgCaptchaOwnerAt(t, "shared"), "cs-b"); err == nil {
		t.Fatal("second captcha publisher on the same name must fail")
	}
}
