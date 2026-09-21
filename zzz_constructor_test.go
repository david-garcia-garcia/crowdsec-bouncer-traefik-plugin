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
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/instance"
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
	c.AppsecScheme = "http"
	c.AppsecHost = appsecHost
	c.AppsecPath = "/"
	c.AppsecKey = "appsec-test"
	c.BouncerAppsecFailureAction = configuration.FailureActionCaptcha
	c.BouncerCaptchaProvider = configuration.CustomProvider
	c.BouncerCaptchaCustomJsURL = "/captcha.js"
	c.BouncerCaptchaCustomKey = "dummy-captcha"
	c.BouncerCaptchaCustomResponse = "dummy-captcha-response"
	c.BouncerCaptchaCustomValidateURL = "http://127.0.0.1/siteverify"
	c.BouncerCaptchaSiteKey = "site"
	c.BouncerCaptchaSecretKey = "secret"
	c.BouncerCaptchaGateSecret = "gate-secret"
	c.BouncerCaptchaFile = writeTestFile(t, "captcha.html", "CAPTCHA_CHALLENGE_PAGE")
	c.BouncerRemediationHeader = "X-Remediation"
	c.BouncerForwardedTrustedIPs = []string{"127.0.0.1/32"}
	c.BouncerForwardedHeader = "X-Forwarded-For"
	return c
}

// TestNew_FailedConstructorReleasesLapiHolder checks that a constructor which fails after an
// earlier Open succeeded releases that holder. The stream client opens, then appsec.Open fails
// on an unusable client certificate. Without a rollback the stream ticker polls LAPI forever.
func TestNew_FailedConstructorReleasesLapiHolder(t *testing.T) {
	reclaim.ResetForTestWith(0)
	instance.ResetForTest()
	t.Cleanup(func() { reclaim.ResetForTest(); instance.ResetForTest() })

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
	cfg.AppsecTLSCert = "not a certificate"
	cfg.AppsecTLSKey = "not a key"

	if _, err := New(context.Background(), testNextOK(), cfg, "rollback"); err == nil {
		t.Fatal("New must fail when the AppSec client certificate cannot be loaded")
	}
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
	instance.ResetForTest()
	t.Cleanup(func() { reclaim.ResetForTest(); instance.ResetForTest() })

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

// TestNew_LapiDisabledStartsWithoutKey checks a middleware with lapiEnabled false
// and no AppSec starts without a LAPI key.
func TestNew_LapiDisabledStartsWithoutKey(t *testing.T) {
	reclaim.ResetForTestWith(0)
	instance.ResetForTest()
	t.Cleanup(func() { reclaim.ResetForTest(); instance.ResetForTest() })

	cfg := getTestConfig()
	cfg.LapiEnabled = false
	cfg.LapiKey = ""
	cfg.AppsecEnabled = false

	if _, err := New(context.Background(), testNextOK(), cfg, "no-lapi"); err != nil {
		t.Fatalf("lapiEnabled false with no AppSec must still start: %v", err)
	}
}

// TestNew_AppsecModeCaptchaFailureActionServesChallenge checks that an AppSec failure in appsec
// mode with bouncerAppsecFailureAction: captcha serves the challenge. Without the captcha client
// the bouncer falls back to a ban, which contradicts core_plugin_appsec_failure-action.
func TestNew_AppsecModeCaptchaFailureActionServesChallenge(t *testing.T) {
	reclaim.ResetForTestWith(0)
	instance.ResetForTest()
	t.Cleanup(func() { reclaim.ResetForTest(); instance.ResetForTest() })

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

	if got := rw.Header().Get("X-Remediation"); got != "captcha" {
		t.Fatalf("remediation %q want captcha, body: %s", got, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("captcha challenge not served, body: %s", rw.Body.String())
	}
}

// TestNew_DoesNotMutateCallerConfig checks New works on a snapshot: Traefik's own struct must not
// come back normalised, and must not come back carrying the resolved LAPI secret.
func TestNew_DoesNotMutateCallerConfig(t *testing.T) {
	reclaim.ResetForTestWith(0)
	instance.ResetForTest()
	t.Cleanup(func() { reclaim.ResetForTest(); instance.ResetForTest() })

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
