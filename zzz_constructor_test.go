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
	c.CrowdsecMode = configuration.AppsecMode
	c.CrowdsecAppsecEnabled = true
	c.CrowdsecAppsecScheme = "http"
	c.CrowdsecAppsecHost = appsecHost
	c.CrowdsecAppsecPath = "/"
	c.CrowdsecAppsecFailureAction = configuration.FailureActionCaptcha
	c.CaptchaProvider = configuration.CustomProvider
	c.CaptchaCustomJsURL = "/captcha.js"
	c.CaptchaCustomKey = "dummy-captcha"
	c.CaptchaCustomResponse = "dummy-captcha-response"
	c.CaptchaCustomValidateURL = "http://127.0.0.1/siteverify"
	c.CaptchaSiteKey = "site"
	c.CaptchaSecretKey = "secret"
	c.CaptchaGateSecret = "gate-secret"
	c.CaptchaFilePath = writeTestFile(t, "captcha.html", "CAPTCHA_CHALLENGE_PAGE")
	c.RemediationHeadersCustomName = "X-Remediation"
	c.ForwardedHeadersTrustedIPs = []string{"127.0.0.1/32"}
	c.ForwardedHeadersCustomName = "X-Forwarded-For"
	return c
}

// TestNew_FailedConstructorReleasesLapiHolder checks that a constructor which fails after an
// earlier Open succeeded releases that holder. The stream client opens, then appsec.Open fails
// on an unusable client certificate. Without a rollback the stream ticker polls LAPI forever.
func TestNew_FailedConstructorReleasesLapiHolder(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

	var hits int64
	srv := liveLAPI(t, nil, &hits)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	cfg := cfgStreamAt(u.Host, 1)
	cfg.CrowdsecAppsecEnabled = true
	cfg.CrowdsecAppsecScheme = "https"
	cfg.CrowdsecAppsecHost = u.Host
	cfg.CrowdsecAppsecPath = "/"
	cfg.CrowdsecAppsecTLSInsecureVerify = true
	cfg.CrowdsecAppsecTLSCertificateBouncer = "not a certificate"
	cfg.CrowdsecAppsecTLSCertificateBouncerKey = "not a key"

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
	t.Cleanup(func() { reclaim.ResetForTest() })

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
func TestNew_AppsecModeWithoutAppsecWarns(t *testing.T) {
	logFile := newTestLogFile(t)

	cfg := getTestConfig()
	cfg.CrowdsecMode = configuration.AppsecMode
	cfg.CrowdsecAppsecEnabled = false
	cfg.LogFormat = "common"
	cfg.LogFilePath = logFile

	if _, err := New(context.Background(), testNextOK(), cfg, "appsec-no-waf"); err != nil {
		t.Fatalf("appsec mode with AppSec disabled must still start: %v", err)
	}

	logged, err := os.ReadFile(logFile) //nolint:gosec // test-generated temp path
	if err != nil {
		t.Fatal(err)
	}
	line := ""
	for _, candidate := range strings.Split(string(logged), "\n") {
		if strings.Contains(candidate, "level=WARN") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatalf("no WARN line for appsec mode without AppSec. log:\n%s", logged)
	}
	for _, want := range []string{"crowdsecMode", "crowdsecAppsecEnabled"} {
		if !strings.Contains(line, want) {
			t.Fatalf("WARN line must name %s, got %q", want, line)
		}
	}
}

// TestNew_AppsecModeCaptchaFailureActionServesChallenge checks that an AppSec failure in appsec
// mode with crowdsecAppsecFailureAction: captcha serves the challenge. Without the captcha client
// the bouncer falls back to a ban, which contradicts core_plugin_appsec_failure-action.
func TestNew_AppsecModeCaptchaFailureActionServesChallenge(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })

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
	t.Cleanup(func() { reclaim.ResetForTest() })

	var zero int64
	srv := liveLAPI(t, nil, &zero)
	t.Cleanup(func() { srv.Close() })
	u, _ := url.Parse(srv.URL)

	cfg := cfgLiveAt(u.Host)
	cfg.LogLevel = "info"
	cfg.CrowdsecLapiKey = ""
	cfg.CrowdsecLapiKeyFile = writeTestFile(t, "lapi.key", "resolved-lapi-key")

	if _, err := New(context.Background(), testNextOK(), cfg, "snapshot"); err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "info" {
		t.Fatalf("New normalised the caller's logLevel to %q", cfg.LogLevel)
	}
	if cfg.CrowdsecLapiKey != "" {
		t.Fatalf("New wrote the resolved LAPI secret into the caller's config: %q", cfg.CrowdsecLapiKey)
	}
}
