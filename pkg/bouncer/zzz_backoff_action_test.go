package bouncer

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
)

// testBackoffClientIP is the client address of every request in these tests.
const testBackoffClientIP = "203.0.113.40"

// newTestBackoffRouter builds a router through New, so its failure and backoff actions are the resolved
// config values, with a ban template that prints RemediationReason. passed reports a call to next.
func newTestBackoffRouter(t *testing.T, cfg *configuration.Config, subscriptions Subscriptions, log *slog.Logger) (*Bouncer, *bool) {
	t.Helper()
	passed := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passed = true })
	b, err := New(next, "router", cfg, subscriptions, log)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned {{ .RemediationReason }}")
	if err != nil {
		t.Fatal(err)
	}
	b.banTemplate = banTemplate
	b.banTemplateContentType = "text/html; charset=utf-8"
	return b, &passed
}

// testBackoffRouterConfig is the packaged config with the router on and the verdict header named.
func testBackoffRouterConfig() *configuration.Config {
	cfg := configuration.New()
	cfg.BouncerEnabled = true
	cfg.BouncerRemediationHeadersCustomName = "X-Remediation"
	return cfg
}

// serveBackoffRequest runs ServeHTTP for req from testBackoffClientIP.
func serveBackoffRequest(b *Bouncer, req *http.Request) *httptest.ResponseRecorder {
	req.RemoteAddr = testBackoffClientIP + ":1"
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	return rw
}

// trippedLiveLAPI is a live LAPI Client whose gate tripped against a LAPI that answers 503. hits counts the GETs.
func trippedLiveLAPI(t *testing.T) (*lapi.Client, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	cfg := configuration.New()
	cfg.LapiHost = serverURL.Host
	cfg.LapiKey = "test-key"
	cfg.LapiMetricsUpdateIntervalSeconds = 0
	store := decisionstore.NewMemory(logger.New("ERROR"))
	client, err := lapi.New(cfg, logger.New("ERROR"), "test", store, "owner", "bind")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	for range admission.TripFailures {
		_, _, _ = client.LiveLookup("198.51.100.1", nil, 60)
	}
	return client, &hits
}

// bindLiveTestLAPI subscribes b to a live client without forcing stream mode (bindTestLAPI does).
func bindLiveTestLAPI(b *Bouncer, client *lapi.Client) {
	b.lapiLeg.subscribed = true
	b.lapiLeg.bound.Store(client)
}

// metricsTestLAPI is a healthy stream client with no decision, bound so a WAF backoff answer has a
// connection to count its drop on.
func metricsTestLAPI(b *Bouncer) *lapi.Client {
	client, _ := lapi.NewTestClient(logger.New("ERROR"))
	lapi.AttachTestMetricsReporter(client)
	client.SetStreamHealthyForTest(true)
	bindTestLAPI(b, client)
	return client
}

// trippedAppSec is an AppSec Client whose gate tripped against a listener that answers 500, and that
// already skipped once (so it reports BackingOff). hits counts the listener calls.
func trippedAppSec(t *testing.T) (*appsec.Client, *int64) {
	t.Helper()
	var hits int64
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	serverURL, _ := url.Parse(server.URL)
	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecHost = serverURL.Host
	cfg.AppsecScheme = "http"
	client, err := appsec.New(cfg, logger.New("ERROR"), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	for range admission.TripFailures + 1 {
		req := testClientRequest(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), testBackoffClientIP)
		_, _ = client.Query(req, appsec.Policy{FailureAction: configuration.FailureActionBan})
	}
	return client, &hits
}

// trippedModSec is a ModSec Client whose gate tripped against a sidecar that answers 503, and that
// already skipped once (so it reports BackingOff). hits counts the sidecar calls.
func trippedModSec(t *testing.T) (*modsecurity.Client, *int) {
	t.Helper()
	hits := 0
	client := failingModsec(t, 10, &hits)
	for range admission.TripFailures + 1 {
		_, _ = client.Inspect(httptest.NewRequest(http.MethodGet, "http://example.com/", nil), configuration.FailureActionBan)
	}
	return client, &hits
}

// backoffLeg is one gated leg as the backoff matrix drives it.
type backoffLeg struct {
	name          string
	setBackOff    func(cfg *configuration.Config, action string)
	subscriptions Subscriptions
	// bind binds a tripped client of this leg and returns the client that counts drops plus a
	// function that reads the backend hits.
	bind      func(t *testing.T, b *Bouncer) (*lapi.Client, func() int64)
	banReason string
	origin    string
}

// backoffLegs are LAPI live, AppSec, and ModSec, each tripped before the request under test.
func backoffLegs() []backoffLeg {
	return []backoffLeg{
		{
			name: "lapi",
			setBackOff: func(cfg *configuration.Config, action string) {
				cfg.BouncerLapiFailureAction = configuration.FailureActionPassthrough
				cfg.BouncerLapiBackOffAction = action
			},
			subscriptions: Subscriptions{LAPI: true, Captcha: true},
			bind: func(t *testing.T, b *Bouncer) (*lapi.Client, func() int64) {
				t.Helper()
				client, hits := trippedLiveLAPI(t)
				bindLiveTestLAPI(b, client)
				return client, func() int64 { return atomic.LoadInt64(hits) }
			},
			banReason: configuration.ReasonLAPI,
			origin:    lapi.OriginPluginLapiFailure,
		},
		{
			name:          "appsec",
			setBackOff:    func(cfg *configuration.Config, action string) { cfg.BouncerAppsecBackOffAction = action },
			subscriptions: Subscriptions{LAPI: true, AppSec: true, Captcha: true},
			bind: func(t *testing.T, b *Bouncer) (*lapi.Client, func() int64) {
				t.Helper()
				metrics := metricsTestLAPI(b)
				client, hits := trippedAppSec(t)
				bindTestAppSec(b, client)
				return metrics, func() int64 { return atomic.LoadInt64(hits) }
			},
			banReason: configuration.ReasonAPPSEC,
			origin:    lapi.OriginPluginAppsecFailure,
		},
		{
			name:          "modsec",
			setBackOff:    func(cfg *configuration.Config, action string) { cfg.BouncerModsecBackOffAction = action },
			subscriptions: Subscriptions{LAPI: true, ModSec: true, Captcha: true},
			bind: func(t *testing.T, b *Bouncer) (*lapi.Client, func() int64) {
				t.Helper()
				metrics := metricsTestLAPI(b)
				client, hits := trippedModSec(t)
				bindTestModSec(b, client)
				return metrics, func() int64 { return int64(*hits) }
			},
			banReason: configuration.ReasonMODSEC,
			origin:    lapi.OriginPluginModsecFailure,
		},
	}
}

// TestServeHTTP_backOffActionPerLeg drives every gated leg through passthrough, ban, captcha, and a
// captcha with no usable captcha client while its gate backs off. The backend is never called, the
// failure action never decides, and a written answer is labeled <leg>-backoff under the failure origin.
func TestServeHTTP_backOffActionPerLeg(t *testing.T) {
	for _, leg := range backoffLegs() {
		t.Run(leg.name+" passthrough", func(t *testing.T) { assertBackOffPassthrough(t, leg) })
		t.Run(leg.name+" ban", func(t *testing.T) { assertBackOffBan(t, leg) })
		t.Run(leg.name+" captcha", func(t *testing.T) { assertBackOffCaptcha(t, leg) })
		t.Run(leg.name+" captcha without a usable captcha", func(t *testing.T) { assertBackOffCaptchaDowngrade(t, leg) })
	}
}

// assertBackOffPassthrough: the request reaches the backend with no header and no backend call.
func assertBackOffPassthrough(t *testing.T, leg backoffLeg) {
	t.Helper()
	cfg := testBackoffRouterConfig()
	leg.setBackOff(cfg, configuration.FailureActionPassthrough)
	b, passed := newTestBackoffRouter(t, cfg, leg.subscriptions, logger.New("ERROR"))
	_, hits := leg.bind(t, b)
	before := hits()
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if !*passed || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("passed=%v header=%q want the backend with no header", *passed, rw.Header().Get("X-Remediation"))
	}
	if hits() != before {
		t.Fatal("a backoff must not call the backend")
	}
}

// assertBackOffBan: 403 ban:<leg>-backoff, the leg's RemediationReason, one drop under the failure origin.
func assertBackOffBan(t *testing.T, leg backoffLeg) {
	t.Helper()
	cfg := testBackoffRouterConfig()
	leg.setBackOff(cfg, configuration.FailureActionBan)
	b, passed := newTestBackoffRouter(t, cfg, leg.subscriptions, logger.New("ERROR"))
	metrics, hits := leg.bind(t, b)
	before := hits()
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if *passed || rw.Code != http.StatusForbidden {
		t.Fatalf("passed=%v status=%d want 403", *passed, rw.Code)
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:"+leg.name+"-backoff" {
		t.Fatalf("X-Remediation=%q want ban:%s-backoff", got, leg.name)
	}
	if body := rw.Body.String(); body != "banned "+leg.banReason {
		t.Fatalf("body=%q want RemediationReason %s", body, leg.banReason)
	}
	if got := metrics.TestDroppedCount(leg.origin, "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped %s/ban=%d want 1", leg.origin, got)
	}
	if hits() != before {
		t.Fatal("a backoff must not call the backend")
	}
}

// assertBackOffCaptcha: the router's captcha page, captcha:<leg>-backoff, one drop under the failure origin.
func assertBackOffCaptcha(t *testing.T, leg backoffLeg) {
	t.Helper()
	cfg := testBackoffRouterConfig()
	leg.setBackOff(cfg, configuration.FailureActionCaptcha)
	b, passed := newTestBackoffRouter(t, cfg, leg.subscriptions, logger.New("ERROR"))
	metrics, _ := leg.bind(t, b)
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if *passed || !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("passed=%v body=%q want the captcha page", *passed, rw.Body.String())
	}
	if got := rw.Header().Get("X-Remediation"); got != "captcha:"+leg.name+"-backoff" {
		t.Fatalf("X-Remediation=%q want captcha:%s-backoff", got, leg.name)
	}
	if got := metrics.TestDroppedCount(leg.origin, "ipv4", "captcha"); got != 1 {
		t.Fatalf("dropped %s/captcha=%d want 1", leg.origin, got)
	}
}

// assertBackOffCaptchaDowngrade: a subscribed but unpublished captcha bans with ban:captcha-downgrade.
func assertBackOffCaptchaDowngrade(t *testing.T, leg backoffLeg) {
	t.Helper()
	cfg := testBackoffRouterConfig()
	leg.setBackOff(cfg, configuration.FailureActionCaptcha)
	b, passed := newTestBackoffRouter(t, cfg, leg.subscriptions, logger.New("ERROR"))
	leg.bind(t, b)
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if *passed || rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:captcha-downgrade" {
		t.Fatalf("passed=%v status=%d header=%q want 403 ban:captcha-downgrade", *passed, rw.Code, rw.Header().Get("X-Remediation"))
	}
	if body := rw.Body.String(); body != "banned "+leg.banReason {
		t.Fatalf("body=%q want RemediationReason %s", body, leg.banReason)
	}
}

// TestServeHTTP_lapiBackOffCaptchaIsBypassed proves a bypassCaptcha rule lets a LAPI backoff captcha
// through, with no header and no drop.
func TestServeHTTP_lapiBackOffCaptchaIsBypassed(t *testing.T) {
	cfg := testBackoffRouterConfig()
	cfg.BouncerLapiBackOffAction = configuration.FailureActionCaptcha
	b, passed := newTestBackoffRouter(t, cfg, Subscriptions{LAPI: true, Captcha: true}, logger.New("ERROR"))
	b.actionRules = apiBypassCaptchaRules(t)
	client, _ := trippedLiveLAPI(t)
	bindLiveTestLAPI(b, client)
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodGet, "http://example.com/api/items", nil))
	if !*passed || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("passed=%v header=%q want the backend with no header", *passed, rw.Header().Get("X-Remediation"))
	}
	if got := client.TestDroppedCount(lapi.OriginPluginLapiFailure, "ipv4", "captcha"); got != 0 {
		t.Fatalf("dropped captcha=%d want 0", got)
	}
}

// TestServeHTTP_lapiBackOffBanSupersedesCaptchaRule proves a backoff ban beats a matching captcha rule,
// keeps the LAPI failure origin, and warns that the rule lost.
func TestServeHTTP_lapiBackOffBanSupersedesCaptchaRule(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	b, passed := newTestBackoffRouter(t, testBackoffRouterConfig(), Subscriptions{LAPI: true, Captcha: true}, log)
	b.actionRules = mustPathAction(t, "gate", "^/", httprule.ActionCaptcha)
	client, _ := trippedLiveLAPI(t)
	bindLiveTestLAPI(b, client)
	bindTestCaptcha(b, testCaptchaClient(t, "/fast.js", "", "", nil))
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if *passed || rw.Header().Get("X-Remediation") != "ban:lapi-backoff" {
		t.Fatalf("passed=%v header=%q want ban:lapi-backoff", *passed, rw.Header().Get("X-Remediation"))
	}
	if got := client.TestDroppedCount(lapi.OriginPluginLapiFailure, "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped %s/ban=%d want 1", lapi.OriginPluginLapiFailure, got)
	}
	if logged := sink.String(); !strings.Contains(logged, "warnCaptchaSuperseded") || !strings.Contains(logged, `"name":"gate"`) {
		t.Fatalf("want WARN warnCaptchaSuperseded naming gate, got %s", logged)
	}
}

// TestServeHTTP_twoRoutersOnOneAppsecGate proves the gate is shared and the action is per router.
func TestServeHTTP_twoRoutersOnOneAppsecGate(t *testing.T) {
	client, hits := trippedAppSec(t)
	before := atomic.LoadInt64(hits)
	strictCfg := testBackoffRouterConfig()
	strictCfg.BouncerAppsecBackOffAction = configuration.FailureActionBan
	strict, strictPassed := newTestBackoffRouter(t, strictCfg, Subscriptions{AppSec: true}, logger.New("ERROR"))
	bindTestAppSec(strict, client)
	lenient, lenientPassed := newTestBackoffRouter(t, testBackoffRouterConfig(), Subscriptions{AppSec: true}, logger.New("ERROR"))
	bindTestAppSec(lenient, client)

	rw := serveBackoffRequest(strict, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if *strictPassed || rw.Header().Get("X-Remediation") != "ban:appsec-backoff" {
		t.Fatalf("strict router passed=%v header=%q want ban:appsec-backoff", *strictPassed, rw.Header().Get("X-Remediation"))
	}
	rw = serveBackoffRequest(lenient, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if !*lenientPassed || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("default router passed=%v header=%q want the backend", *lenientPassed, rw.Header().Get("X-Remediation"))
	}
	if atomic.LoadInt64(hits) != before {
		t.Fatal("neither router may call AppSec while the shared gate backs off")
	}
}

// TestServeHTTP_twoRoutersOnOneLapiGate proves the live LAPI gate is shared and the backoff action is
// per router: the default router bans, the router that asks for passthrough lets the request through.
func TestServeHTTP_twoRoutersOnOneLapiGate(t *testing.T) {
	client, hits := trippedLiveLAPI(t)
	before := atomic.LoadInt64(hits)
	strict, strictPassed := newTestBackoffRouter(t, testBackoffRouterConfig(), Subscriptions{LAPI: true}, logger.New("ERROR"))
	bindLiveTestLAPI(strict, client)
	lenientCfg := testBackoffRouterConfig()
	lenientCfg.BouncerLapiBackOffAction = configuration.FailureActionPassthrough
	lenient, lenientPassed := newTestBackoffRouter(t, lenientCfg, Subscriptions{LAPI: true}, logger.New("ERROR"))
	bindLiveTestLAPI(lenient, client)

	rw := serveBackoffRequest(strict, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if *strictPassed || rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:lapi-backoff" {
		t.Fatalf("default router passed=%v status=%d header=%q want 403 ban:lapi-backoff", *strictPassed, rw.Code, rw.Header().Get("X-Remediation"))
	}
	rw = serveBackoffRequest(lenient, httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	if !*lenientPassed || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("passthrough router passed=%v header=%q want the backend", *lenientPassed, rw.Header().Get("X-Remediation"))
	}
	if atomic.LoadInt64(hits) != before {
		t.Fatal("neither router may call LAPI while the shared gate backs off")
	}
}

// unreadableBodyRequest is a POST whose body streams without a length.
func unreadableBodyRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", io.NopCloser(strings.NewReader("payload")))
	req.ContentLength = -1
	return req
}

// TestServeHTTP_unreadableBodyWhileBackingOffUsesBackOffAction proves the AppSec and ModSec skip for a
// streamed body without a length answers with the backoff action, not the failure action.
func TestServeHTTP_unreadableBodyWhileBackingOffUsesBackOffAction(t *testing.T) {
	t.Run("appsec", func(t *testing.T) {
		cfg := testBackoffRouterConfig()
		cfg.BouncerAppsecFailureAction = configuration.FailureActionCaptcha
		cfg.BouncerAppsecBackOffAction = configuration.FailureActionBan
		b, _ := newTestBackoffRouter(t, cfg, Subscriptions{AppSec: true}, logger.New("ERROR"))
		client, hits := trippedAppSec(t)
		before := atomic.LoadInt64(hits)
		bindTestAppSec(b, client)
		rw := serveBackoffRequest(b, unreadableBodyRequest())
		if rw.Header().Get("X-Remediation") != "ban:appsec-backoff" {
			t.Fatalf("X-Remediation=%q want ban:appsec-backoff", rw.Header().Get("X-Remediation"))
		}
		if atomic.LoadInt64(hits) != before {
			t.Fatal("an unreadable body while backing off must not call AppSec")
		}
	})
	t.Run("modsec", func(t *testing.T) {
		cfg := testBackoffRouterConfig()
		cfg.BouncerModsecFailureAction = configuration.FailureActionCaptcha
		cfg.BouncerModsecBackOffAction = configuration.FailureActionBan
		b, _ := newTestBackoffRouter(t, cfg, Subscriptions{ModSec: true}, logger.New("ERROR"))
		client, hits := trippedModSec(t)
		before := *hits
		bindTestModSec(b, client)
		rw := serveBackoffRequest(b, unreadableBodyRequest())
		if rw.Header().Get("X-Remediation") != "ban:modsec-backoff" {
			t.Fatalf("X-Remediation=%q want ban:modsec-backoff", rw.Header().Get("X-Remediation"))
		}
		if *hits != before {
			t.Fatal("an unreadable body while backing off must not call the sidecar")
		}
	})
}

// TestServeHTTP_modsecOverLimitIs413WhileBackingOff keeps the body limit ahead of the gate.
func TestServeHTTP_modsecOverLimitIs413WhileBackingOff(t *testing.T) {
	cfg := testBackoffRouterConfig()
	cfg.BouncerModsecBackOffAction = configuration.FailureActionBan
	b, passed := newTestBackoffRouter(t, cfg, Subscriptions{ModSec: true}, logger.New("ERROR"))
	client, _ := trippedModSec(t)
	bindTestModSec(b, client)
	rw := serveBackoffRequest(b, httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("123456789")))
	if *passed || rw.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("passed=%v status=%d want 413", *passed, rw.Code)
	}
}

// TestNew_warnsWhenBackOffActionIsStricter pins the startup WARN: once per subscribed leg whose backoff
// action outranks its failure action, never for a stream LAPI owner or an unsubscribed leg.
func TestNew_warnsWhenBackOffActionIsStricter(t *testing.T) {
	cases := []struct {
		name          string
		mutate        func(cfg *configuration.Config)
		subscriptions Subscriptions
		wantWarns     int
		wantFields    []string
	}{
		{
			name:          "LAPI passthrough failure with the default backoff ban",
			mutate:        func(cfg *configuration.Config) { cfg.BouncerLapiFailureAction = configuration.FailureActionPassthrough },
			subscriptions: Subscriptions{LAPI: true},
			wantWarns:     1,
			wantFields:    []string{`"leg":"lapi"`, `"failureAction":"passthrough"`, `"backOffAction":"ban"`},
		},
		{
			name:          "defaults",
			mutate:        func(*configuration.Config) {},
			subscriptions: Subscriptions{LAPI: true, AppSec: true, ModSec: true},
		},
		{
			name: "stream LAPI owner",
			mutate: func(cfg *configuration.Config) {
				cfg.LapiEnabled = true
				cfg.LapiMode = configuration.StreamMode
				cfg.BouncerLapiFailureAction = configuration.FailureActionPassthrough
			},
			subscriptions: Subscriptions{LAPI: true},
		},
		{
			name:          "unsubscribed ModSec",
			mutate:        func(cfg *configuration.Config) { cfg.BouncerModsecBackOffAction = configuration.FailureActionBan },
			subscriptions: Subscriptions{LAPI: true},
		},
		{
			name:          "ModSec subscriber with a backoff ban",
			mutate:        func(cfg *configuration.Config) { cfg.BouncerModsecBackOffAction = configuration.FailureActionBan },
			subscriptions: Subscriptions{ModSec: true},
			wantWarns:     1,
			wantFields:    []string{`"leg":"modsec"`, `"failureAction":"passthrough"`, `"backOffAction":"ban"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testBackoffRouterConfig()
			tc.mutate(cfg)
			log, sink := newTestLogSink(slog.LevelWarn)
			if _, err := New(http.NotFoundHandler(), "router", cfg, tc.subscriptions, log); err != nil {
				t.Fatalf("New must not fail: %v", err)
			}
			logged := sink.String()
			if got := strings.Count(logged, msgBackOffStricterThanFailure); got != tc.wantWarns {
				t.Fatalf("stricter-than WARN logged %d times, want %d:\n%s", got, tc.wantWarns, logged)
			}
			for _, field := range tc.wantFields {
				if !strings.Contains(logged, field) {
					t.Fatalf("WARN misses %s:\n%s", field, logged)
				}
			}
		})
	}
}
