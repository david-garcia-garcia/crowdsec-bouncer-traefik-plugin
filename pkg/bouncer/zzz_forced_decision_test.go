package bouncer

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"text/template"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ip"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
)

const testForcedDecisionHeader = "X-Crowdsec-Decision"

// testForcedDecisionBouncer is a stream bouncer. seedBan puts an Ip ban on the test client.
func testForcedDecisionBouncer(t *testing.T, log *slog.Logger, captchaClient *captcha.Client, trusted []string, seedBan bool) (*Bouncer, *lapi.Client, *bool) {
	t.Helper()
	if log == nil {
		log = logger.New("ERROR", "")
	}
	lapiClient, store := lapi.NewTestClient(log)
	lapi.AttachTestMetricsReporter(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	if seedBan {
		store.Put(decisionstore.Decision{
			Scope: decisionscope.ScopeIP, Value: testCaptchaRemoteIP, Kind: decisionscope.BannedValue, DurationSec: 60,
		})
	}
	clientChecker, err := ip.NewChecker(log, trusted)
	if err != nil {
		t.Fatal(err)
	}
	banTemplate, err := template.New("ban").Parse("banned")
	if err != nil {
		t.Fatal(err)
	}
	if captchaClient == nil {
		captchaClient = &captcha.Client{}
	}
	passed := false
	b := &Bouncer{
		enabled:                  true,
		forcedDecisionHeader:     testForcedDecisionHeader,
		forwardedHeadersInsecure: true,
		forwardedCustomHeader:    "X-Forwarded-For",
		clientPoolStrategy:       &ip.PoolStrategy{Checker: clientChecker},
		captchaClient:            captchaClient,
		log:                      log,
		remediationStatusCode:    http.StatusForbidden,
		banTemplate:              banTemplate,
		banTemplateContentType:   "text/html; charset=utf-8",
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			passed = true
		}),
	}
	bindTestLAPI(b, lapiClient)
	return b, lapiClient, &passed
}

// testForcedDecisionRequest is a GET whose forwarded client is the captcha test IP.
func testForcedDecisionRequest(headerValue string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", testCaptchaRemoteIP)
	if headerValue != "" {
		req.Header.Set(testForcedDecisionHeader, headerValue)
	}
	return req
}

func TestServeHTTP_forcedDecisionOffIgnoresHeader(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, nil, true)
	b.forcedDecisionHeader = ""
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("empty crowdsecDecisionHeader must still apply the stream ban")
	}
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "banned") {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_forcedDecisionCaptchaWhenLookupIsNotBan(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, lapiClient, passed := testForcedDecisionBouncer(t, nil, client, nil, false)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("forced captcha must not reach origin")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want captcha page, got %q", rw.Body.String())
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginForcedDecision, "ipv4", "captcha"); got != 1 {
		t.Fatalf("dropped origin=%d", got)
	}
}

func TestServeHTTP_forcedDecisionCaptchaDoesNotOverrideBan(t *testing.T) {
	log, sink := newTestLogSink(slog.LevelWarn)
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, _, passed := testForcedDecisionBouncer(t, log, client, nil, true)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("stream ban must not reach origin")
	}
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "banned") {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	if !strings.Contains(sink.String(), "ServeHTTP:forcedCaptchaSuperseded") {
		t.Fatalf("want WARN forcedCaptchaSuperseded, got %s", sink.String())
	}
}

// TestServeHTTP_forcedDecisionTrimmedHeaderValues fails if Header.Get values are matched without TrimSpace.
func TestServeHTTP_forcedDecisionTrimmedHeaderValues(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	captchaBouncer, _, captchaPassed := testForcedDecisionBouncer(t, nil, client, nil, false)
	captchaRW := httptest.NewRecorder()
	captchaBouncer.ServeHTTP(captchaRW, testForcedDecisionRequest(" c "))
	if *captchaPassed {
		t.Fatal("padded c must still captcha")
	}
	if !strings.Contains(captchaRW.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("padded c want captcha page, got %q", captchaRW.Body.String())
	}

	banBouncer, _, banPassed := testForcedDecisionBouncer(t, nil, nil, nil, false)
	banRW := httptest.NewRecorder()
	banBouncer.ServeHTTP(banRW, testForcedDecisionRequest(" b "))
	if *banPassed {
		t.Fatal("padded b must still ban")
	}
	if banRW.Code != http.StatusForbidden || !strings.Contains(banRW.Body.String(), "banned") {
		t.Fatalf("padded b status=%d body=%q", banRW.Code, banRW.Body.String())
	}
}

func TestServeHTTP_forcedDecisionBanSkipsStream(t *testing.T) {
	b, lapiClient, passed := testForcedDecisionBouncer(t, nil, nil, nil, false)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("b"))
	if *passed {
		t.Fatal("forced ban must not reach origin")
	}
	if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "banned") {
		t.Fatalf("status=%d body=%q", rw.Code, rw.Body.String())
	}
	if got := lapiClient.TestDroppedCount(lapi.OriginPluginForcedDecision, "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped origin=%d", got)
	}
}

func TestServeHTTP_forcedDecisionUnknownTokenFallsThrough(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, _, passed := testForcedDecisionBouncer(t, nil, client, nil, true)
	for _, token := range []string{"t", "B", "ban", "captcha", " ", ""} {
		rw := httptest.NewRecorder()
		b.ServeHTTP(rw, testForcedDecisionRequest(token))
		if *passed {
			t.Fatalf("token %q must still apply the stream ban", token)
		}
		if !strings.Contains(rw.Body.String(), "banned") {
			t.Fatalf("token %q want ban, got %q", token, rw.Body.String())
		}
		*passed = false
	}
}

func TestServeHTTP_forcedDecisionTrustedSkipsHeader(t *testing.T) {
	b, _, passed := testForcedDecisionBouncer(t, nil, nil, []string{testCaptchaRemoteIP}, true)
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("b"))
	if !*passed {
		t.Fatal("trusted client must reach origin")
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("status=%d", rw.Code)
	}
}

func TestServeHTTP_forcedDecisionCaptchaGatePasses(t *testing.T) {
	siteverify := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(siteverify.Close)
	client := testCaptchaClient(t, "/fast.js", "", siteverify.URL+"/siteverify", siteverify.Client())
	cookieValue := solveTestGateCookie(t, client)
	b, _, passed := testForcedDecisionBouncer(t, nil, client, nil, false)
	req := testForcedDecisionRequest("c")
	req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: cookieValue})
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, req)
	if !*passed {
		t.Fatal("gated visitor must reach origin while header is still c")
	}
}

func TestServeHTTP_forcedDecisionAppsecOnlyCaptcha(t *testing.T) {
	client := testCaptchaClient(t, "/fast.js", "", "", nil)
	b, _, passed := testForcedDecisionBouncer(t, nil, client, nil, false)
	b.subscribeLAPI = false
	b.lapiBound.Store((*lapi.Client)(nil))
	rw := httptest.NewRecorder()
	b.ServeHTTP(rw, testForcedDecisionRequest("c"))
	if *passed {
		t.Fatal("LAPI-off forced captcha must not reach origin")
	}
	if !strings.Contains(rw.Body.String(), "CAPTCHA_CHALLENGE_PAGE") {
		t.Fatalf("want captcha page, got %q", rw.Body.String())
	}
}

func TestBouncerNew_trimsForcedDecisionHeader(t *testing.T) {
	log := logger.New("ERROR", "")
	cfg := configuration.New()
	cfg.LapiMode = configuration.StreamMode
	cfg.BouncerDecisionHeader = "  X-Crowdsec-Decision  "
	got, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "test", cfg, false, true, log)
	if err != nil {
		t.Fatal(err)
	}
	if got.forcedDecisionHeader != testForcedDecisionHeader {
		t.Fatalf("forcedDecisionHeader=%q", got.forcedDecisionHeader)
	}
}
