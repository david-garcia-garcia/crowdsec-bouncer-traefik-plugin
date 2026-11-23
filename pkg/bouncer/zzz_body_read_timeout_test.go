package bouncer

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/modsecurity"
)

// stallingTestBody blocks every Read until Close, the way an HTTP/2 stream that never ends blocks
// until its handler closes the body.
type stallingTestBody struct {
	once sync.Once
	cut  chan struct{}
}

// Read blocks until Close, then fails like a closed HTTP/2 request body.
func (s *stallingTestBody) Read([]byte) (int, error) {
	<-s.cut
	return 0, errors.New("http2: request body closed due to handler exiting")
}

// Close unblocks Read.
func (s *stallingTestBody) Close() error {
	s.once.Do(func() { close(s.cut) })
	return nil
}

// unknownLengthTestRequest is an HTTP/2 POST /upload?token=secret with body and no Content-Length.
func unknownLengthTestRequest(t *testing.T, body io.ReadCloser) *http.Request {
	t.Helper()
	req := testModsecRequest("/upload?token=secret")
	req.Method = http.MethodPost
	req.ProtoMajor = 2
	req.ContentLength = -1
	req.Body = body
	t.Cleanup(func() { _ = body.Close() })
	return req
}

// stalledTestRequest is an unknownLengthTestRequest whose body never ends.
func stalledTestRequest(t *testing.T) *http.Request {
	t.Helper()
	return unknownLengthTestRequest(t, &stallingTestBody{cut: make(chan struct{})})
}

// oneSecondReadTimeoutAppsec is an AppSec client with appsecBodyReadTimeoutSeconds 1 that counts its
// calls and allows every request.
func oneSecondReadTimeoutAppsec(t *testing.T, hits *atomic.Int32) *appsec.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := configuration.New()
	cfg.AppsecEnabled = true
	cfg.AppsecHost = u.Host
	cfg.AppsecScheme = "http"
	cfg.AppsecBodyReadTimeoutSeconds = 1
	cfg.AppsecUnhealthyBackOffPeriodSecs = 0
	client, err := appsec.New(cfg, logger.New("ERROR", ""), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// oneSecondReadTimeoutModsec is a ModSec client with modsecBodyReadTimeoutSeconds 1 that counts its calls
// and allows every request.
func oneSecondReadTimeoutModsec(t *testing.T, hits *atomic.Int32) *modsecurity.Client {
	t.Helper()
	sidecar := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(sidecar.Close)
	cfg := configuration.New()
	cfg.ModsecEnabled = true
	cfg.ModsecURL = sidecar.URL
	cfg.ModsecBodyReadTimeoutSeconds = 1
	client, err := modsecurity.New(cfg, slog.Default(), "test", "n", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// bodyReadTimeoutTestBouncer binds one WAF leg ("appsec" or "modsec") with a 1 s read timeout and the
// given failure action on that leg.
func bodyReadTimeoutTestBouncer(t *testing.T, leg, failureAction string, rules []httprule.ActionRule, hits *atomic.Int32) (*Bouncer, *bool) {
	t.Helper()
	if leg == legModsec {
		b, passed := testModsecBouncer(t, failureAction, rules)
		bindTestModSec(b, oneSecondReadTimeoutModsec(t, hits))
		return b, passed
	}
	b, passed := testModsecBouncer(t, configuration.FailureActionPassthrough, rules)
	b.appsecFailureAction = failureAction
	bindTestAppSec(b, oneSecondReadTimeoutAppsec(t, hits))
	return b, passed
}

// TestServeHTTP_bodyReadTimeoutIs400WhateverTheFailureAction proves a stalled body without
// Content-Length is answered 400 error:body-read-timeout on each leg and under each failure action:
// no ban, no captcha, no dropped request, the WAF is not called, and origin is not called.
func TestServeHTTP_bodyReadTimeoutIs400WhateverTheFailureAction(t *testing.T) {
	for _, leg := range []string{legAppsec, legModsec} {
		for _, failureAction := range []string{configuration.FailureActionBan, configuration.FailureActionPassthrough, configuration.FailureActionCaptcha} {
			t.Run(leg+"/"+failureAction, func(t *testing.T) {
				assertStalledBodyIs400(t, leg, failureAction)
			})
		}
	}
}

// assertStalledBodyIs400 serves a stalled body on one leg under one failure action and checks the
// 400 answer, its header, that neither the WAF nor origin was called, and that nothing was counted dropped.
func assertStalledBodyIs400(t *testing.T, leg, failureAction string) {
	t.Helper()
	var hits atomic.Int32
	b, passed := bodyReadTimeoutTestBouncer(t, leg, failureAction, nil, &hits)
	lapiClient := withTestMetrics(b)
	rw := httptest.NewRecorder()
	continueAfterLAPIForTest(b, rw, testClientRequest(stalledTestRequest(t), "203.0.113.40"))
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rw.Code)
	}
	if got := rw.Header().Get("X-Remediation"); got != "error:body-read-timeout" {
		t.Fatalf("X-Remediation=%q want error:body-read-timeout", got)
	}
	if *passed {
		t.Fatal("a stalled body must not reach origin")
	}
	if hits.Load() != 0 {
		t.Fatalf("WAF called %d times for a stalled body", hits.Load())
	}
	for _, origin := range []string{originAppsec, originModsec, lapi.OriginPluginAppsecFailure, lapi.OriginPluginModsecFailure} {
		for _, remediation := range []string{"ban", "captcha"} {
			if got := lapiClient.TestDroppedCount(origin, "ipv4", remediation); got != 0 {
				t.Fatalf("dropped %s/%s=%d want 0", origin, remediation, got)
			}
		}
	}
}

// TestServeHTTP_bodyReadTimeoutWarnsOncePerWindowPerLeg proves two deadlines within 5 s log one WARN per
// leg, with the request named by ip, method, host, and path, and no query string.
func TestServeHTTP_bodyReadTimeoutWarnsOncePerWindowPerLeg(t *testing.T) {
	logger.ResetDebounceForTest()
	t.Cleanup(logger.ResetDebounceForTest)
	for _, tc := range []struct{ leg, msg string }{
		{legAppsec, msgAppsecBodyReadTimeout},
		{legModsec, msgModsecBodyReadTimeout},
	} {
		var hits atomic.Int32
		b, _ := bodyReadTimeoutTestBouncer(t, tc.leg, configuration.FailureActionBan, nil, &hits)
		log, sink := newTestLogSink(slog.LevelWarn)
		b.log = log
		for range 2 {
			rw := httptest.NewRecorder()
			continueAfterLAPIForTest(b, rw, testClientRequest(stalledTestRequest(t), "203.0.113.40"))
			if rw.Code != http.StatusBadRequest {
				t.Fatalf("%s: status=%d want 400", tc.leg, rw.Code)
			}
		}
		logged := sink.String()
		if got := strings.Count(logged, tc.msg); got != 1 {
			t.Fatalf("%s: WARN lines=%d want 1\n%s", tc.leg, got, logged)
		}
		for _, attr := range []string{`"level":"WARN"`, `"ip":"203.0.113.40"`, `"method":"POST"`, `"host":"example.com"`, `"path":"/upload"`, `"timeoutSeconds":1`} {
			if !strings.Contains(logged, attr) {
				t.Fatalf("%s: WARN missing %s\n%s", tc.leg, attr, logged)
			}
		}
		if strings.Contains(logged, "secret") {
			t.Fatalf("%s: WARN leaked the query string\n%s", tc.leg, logged)
		}
	}
}

// TestServeHTTP_bypassRuleSkipsTheBodyRead proves bypassAppsec / bypassModsec keep that leg from reading
// a body that never ends: no deadline, no WAF call, and origin is called at once.
func TestServeHTTP_bypassRuleSkipsTheBodyRead(t *testing.T) {
	for _, tc := range []struct{ leg, token string }{
		{legAppsec, httprule.ActionBypassAppsec},
		{legModsec, httprule.ActionBypassModsec},
	} {
		var hits atomic.Int32
		rules := []httprule.ActionRule{{Name: "stream", Action: []string{tc.token}, Rule: httprule.Rule{Path: "^/upload$"}}}
		b, passed := bodyReadTimeoutTestBouncer(t, tc.leg, configuration.FailureActionBan, rules, &hits)
		started := time.Now()
		continueAfterLAPIForTest(b, httptest.NewRecorder(), testClientRequest(stalledTestRequest(t), "203.0.113.40"))
		if !*passed || hits.Load() != 0 {
			t.Fatalf("%s: passed=%v WAF calls=%d want origin and no WAF call", tc.token, *passed, hits.Load())
		}
		if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
			t.Fatalf("%s: took %v, the leg must not read the body", tc.token, elapsed)
		}
	}
}

// TestServeHTTP_resticShapeReachesOrigin is upstream issue #405: an empty HTTP/2 POST with no
// Content-Length, both WAF legs, the default failure actions and ModSec's ban. Both legs inspect it and
// origin is called; neither failure action applies.
func TestServeHTTP_resticShapeReachesOrigin(t *testing.T) {
	for _, modsecFailureAction := range []string{"", configuration.FailureActionBan} {
		var appsecHits, modsecHits atomic.Int32
		b, passed := testModsecBouncer(t, modsecFailureAction, nil)
		b.appsecFailureAction = configuration.EffectiveFailureAction("")
		bindTestAppSec(b, countingAppsec(t, &appsecHits))
		bindTestModSec(b, countingModsec(t, &modsecHits))
		rw := httptest.NewRecorder()
		req := unknownLengthTestRequest(t, io.NopCloser(strings.NewReader("")))
		req.URL.RawQuery = "create=true"
		continueAfterLAPIForTest(b, rw, testClientRequest(req, "203.0.113.40"))
		if !*passed {
			t.Fatalf("modsec failure action %q: restic init must reach origin, status=%d header=%q", modsecFailureAction, rw.Code, rw.Header().Get("X-Remediation"))
		}
		if appsecHits.Load() != 1 || modsecHits.Load() != 1 {
			t.Fatalf("modsec failure action %q: AppSec calls=%d ModSec calls=%d want 1 and 1", modsecFailureAction, appsecHits.Load(), modsecHits.Load())
		}
	}
}
