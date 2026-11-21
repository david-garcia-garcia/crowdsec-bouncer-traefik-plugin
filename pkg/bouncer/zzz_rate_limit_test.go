package bouncer

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"text/template"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/appsec"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionstore"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
)

// testRateLimitClientIP is the client address every rate-limit request comes from unless a test says otherwise.
const testRateLimitClientIP = "198.51.100.20"

// testRateLimitRetryAfter is the RetryAfter testRateLimitCounter returns on a deny; Retry-After must round it up to 8.
const testRateLimitRetryAfter = 7*time.Second + 300*time.Millisecond

// testRateLimitCounter is an in-memory ratelimit.Counter. err makes every Take fail; block makes every
// Take wait for its context. A denied Take carries testRateLimitRetryAfter.
type testRateLimitCounter struct {
	block  bool
	counts map[string]int64
	err    error
	takes  atomic.Int64
}

// Take counts one hit on key and reports whether the count is within limit.
func (counter *testRateLimitCounter) Take(ctx context.Context, key string, limit int64, _ time.Duration) (ratelimit.Status, error) {
	counter.takes.Add(1)
	if counter.block {
		<-ctx.Done()
		return ratelimit.Status{}, ctx.Err()
	}
	if counter.err != nil {
		return ratelimit.Status{}, counter.err
	}
	counter.counts[key]++
	status := ratelimit.Status{Allowed: counter.counts[key] <= limit, Limit: limit, Estimated: float64(counter.counts[key])}
	if !status.Allowed {
		status.RetryAfter = testRateLimitRetryAfter
	}
	return status, nil
}

// testRateLimitFixture is one router with the rate limit on, a stream LAPI client that counts usage
// metrics, and an in-memory counter.
type testRateLimitFixture struct {
	b          *Bouncer
	counter    *testRateLimitCounter
	lapiClient *lapi.Client
	next       *recordedNextRequest
	store      *decisionstore.Store
}

// perIPTestBucket is a catch-all deny bucket that allows requests per minute per client address.
func perIPTestBucket(name string, requests int) ratelimit.BucketRule {
	return ratelimit.BucketRule{Name: name, Requests: requests, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}}
}

// newTestRateLimitFixture builds the router through New, so the buckets compile the way they do in production.
func newTestRateLimitFixture(t *testing.T, buckets []ratelimit.BucketRule, change func(*configuration.Config)) *testRateLimitFixture {
	t.Helper()
	cfg := configuration.New()
	cfg.BouncerEnabled = true
	cfg.BouncerRemediationHeadersCustomName = "X-Remediation"
	cfg.RateLimitEnabled = true
	cfg.RateLimitBuckets = buckets
	if change != nil {
		change(cfg)
	}
	next := &recordedNextRequest{}
	b, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next.called = true }), "edge", cfg, false, false, false, false, logger.New("ERROR", ""))
	if err != nil {
		t.Fatal(err)
	}
	b.banTemplate = template.Must(template.New("ban").Parse("banned reason={{.RemediationReason}}"))
	b.banTemplateContentType = "text/html; charset=utf-8"
	lapiClient, store := lapi.NewTestClient(b.log)
	lapi.AttachTestMetricsReporter(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	bindTestLAPI(b, lapiClient)
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	b.AttachRateLimit(counter)
	return &testRateLimitFixture{b: b, counter: counter, lapiClient: lapiClient, next: next, store: store}
}

// bindCountingAppSec binds an AppSec client that allows every request and returns how many it answered.
func (fixture *testRateLimitFixture) bindCountingAppSec(t *testing.T) *atomic.Int64 {
	t.Helper()
	var queries atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	bindTestAppSec(fixture.b, appsec.NewTestClient(serverURL, server.Client(), logger.New("ERROR", "")))
	return &queries
}

// serve runs the whole ServeHTTP for method target from clientIP. next.called is reset first.
func (fixture *testRateLimitFixture) serve(method, target, clientIP string) *httptest.ResponseRecorder {
	fixture.next.called = false
	req := httptest.NewRequest(method, "http://example.com"+target, nil)
	req.RemoteAddr = clientIP + ":1"
	rw := httptest.NewRecorder()
	fixture.b.ServeHTTP(rw, req)
	return rw
}

// TestRateLimit_denyAnswersWithStatusRetryAfterAndHeader proves the deny response: rateLimitStatusCode,
// the ban template with RATE_LIMIT, Retry-After, Cache-Control, the header, and one drop.
func TestRateLimit_denyAnswersWithStatusRetryAfterAndHeader(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("login", 1)}, nil)
	if rw := fixture.serve(http.MethodGet, "/login", testRateLimitClientIP); !fixture.next.called || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("first request must pass without a header, got %d %q", rw.Code, rw.Header().Get("X-Remediation"))
	}
	rw := fixture.serve(http.MethodGet, "/login", testRateLimitClientIP)
	if fixture.next.called || rw.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status %d next=%v, want 429", rw.Code, fixture.next.called)
	}
	if rw.Body.String() != "banned reason="+configuration.ReasonRateLimit {
		t.Fatalf("body=%q", rw.Body.String())
	}
	if got := rw.Header().Get("Retry-After"); got != "8" {
		t.Fatalf("Retry-After=%q want 8: the counter's 7.3s rounded up", got)
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:ratelimit:login" {
		t.Fatalf("X-Remediation=%q", got)
	}
	if got := rw.Header().Get("Cache-Control"); got != "no-cache, no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("login"), "ipv4", "ban"); got != 1 {
		t.Fatalf("dropped plugin:ratelimit:login=%d want 1", got)
	}
	if got := fixture.lapiClient.TestProcessedCount("ipv4"); got != 2 {
		t.Fatalf("processed=%d want 2: the step must not count processed again", got)
	}
	if rw := fixture.serve(http.MethodGet, "/login", "198.51.100.21"); !fixture.next.called {
		t.Fatalf("another client address must not be limited by that counter, got %d", rw.Code)
	}
}

// TestRateLimit_statusAndHeadersSettings proves rateLimitStatusCode is separate from the ban status,
// rateLimitResponseHeaders false sends no Retry-After, and a HEAD deny has no body.
func TestRateLimit_statusAndHeadersSettings(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("login", 1)}, func(cfg *configuration.Config) {
		cfg.BouncerRemediationStatusCode = http.StatusForbidden
		cfg.RateLimitStatusCode = http.StatusServiceUnavailable
		cfg.RateLimitResponseHeaders = false
	})
	lapi.SeedLiveSnapshotForTest(fixture.store, "198.51.100.66", decisionscope.BannedValue, "crowdsec", 60)
	fixture.serve(http.MethodHead, "/", testRateLimitClientIP)
	rw := fixture.serve(http.MethodHead, "/", testRateLimitClientIP)
	if rw.Code != http.StatusServiceUnavailable || rw.Body.Len() != 0 {
		t.Fatalf("HEAD deny: status %d body %q, want 503 and no body", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("Retry-After"); got != "" {
		t.Fatalf("Retry-After=%q with rateLimitResponseHeaders false", got)
	}
	if rw := fixture.serve(http.MethodGet, "/", "198.51.100.66"); rw.Code != http.StatusForbidden {
		t.Fatalf("a LAPI ban must keep bouncerRemediationStatusCode, got %d", rw.Code)
	}
}

// TestRateLimit_requestsThatNeverReachTheStepAreNotCharged proves a LAPI ban and a trusted client are not charged.
func TestRateLimit_requestsThatNeverReachTheStepAreNotCharged(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, func(cfg *configuration.Config) {
		cfg.BouncerClientTrustedIPs = []string{"198.51.100.77"}
	})
	lapi.SeedLiveSnapshotForTest(fixture.store, testRateLimitClientIP, decisionscope.BannedValue, "crowdsec", 60)
	for range 3 {
		if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); rw.Header().Get("X-Remediation") != "ban:lapi:crowdsec" {
			t.Fatalf("LAPI ban: header %q", rw.Header().Get("X-Remediation"))
		}
		if fixture.serve(http.MethodGet, "/", "198.51.100.77"); !fixture.next.called {
			t.Fatal("a trusted client must reach the backend")
		}
	}
	if got := fixture.counter.takes.Load(); got != 0 {
		t.Fatalf("counter charged %d times, want 0", got)
	}
}

// TestRateLimit_deniedRequestDoesNotReachAppsec proves the step runs before AppSec.
func TestRateLimit_deniedRequestDoesNotReachAppsec(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	queries := fixture.bindCountingAppSec(t)
	fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
	if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status %d want 429", rw.Code)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("AppSec queried %d times, want 1 (the denied request must not reach it)", got)
	}
}

// TestRateLimit_captchaRuleComesAfterTheRateLimit proves a deny wins over a matching captcha rule and warns that it lost.
func TestRateLimit_captchaRuleComesAfterTheRateLimit(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	fixture.b.actionRules = mustPathAction(t, "site-captcha", "^/", httprule.ActionCaptcha)
	bindTestCaptcha(fixture.b, testCaptchaClient(t, "/fast.js", "", "", nil))
	log, sink := newTestLogSink(slog.LevelWarn)
	fixture.b.log = log
	if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); rw.Header().Get("X-Remediation") != "captcha:rules" {
		t.Fatalf("first request: header %q want captcha:rules", rw.Header().Get("X-Remediation"))
	}
	rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
	if rw.Code != http.StatusTooManyRequests || rw.Header().Get("X-Remediation") != "ban:ratelimit:per-ip" {
		t.Fatalf("second request: %d %q want the rate-limit deny", rw.Code, rw.Header().Get("X-Remediation"))
	}
	if logged := sink.String(); !strings.Contains(logged, `"msg":"warnCaptchaSuperseded"`) || !strings.Contains(logged, `"name":"site-captcha"`) {
		t.Fatalf("want WARN warnCaptchaSuperseded naming site-captcha, got %s", logged)
	}
}

// TestRateLimit_actionRuleSkips proves bypassRateLimit skips only the rate limit and bypass does not skip it.
func TestRateLimit_actionRuleSkips(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	fixture.b.actionRules = mustCompileActions(t, []httprule.ActionRule{
		{Name: "health", Action: []string{httprule.ActionBypassRateLimit}, Rule: httprule.Rule{Path: "^/health$"}},
		{Name: "api", Action: []string{httprule.ActionBypass}, Rule: httprule.Rule{Path: "^/api/"}},
	})
	queries := fixture.bindCountingAppSec(t)
	lapi.SeedLiveSnapshotForTest(fixture.store, "198.51.100.66", decisionscope.BannedValue, "crowdsec", 60)
	for request := range 3 {
		if fixture.serve(http.MethodGet, "/health", testRateLimitClientIP); !fixture.next.called {
			t.Fatalf("bypassRateLimit request %d must reach the backend", request)
		}
	}
	if got := fixture.counter.takes.Load(); got != 0 {
		t.Fatalf("bypassRateLimit charged the counter %d times", got)
	}
	if got := queries.Load(); got != 3 {
		t.Fatalf("AppSec queried %d times on bypassRateLimit, want 3", got)
	}
	if rw := fixture.serve(http.MethodGet, "/health", "198.51.100.66"); rw.Header().Get("X-Remediation") != "ban:lapi:crowdsec" {
		t.Fatalf("LAPI must still run on bypassRateLimit, got %q", rw.Header().Get("X-Remediation"))
	}
	fixture.serve(http.MethodGet, "/api/items", "198.51.100.30")
	if rw := fixture.serve(http.MethodGet, "/api/items", "198.51.100.30"); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("bypass must not skip the rate limit, got %d", rw.Code)
	}
}

// TestRateLimit_logBucketNeverDenies proves a log bucket logs INFO over its limit, sets no header, and drops nothing.
func TestRateLimit_logBucketNeverDenies(t *testing.T) {
	logBucket := perIPTestBucket("dry-run", 1)
	logBucket.Action = ratelimit.ActionLog
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{logBucket}, nil)
	log, sink := newTestLogSink(slog.LevelInfo)
	fixture.b.log = log
	for request := range 3 {
		if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); !fixture.next.called || rw.Header().Get("X-Remediation") != "" {
			t.Fatalf("request %d: next=%v header %q", request, fixture.next.called, rw.Header().Get("X-Remediation"))
		}
	}
	if got := strings.Count(sink.String(), `"msg":"`+msgRateLimitExceeded+`"`); got != 2 {
		t.Fatalf("INFO %q logged %d times, want 2: %s", msgRateLimitExceeded, got, sink.String())
	}
	for _, attr := range []string{`"bucket":"dry-run"`, `"requests":1`, `"window":"1m0s"`, `"ip":"` + testRateLimitClientIP + `"`} {
		if !strings.Contains(sink.String(), attr) {
			t.Fatalf("INFO line lacks %s: %s", attr, sink.String())
		}
	}
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("dry-run"), "ipv4", "ban"); got != 0 {
		t.Fatalf("a log bucket counted %d drops", got)
	}
	if got := fixture.lapiClient.TestProcessedCount("ipv4"); got != 3 {
		t.Fatalf("processed=%d want 3", got)
	}
}

// TestRateLimit_failureActions proves each rateLimitFailureAction when the counter errors, with its header and drop.
func TestRateLimit_failureActions(t *testing.T) {
	for _, tc := range []struct {
		name              string
		action            string
		captcha           bool
		bypassCaptchaRule bool
		wantNext          bool
		wantStatus        int
		wantHeader        string
		wantDrop          string
	}{
		{name: "passthrough", action: configuration.FailureActionPassthrough, wantNext: true, wantStatus: http.StatusOK},
		{name: "empty is passthrough", action: "", wantNext: true, wantStatus: http.StatusOK},
		{name: "ban", action: configuration.FailureActionBan, wantStatus: http.StatusForbidden, wantHeader: "ban:ratelimit-failure", wantDrop: "ban"},
		{name: "captcha", action: configuration.FailureActionCaptcha, captcha: true, wantStatus: http.StatusOK, wantHeader: "captcha:ratelimit-failure", wantDrop: "captcha"},
		{name: "captcha with bypassCaptcha", action: configuration.FailureActionCaptcha, captcha: true, bypassCaptchaRule: true, wantNext: true, wantStatus: http.StatusOK},
		{name: "captcha without a captcha client", action: configuration.FailureActionCaptcha, wantStatus: http.StatusForbidden, wantHeader: "ban:captcha-downgrade", wantDrop: "ban"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 100)}, func(cfg *configuration.Config) {
				cfg.RateLimitFailureAction = tc.action
			})
			fixture.counter.err = errors.New("redis: unreachable")
			if tc.captcha {
				bindTestCaptcha(fixture.b, testCaptchaClient(t, "/fast.js", "", "", nil))
			}
			if tc.bypassCaptchaRule {
				fixture.b.actionRules = mustPathAction(t, "all", "^/", httprule.ActionBypassCaptcha)
			}
			log, sink := newTestLogSink(slog.LevelDebug)
			fixture.b.log = log
			rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
			if fixture.next.called != tc.wantNext || rw.Code != tc.wantStatus || rw.Header().Get("X-Remediation") != tc.wantHeader {
				t.Fatalf("next=%v status=%d header=%q, want next=%v status=%d header=%q", fixture.next.called, rw.Code, rw.Header().Get("X-Remediation"), tc.wantNext, tc.wantStatus, tc.wantHeader)
			}
			assertRateLimitFailureDrop(t, fixture.lapiClient, tc.wantDrop)
			assertRateLimitFailureLoggedAtDebug(t, sink.String(), tc.wantHeader == "ban:captcha-downgrade")
		})
	}
}

// assertRateLimitFailureDrop expects one plugin:ratelimit_failure drop of remediation wantDrop, and none
// of the other remediation. Empty wantDrop expects no drop at all.
func assertRateLimitFailureDrop(t *testing.T, lapiClient *lapi.Client, wantDrop string) {
	t.Helper()
	for _, remediation := range []string{"ban", "captcha"} {
		want := int64(0)
		if remediation == wantDrop {
			want = 1
		}
		if got := lapiClient.TestDroppedCount(lapi.OriginPluginRateLimitFailure, "ipv4", remediation); got != want {
			t.Fatalf("dropped %s/%s=%d want %d", lapi.OriginPluginRateLimitFailure, remediation, got, want)
		}
	}
}

// assertRateLimitFailureLoggedAtDebug expects DEBUG serveRateLimit with the counter error and no ERROR.
// WARN is allowed only for the captcha downgrade, which warns that the router has no captcha.
func assertRateLimitFailureLoggedAtDebug(t *testing.T, logged string, captchaDowngrade bool) {
	t.Helper()
	if !strings.Contains(logged, `"msg":"serveRateLimit"`) || !strings.Contains(logged, `"error":"bucket per-ip: redis: unreachable"`) {
		t.Fatalf("want DEBUG serveRateLimit with the error, got %s", logged)
	}
	if strings.Contains(logged, `"level":"ERROR"`) || (!captchaDowngrade && strings.Contains(logged, `"level":"WARN"`)) {
		t.Fatalf("a counter error must not log WARN or ERROR per request: %s", logged)
	}
}

// TestRateLimit_blockingCounterReturnsWithinTheBudget proves a counter that never answers costs at most the step budget.
func TestRateLimit_blockingCounterReturnsWithinTheBudget(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 100)}, func(cfg *configuration.Config) {
		cfg.RateLimitFailureAction = configuration.FailureActionPassthrough
	})
	fixture.counter.block = true
	started := time.Now()
	fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
	if elapsed := time.Since(started); elapsed > ratelimit.StepBudget+150*time.Millisecond {
		t.Fatalf("step took %s, budget %s", elapsed, ratelimit.StepBudget)
	}
	if !fixture.next.called {
		t.Fatal("passthrough must reach the backend after the budget")
	}
}

// TestRateLimit_offLeavesThePathUnchanged proves a router without a counter, or with the leg disabled, charges nothing.
func TestRateLimit_offLeavesThePathUnchanged(t *testing.T) {
	noCounter := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	noCounter.b.AttachRateLimit(nil)
	disabled := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, func(cfg *configuration.Config) {
		cfg.RateLimitEnabled = false
	})
	for _, fixture := range []*testRateLimitFixture{noCounter, disabled} {
		for request := range 3 {
			if fixture.serve(http.MethodGet, "/", testRateLimitClientIP); !fixture.next.called {
				t.Fatalf("request %d must reach the backend", request)
			}
		}
	}
	if got := disabled.counter.takes.Load(); got != 0 {
		t.Fatalf("a disabled leg charged the counter %d times", got)
	}
}
