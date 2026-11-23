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
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// testRateLimitClientIP is the client address every rate-limit request comes from unless a test says otherwise.
const testRateLimitClientIP = "198.51.100.20"

// testRateLimitRetryAfter is the RetryAfter testRateLimitCounter returns over the limit; Retry-After must round it up to 8.
const testRateLimitRetryAfter = 7*time.Second + 300*time.Millisecond

// testRateLimitCounter is an in-memory ratelimit.Counter. err makes every Take fail; block makes every
// Take wait for its context. A Take over the limit carries testRateLimitRetryAfter.
type testRateLimitCounter struct {
	block  bool
	counts map[string]int64
	err    error
	takes  atomic.Int64
}

// Take counts one hit on key and reports whether the count is within limit.
func (counter *testRateLimitCounter) Take(ctx context.Context, key string, limit ratelimit.Limit) (ratelimit.Status, error) {
	counter.takes.Add(1)
	if counter.block {
		<-ctx.Done()
		return ratelimit.Status{}, ctx.Err()
	}
	if counter.err != nil {
		return ratelimit.Status{}, counter.err
	}
	counter.counts[key]++
	status := ratelimit.Status{Allowed: counter.counts[key] <= limit.Requests}
	if !status.Allowed {
		status.RetryAfter = testRateLimitRetryAfter
	}
	return status, nil
}

// testRateLimitFixture is one router bound to a rate-limit client over an in-memory counter, and a
// stream LAPI client that counts usage metrics.
type testRateLimitFixture struct {
	b          *Bouncer
	counter    *testRateLimitCounter
	lapiClient *lapi.Client
	next       *recordedNextRequest
	store      *decisionstore.Store
}

// testRateLimitOwnerSettings is the Settings an owner with cfg opens: its buckets and its policy.
func testRateLimitOwnerSettings(cfg *configuration.Config) ratelimit.Settings {
	return ratelimit.Settings{
		Buckets: cfg.RateLimitBuckets,
		Policy: ratelimit.Policy{
			FailureAction:   configuration.EffectiveRateLimitFailureAction(cfg.RateLimitFailureAction),
			ResponseHeaders: cfg.RateLimitResponseHeaders,
			StatusCode:      cfg.RateLimitStatusCode,
		},
	}
}

// newTestRateLimitClient is a rate-limit client over counter with the buckets and policy of an owner with cfg.
func newTestRateLimitClient(t *testing.T, cfg *configuration.Config, counter ratelimit.Counter) *ratelimit.Client {
	t.Helper()
	client, err := ratelimit.NewTestClient(testRateLimitOwnerSettings(cfg), counter)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// newTestRateLimitRoute builds router name through New, subscribed to the rate limit, with a ban template.
func newTestRateLimitRoute(t *testing.T, name string, cfg *configuration.Config, next *recordedNextRequest) *Bouncer {
	t.Helper()
	b, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next.called = true }), name, cfg, Subscriptions{RateLimit: true}, logger.New("ERROR"))
	if err != nil {
		t.Fatal(err)
	}
	b.banTemplate = template.Must(template.New("ban").Parse("banned reason={{.RemediationReason}}"))
	b.banTemplateContentType = "text/html; charset=utf-8"
	return b
}

// perIPTestBucket is a catch-all ratelimit bucket that allows requests per minute per client address.
func perIPTestBucket(name string, requests int) ratelimit.BucketRule {
	return ratelimit.BucketRule{Name: name, Requests: requests, Window: "1m", Key: []ratelimit.KeyPart{{From: ratelimit.KeyFromIP}}}
}

// newTestRateLimitConfig is a bouncing router config whose rateLimit* settings are also the owner's.
func newTestRateLimitConfig(buckets []ratelimit.BucketRule, change func(*configuration.Config)) *configuration.Config {
	cfg := configuration.New()
	cfg.BouncerEnabled = true
	cfg.BouncerRemediationHeadersCustomName = "X-Remediation"
	cfg.RateLimitEnabled = true
	cfg.RateLimitBuckets = buckets
	if change != nil {
		change(cfg)
	}
	return cfg
}

// newTestRateLimitFixture builds router edge through New and binds it to a rate-limit client whose
// buckets and policy come from the same config, the way one middleware that owns and charges runs.
func newTestRateLimitFixture(t *testing.T, buckets []ratelimit.BucketRule, change func(*configuration.Config)) *testRateLimitFixture {
	t.Helper()
	cfg := newTestRateLimitConfig(buckets, change)
	next := &recordedNextRequest{}
	b := newTestRateLimitRoute(t, "edge", cfg, next)
	lapiClient, store := lapi.NewTestClient(b.log)
	lapi.AttachTestMetricsReporter(lapiClient)
	lapiClient.SetStreamHealthyForTest(true)
	bindTestLAPI(b, lapiClient)
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	bindTestRateLimit(b, newTestRateLimitClient(t, cfg, counter))
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
	bindTestAppSec(fixture.b, appsec.NewTestClient(serverURL, server.Client(), logger.New("ERROR")))
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

// TestRateLimit_ratelimitAnswersWithStatusRetryAfterAndHeader proves the ratelimit answer: rateLimitStatusCode,
// the ban template with RATE_LIMIT, Retry-After, Cache-Control, the header, and one drop.
func TestRateLimit_ratelimitAnswersWithStatusRetryAfterAndHeader(t *testing.T) {
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
// rateLimitResponseHeaders false sends no Retry-After, and a HEAD ratelimit answer has no body.
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
		t.Fatalf("HEAD ratelimit answer: status %d body %q, want 503 and no body", rw.Code, rw.Body.String())
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

// TestRateLimit_answeredRequestDoesNotReachAppsec proves the step runs before AppSec.
func TestRateLimit_answeredRequestDoesNotReachAppsec(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	queries := fixture.bindCountingAppSec(t)
	fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
	if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status %d want 429", rw.Code)
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("AppSec queried %d times, want 1 (the answered request must not reach it)", got)
	}
}

// TestRateLimit_captchaRuleComesAfterTheRateLimit proves a ratelimit answer wins over a matching captcha rule and warns that it lost.
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
		t.Fatalf("second request: %d %q want the ratelimit answer", rw.Code, rw.Header().Get("X-Remediation"))
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

// TestRateLimit_logBucketNeverAnswers proves a log bucket logs INFO over its limit, sets no header, and drops nothing.
func TestRateLimit_logBucketNeverAnswers(t *testing.T) {
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
			assertRateLimitFailureLoggedAtDebug(t, sink.String())
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

// assertRateLimitFailureLoggedAtDebug expects DEBUG serveRateLimit with the counter error and no WARN or
// ERROR, the captcha downgrade on a router without a captcha included.
func assertRateLimitFailureLoggedAtDebug(t *testing.T, logged string) {
	t.Helper()
	if !strings.Contains(logged, `"msg":"serveRateLimit"`) || !strings.Contains(logged, `"error":"bucket per-ip: redis: unreachable"`) {
		t.Fatalf("want DEBUG serveRateLimit with the error, got %s", logged)
	}
	if strings.Contains(logged, `"level":"ERROR"`) || strings.Contains(logged, `"level":"WARN"`) {
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

// TestRateLimit_offLeavesThePathUnchanged proves a router that does not subscribe to the rate limit, and
// one whose owner is not published, pass every request with no header, no drop, and no charge.
func TestRateLimit_offLeavesThePathUnchanged(t *testing.T) {
	unsubscribed := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	bindTestRateLimit(unsubscribed.b, nil)
	unpublished := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	unpublished.b.ReceiveRateLimit(reclaim.Published{Value: (*ratelimit.Client)(nil)})
	if !unpublished.b.rateLimitLeg.subscribed || unpublished.b.loadedRateLimit() != nil {
		t.Fatal("the unpublished fixture must stay subscribed with no client")
	}
	for _, fixture := range []*testRateLimitFixture{unsubscribed, unpublished} {
		for request := range 3 {
			if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); !fixture.next.called || rw.Header().Get("X-Remediation") != "" {
				t.Fatalf("request %d: next=%v header %q, want the backend and no header", request, fixture.next.called, rw.Header().Get("X-Remediation"))
			}
		}
		if got := fixture.counter.takes.Load(); got != 0 {
			t.Fatalf("charged the counter %d times, want 0", got)
		}
		if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("per-ip"), "ipv4", "ban"); got != 0 {
			t.Fatalf("counted %d drops, want 0", got)
		}
	}
}

// TestRateLimit_subscribersKeepSeparateCounters proves two routers bound to one rate-limit client charge
// its buckets under their own names, so each has its own budget.
func TestRateLimit_subscribersKeepSeparateCounters(t *testing.T) {
	cfg := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	client := newTestRateLimitClient(t, cfg, counter)
	nextA, nextB := &recordedNextRequest{}, &recordedNextRequest{}
	appA := &testRateLimitFixture{b: newTestRateLimitRoute(t, "app-a", cfg, nextA), counter: counter, next: nextA}
	appB := &testRateLimitFixture{b: newTestRateLimitRoute(t, "app-b", cfg, nextB), counter: counter, next: nextB}
	bindTestRateLimit(appA.b, client)
	bindTestRateLimit(appB.b, client)

	appA.serve(http.MethodGet, "/", testRateLimitClientIP)
	if rw := appA.serve(http.MethodGet, "/", testRateLimitClientIP); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("app-a second request: status %d, want 429", rw.Code)
	}
	if appB.serve(http.MethodGet, "/", testRateLimitClientIP); !appB.next.called {
		t.Fatal("app-b first request must reach the backend: subscribers keep separate counters")
	}
	for key := range counter.counts {
		if !strings.HasPrefix(key, "rl:app-a:per-ip:") && !strings.HasPrefix(key, "rl:app-b:per-ip:") {
			t.Fatalf("counter key %q, want rl:<subscriber>:per-ip:<hash>", key)
		}
	}
	if len(counter.counts) != 2 {
		t.Fatalf("counter keys %v, want one per subscriber", counter.counts)
	}
}

// TestRateLimit_ownerPolicyAnswersOnSubscriber proves a subscriber answers with the owner's status code,
// Retry-After switch, and failure action, not with its own rateLimit* settings.
func TestRateLimit_ownerPolicyAnswersOnSubscriber(t *testing.T) {
	owner := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, func(cfg *configuration.Config) {
		cfg.RateLimitStatusCode = http.StatusServiceUnavailable
		cfg.RateLimitFailureAction = configuration.FailureActionPassthrough
	})
	subscriberConfig := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 100)}, func(cfg *configuration.Config) {
		cfg.RateLimitEnabled = false
		cfg.RateLimitStatusCode = http.StatusTeapot
		cfg.RateLimitResponseHeaders = false
		cfg.RateLimitFailureAction = configuration.FailureActionBan
	})
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	next := &recordedNextRequest{}
	subscriber := &testRateLimitFixture{b: newTestRateLimitRoute(t, "app-a", subscriberConfig, next), counter: counter, next: next}
	bindTestRateLimit(subscriber.b, newTestRateLimitClient(t, owner, counter))

	subscriber.serve(http.MethodGet, "/", testRateLimitClientIP)
	rw := subscriber.serve(http.MethodGet, "/", testRateLimitClientIP)
	if rw.Code != http.StatusServiceUnavailable || rw.Header().Get("Retry-After") != "8" {
		t.Fatalf("over the owner's limit: status %d Retry-After %q, want 503 and 8", rw.Code, rw.Header().Get("Retry-After"))
	}
	counter.err = errors.New("redis: unreachable")
	if rw := subscriber.serve(http.MethodGet, "/", "198.51.100.21"); !subscriber.next.called || rw.Header().Get("X-Remediation") != "" {
		t.Fatalf("counter error: next=%v header %q, want the owner's passthrough", subscriber.next.called, rw.Header().Get("X-Remediation"))
	}
}

// TestRateLimit_ownerUnavailableLogsOnTransitions proves a subscriber logs one WARN when its rate-limit owner
// stops being published and one INFO when a client binds again, never per request, while requests pass
// uncharged. "publish first" is the compiled-Go order (Watch skips the first typed nil); "empty first" is the
// Yaegi order, where Watch delivers the typed nil to a subscriber that starts before its owner.
func TestRateLimit_ownerUnavailableLogsOnTransitions(t *testing.T) {
	t.Run("publish first", func(t *testing.T) { checkRateLimitOwnerTransitions(t, false) })
	t.Run("empty first", func(t *testing.T) { checkRateLimitOwnerTransitions(t, true) })
}

// checkRateLimitOwnerTransitions runs subscriber app-a of instance shared through before the owner (an empty
// delivery when emptyFirst), first bind, owner removed with requests, and owner restored, checking the owner
// WARN / INFO counts after each step.
func checkRateLimitOwnerTransitions(t *testing.T, emptyFirst bool) {
	t.Helper()
	ResetRateLimitOwnerWarningsForTest()
	t.Cleanup(ResetRateLimitOwnerWarningsForTest)
	cfg := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, func(cfg *configuration.Config) {
		cfg.RateLimitEnabled = false
		cfg.RateLimitInstanceName = "shared"
	})
	next := &recordedNextRequest{}
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	fixture := &testRateLimitFixture{b: newTestRateLimitRoute(t, "app-a", cfg, next), counter: counter, next: next}
	log, sink := newTestLogSink(slog.LevelDebug)
	// bouncer.New adds traefikName with log.With; replace the logger the same way.
	fixture.b.log = log.With("traefikName", fixture.b.name)
	owner := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	empty := reclaim.Published{Value: (*ratelimit.Client)(nil)}

	// Before any owner: Yaegi delivers the typed nil and warns once; Go delivers nothing.
	wantWarn := 0
	if emptyFirst {
		fixture.b.ReceiveRateLimit(empty)
		wantWarn = 1
	}
	assertRateLimitOwnerLines(t, sink, "before the owner", wantWarn, 0)

	// The first bind ends a WARN with one INFO; without a WARN it logs nothing.
	fixture.b.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	assertRateLimitOwnerLines(t, sink, "first bind", wantWarn, wantWarn)

	// The owner goes away: one WARN however often the empty value is delivered or requests arrive.
	fixture.b.ReceiveRateLimit(empty)
	fixture.b.ReceiveRateLimit(empty)
	for range 3 {
		if rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP); !fixture.next.called || rw.Header().Get("X-Remediation") != "" {
			t.Fatalf("no owner: next=%v header %q, want the request through", fixture.next.called, rw.Header().Get("X-Remediation"))
		}
	}
	if takes := counter.takes.Load(); takes != 0 {
		t.Fatalf("no owner: charged %d times, want 0", takes)
	}
	assertRateLimitOwnerLines(t, sink, "owner removed", wantWarn+1, wantWarn)

	// The owner returns: one INFO naming the new incarnation; the same client again and a replace log nothing.
	second := newTestRateLimitClient(t, owner, counter)
	fixture.b.ReceiveRateLimit(reclaim.Published{Value: second})
	fixture.b.ReceiveRateLimit(reclaim.Published{Value: second})
	fixture.b.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	assertRateLimitOwnerLines(t, sink, "owner restored", wantWarn+1, wantWarn+1)
	if got := countLogLines(sink.String(), `"msg":"`+msgRateLimitOwnerAvailable+`"`, `"incarnation":"`+second.Incarnation()+`"`); got != 1 {
		t.Fatalf("INFO %q with incarnation %s lines=%d want 1: %s", msgRateLimitOwnerAvailable, second.Incarnation(), got, sink.String())
	}
}

// assertRateLimitOwnerLines checks that sink holds wantWarn owner-unavailable WARN lines and wantInfo
// owner-available INFO lines for app-a / shared, and no other WARN line.
func assertRateLimitOwnerLines(t *testing.T, sink *syncLogSink, step string, wantWarn, wantInfo int) {
	t.Helper()
	assertRateLimitOwnerLinesOf(t, sink, step, "app-a", "shared", wantWarn, wantInfo)
	if got := countLogLines(sink.String(), `"level":"WARN"`); got != wantWarn {
		t.Fatalf("%s: WARN lines=%d want %d: %s", step, got, wantWarn, sink.String())
	}
}

// assertRateLimitOwnerLinesOf checks that sink holds wantWarn owner-unavailable WARN lines and wantInfo
// owner-available INFO lines naming router traefikName and rate-limit instance instanceName.
func assertRateLimitOwnerLinesOf(t *testing.T, sink *syncLogSink, step, traefikName, instanceName string, wantWarn, wantInfo int) {
	t.Helper()
	logged := sink.String()
	ownerAttrs := []string{`"traefikName":"` + traefikName + `"`, `"instanceName":"` + instanceName + `"`}
	if got := countLogLines(logged, append([]string{`"level":"WARN"`, `"msg":"` + msgRateLimitOwnerUnavailable + `"`}, ownerAttrs...)...); got != wantWarn {
		t.Fatalf("%s: %s/%s WARN %q lines=%d want %d: %s", step, traefikName, instanceName, msgRateLimitOwnerUnavailable, got, wantWarn, logged)
	}
	if got := countLogLines(logged, append([]string{`"level":"INFO"`, `"msg":"` + msgRateLimitOwnerAvailable + `"`}, ownerAttrs...)...); got != wantInfo {
		t.Fatalf("%s: %s/%s INFO %q lines=%d want %d: %s", step, traefikName, instanceName, msgRateLimitOwnerAvailable, got, wantInfo, logged)
	}
}

// newTestRateLimitSubscriber builds router traefikName through New, the way a Traefik reload builds it: a new
// Bouncer subscribed to rate-limit instance instanceName, logging to log, with no client yet.
func newTestRateLimitSubscriber(t *testing.T, traefikName, instanceName string, log *slog.Logger) *Bouncer {
	t.Helper()
	cfg := newTestRateLimitConfig(nil, func(cfg *configuration.Config) {
		cfg.RateLimitEnabled = false
		cfg.RateLimitInstanceName = instanceName
	})
	b, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), traefikName, cfg, Subscriptions{RateLimit: true}, log)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRateLimit_ownerWarningOutlivesTheRebuiltSubscriber proves the owner-unavailable WARN is pending per router
// name, not per Bouncer: a Traefik reload rebuilds a subscriber as a new Bouncer, and the new one neither repeats
// the WARN its previous instance logged nor misses the INFO that answers it.
func TestRateLimit_ownerWarningOutlivesTheRebuiltSubscriber(t *testing.T) {
	ResetRateLimitOwnerWarningsForTest()
	t.Cleanup(ResetRateLimitOwnerWarningsForTest)
	log, sink := newTestLogSink(slog.LevelDebug)
	owner := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	empty := reclaim.Published{Value: (*ratelimit.Client)(nil)}

	// The owner goes away: the bound instance of app-a warns.
	first := newTestRateLimitSubscriber(t, "app-a", "shared", log)
	first.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	first.ReceiveRateLimit(empty)
	assertRateLimitOwnerLinesOf(t, sink, "owner removed", "app-a", "shared", 1, 0)

	// A reload rebuilds app-a while the owner is still gone: its empty first delivery (Yaegi) is the same outage.
	rebuiltWithoutOwner := newTestRateLimitSubscriber(t, "app-a", "shared", log)
	rebuiltWithoutOwner.ReceiveRateLimit(empty)
	assertRateLimitOwnerLinesOf(t, sink, "rebuilt without the owner", "app-a", "shared", 1, 0)

	// The reload that restores the owner builds app-a after it: the new Bouncer's first bind answers the WARN.
	restored := newTestRateLimitClient(t, owner, counter)
	rebuiltAfterOwner := newTestRateLimitSubscriber(t, "app-a", "shared", log)
	rebuiltAfterOwner.ReceiveRateLimit(reclaim.Published{Value: restored})
	assertRateLimitOwnerLinesOf(t, sink, "rebuilt after the owner", "app-a", "shared", 1, 1)
	if got := countLogLines(sink.String(), `"msg":"`+msgRateLimitOwnerAvailable+`"`, `"incarnation":"`+restored.Incarnation()+`"`); got != 1 {
		t.Fatalf("INFO %q with incarnation %s lines=%d want 1: %s", msgRateLimitOwnerAvailable, restored.Incarnation(), got, sink.String())
	}

	// The INFO ended the outage for every instance of app-a: a later bind logs nothing, the next loss warns again.
	rebuiltWithoutOwner.ReceiveRateLimit(reclaim.Published{Value: restored})
	assertRateLimitOwnerLinesOf(t, sink, "older instance binds", "app-a", "shared", 1, 1)
	rebuiltAfterOwner.ReceiveRateLimit(empty)
	assertRateLimitOwnerLinesOf(t, sink, "second outage", "app-a", "shared", 2, 1)
}

// TestRateLimit_ownerWarningIsPendingPerRouterName proves routers with different names keep separate pending
// WARN lines, a router rebuilt on another instance name warns for that instance and answers the router's WARN
// when it binds, and a router rebuilt without the rate limit drops its pending WARN without a line.
func TestRateLimit_ownerWarningIsPendingPerRouterName(t *testing.T) {
	ResetRateLimitOwnerWarningsForTest()
	t.Cleanup(ResetRateLimitOwnerWarningsForTest)
	log, sink := newTestLogSink(slog.LevelDebug)
	owner := newTestRateLimitConfig([]ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, nil)
	counter := &testRateLimitCounter{counts: map[string]int64{}}
	empty := reclaim.Published{Value: (*ratelimit.Client)(nil)}

	// Two router names lose the same owner: one WARN each; binding one answers only that one.
	appA := newTestRateLimitSubscriber(t, "app-a", "shared", log)
	appB := newTestRateLimitSubscriber(t, "app-b", "shared", log)
	appA.ReceiveRateLimit(empty)
	appB.ReceiveRateLimit(empty)
	appB.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	assertRateLimitOwnerLinesOf(t, sink, "app-b restored", "app-a", "shared", 1, 0)
	assertRateLimitOwnerLinesOf(t, sink, "app-b restored", "app-b", "shared", 1, 1)

	// app-a is rebuilt on instance other, also unpublished: the WARN names the instance it now misses.
	renamed := newTestRateLimitSubscriber(t, "app-a", "other", log)
	renamed.ReceiveRateLimit(empty)
	assertRateLimitOwnerLinesOf(t, sink, "renamed while warned", "app-a", "other", 1, 0)

	// other publishes: the INFO answers app-a, and the pending WARN on shared does not outlive it.
	renamed.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	assertRateLimitOwnerLinesOf(t, sink, "renamed bound", "app-a", "other", 1, 1)
	backOnShared := newTestRateLimitSubscriber(t, "app-a", "shared", log)
	backOnShared.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	assertRateLimitOwnerLinesOf(t, sink, "back on shared", "app-a", "shared", 1, 0)

	// app-a warns again, then a reload builds it without the rate limit: the WARN is dropped, so no INFO later.
	backOnShared.ReceiveRateLimit(empty)
	if _, err := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "app-a", configuration.New(), Subscriptions{}, log); err != nil {
		t.Fatal(err)
	}
	resubscribed := newTestRateLimitSubscriber(t, "app-a", "shared", log)
	resubscribed.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, owner, counter)})
	assertRateLimitOwnerLinesOf(t, sink, "dropped by an unsubscribed rebuild", "app-a", "shared", 2, 0)
}
