package bouncer

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/captcha"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/configuration"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/lapi"
	logger "github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/ratelimit"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// testCaptchaWidgetAsset is the same-origin widget asset of testSiteverifyCaptchaClient.
const testCaptchaWidgetAsset = "/fast.js"

// perIPSoftTestCaptchaBucket is per-ip-soft, a catch-all captcha bucket that allows requests per minute
// per client address.
func perIPSoftTestCaptchaBucket(requests int) ratelimit.BucketRule {
	bucket := perIPTestBucket("per-ip-soft", requests)
	bucket.Action = ratelimit.ActionCaptcha
	return bucket
}

// bindUsableTestCaptcha subscribes the fixture's router to a published, valid custom-provider captcha
// whose provider accepts every token, with widget asset testCaptchaWidgetAsset.
func (fixture *testRateLimitFixture) bindUsableTestCaptcha(t *testing.T) *captcha.Client {
	t.Helper()
	captchaClient := testSiteverifyCaptchaClient(t)
	bindTestCaptcha(fixture.b, captchaClient)
	return captchaClient
}

// bindUnpublishedTestCaptcha subscribes the fixture's router to captcha instance shared-captcha, which no owner publishes.
func (fixture *testRateLimitFixture) bindUnpublishedTestCaptcha() {
	fixture.b.captchaLeg.subscribed = true
	fixture.b.captchaLeg.instanceName = "shared-captcha"
	fixture.b.storeBinding(&fixture.b.captchaLeg.bound, (*captcha.Client)(nil))
}

// serveRequest runs the whole ServeHTTP for req from clientIP. next.called is reset first.
func (fixture *testRateLimitFixture) serveRequest(req *http.Request, clientIP string) *httptest.ResponseRecorder {
	fixture.next.called = false
	req.RemoteAddr = clientIP + ":1"
	rw := httptest.NewRecorder()
	fixture.b.ServeHTTP(rw, req)
	return rw
}

// countedKeysOf lists the counter keys of bucket that were charged at least once.
func (fixture *testRateLimitFixture) countedKeysOf(bucket string) []string {
	var keys []string
	for key := range fixture.counter.counts {
		if strings.Contains(key, ":"+bucket+":") {
			keys = append(keys, key)
		}
	}
	return keys
}

// challengeMarkerPost is a challenge-form POST carrying the marker crowdsec_captcha_challenge=v1.
func challengeMarkerPost() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", strings.NewReader("crowdsec_captcha_challenge=v1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// countLogLines is how many records in logged carry every one of attrs (JSON fragments such as `"msg":"x"`).
func countLogLines(logged string, attrs ...string) int {
	total := 0
	for _, line := range strings.Split(logged, "\n") {
		matched := line != ""
		for _, attr := range attrs {
			matched = matched && strings.Contains(line, attr)
		}
		if matched {
			total++
		}
	}
	return total
}

// TestRateLimit_captchaBucketServesTheChallenge proves a captcha bucket over its limit serves the
// router's challenge page with captcha:ratelimit:<bucket>, counts a captcha drop, and does not warn
// warnCaptchaSuperseded although a captcha action rule also matched.
func TestRateLimit_captchaBucketServesTheChallenge(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1)}, nil)
	fixture.bindUsableTestCaptcha(t)
	fixture.b.actionRules = mustPathAction(t, "site-captcha", "^/api/", httprule.ActionCaptcha)
	log, sink := newTestLogSink(slog.LevelWarn)
	fixture.b.log = log
	if fixture.serve(http.MethodGet, "/", testRateLimitClientIP); !fixture.next.called {
		t.Fatal("first request must reach the backend")
	}
	for _, target := range []string{"/", "/api/items"} {
		rw := fixture.serve(http.MethodGet, target, testRateLimitClientIP)
		if fixture.next.called || rw.Body.String() != "CAPTCHA_CHALLENGE_PAGE" {
			t.Fatalf("%s: next=%v body %q, want the challenge page", target, fixture.next.called, rw.Body.String())
		}
		if got := rw.Header().Get("X-Remediation"); got != "captcha:ratelimit:per-ip-soft" {
			t.Fatalf("%s: X-Remediation=%q want captcha:ratelimit:per-ip-soft", target, got)
		}
	}
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("per-ip-soft"), "ipv4", "captcha"); got != 2 {
		t.Fatalf("captcha drops=%d want 2", got)
	}
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("per-ip-soft"), "ipv4", "ban"); got != 0 {
		t.Fatalf("ban drops=%d want 0", got)
	}
	if strings.Contains(sink.String(), "warnCaptchaSuperseded") {
		t.Fatalf("a captcha answer must not warn warnCaptchaSuperseded: %s", sink.String())
	}
}

// TestRateLimit_captchaBucketWithBypassCaptchaAnswersAsRateLimit proves a bypassCaptcha rule turns a
// captcha bucket over its limit into the ratelimit answer for that bucket, not a pass.
func TestRateLimit_captchaBucketWithBypassCaptchaAnswersAsRateLimit(t *testing.T) {
	fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1)}, nil)
	fixture.bindUsableTestCaptcha(t)
	fixture.b.actionRules = mustPathAction(t, "api", "^/api/", httprule.ActionBypassCaptcha)
	fixture.serve(http.MethodGet, "/api/items", testRateLimitClientIP)
	rw := fixture.serve(http.MethodGet, "/api/items", testRateLimitClientIP)
	if fixture.next.called || rw.Code != http.StatusTooManyRequests || rw.Header().Get("Retry-After") != "8" {
		t.Fatalf("next=%v status %d Retry-After %q, want 429 and 8", fixture.next.called, rw.Code, rw.Header().Get("Retry-After"))
	}
	if got := rw.Header().Get("X-Remediation"); got != "ban:ratelimit:per-ip-soft" {
		t.Fatalf("X-Remediation=%q want ban:ratelimit:per-ip-soft", got)
	}
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("per-ip-soft"), "ipv4", "ban"); got != 1 {
		t.Fatalf("ban drops=%d want 1", got)
	}
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("per-ip-soft"), "ipv4", "captcha"); got != 0 {
		t.Fatalf("captcha drops=%d want 0", got)
	}
}

// TestRateLimit_captchaBucketWithoutUsableCaptcha proves a captcha bucket on a router without a usable
// captcha gives the ratelimit answer (not ban:captcha-downgrade) on every downgraded request, logs DEBUG
// each time, logs the unusable ERROR at most once in the window, and never warns captcha unsubscribed.
func TestRateLimit_captchaBucketWithoutUsableCaptcha(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bind       func(*testing.T, *testRateLimitFixture)
		wantErrors int
	}{
		{name: "no captcha subscription", bind: func(*testing.T, *testRateLimitFixture) {}},
		{name: "subscribed captcha unpublished", bind: func(_ *testing.T, fixture *testRateLimitFixture) { fixture.bindUnpublishedTestCaptcha() }, wantErrors: 1},
		{name: "subscribed captcha not valid", bind: func(_ *testing.T, fixture *testRateLimitFixture) {
			bindTestCaptcha(fixture.b, &captcha.Client{})
			fixture.b.captchaLeg.instanceName = "shared-captcha"
		}, wantErrors: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger.ResetDebounceForTest()
			t.Cleanup(logger.ResetDebounceForTest)
			fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1)}, func(cfg *configuration.Config) {
				cfg.RateLimitInstanceName = "shared"
			})
			tc.bind(t, fixture)
			log, sink := newTestLogSink(slog.LevelDebug)
			// bouncer.New adds traefikName with log.With; this literal route does not go through New.
			fixture.b.log = log.With("traefikName", fixture.b.name)
			fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
			for request := 2; request <= 4; request++ {
				rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
				if fixture.next.called || rw.Code != http.StatusTooManyRequests || rw.Header().Get("X-Remediation") != "ban:ratelimit:per-ip-soft" {
					t.Fatalf("request %d: next=%v status %d header %q, want 429 ban:ratelimit:per-ip-soft", request, fixture.next.called, rw.Code, rw.Header().Get("X-Remediation"))
				}
			}
			logged := sink.String()
			if got := countLogLines(logged, `"level":"ERROR"`, `"msg":"`+msgRateLimitCaptchaUnavailable+`"`, `"reason":"unusable"`, `"traefikName":"edge"`, `"instanceName":"shared"`); got != tc.wantErrors {
				t.Fatalf("unusable ERROR lines=%d want %d: %s", got, tc.wantErrors, logged)
			}
			if got := countLogLines(logged, `"level":"ERROR"`); got != tc.wantErrors {
				t.Fatalf("ERROR lines=%d want %d: %s", got, tc.wantErrors, logged)
			}
			if got := countLogLines(logged, `"level":"DEBUG"`, `"msg":"`+msgRateLimitCaptchaDowngrade+`"`, `"origin":"plugin:ratelimit:per-ip-soft"`); got != 3 {
				t.Fatalf("DEBUG downgrade lines=%d want 3: %s", got, logged)
			}
			if strings.Contains(logged, `"level":"WARN"`) {
				t.Fatalf("a rate-limit captcha downgrade must not WARN (%s): %s", msgCaptchaUnsubscribed, logged)
			}
			if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimit("per-ip-soft"), "ipv4", "ban"); got != 3 {
				t.Fatalf("ban drops=%d want 3", got)
			}
		})
	}
}

// TestRateLimit_failureCaptchaWithoutUsableCaptcha proves the failure action captcha on a router without
// a usable captcha writes ban:captcha-downgrade through the leg's downgrade logging: no WARN captcha
// unsubscribed, DEBUG each request, and the unusable ERROR at most once in the window.
func TestRateLimit_failureCaptchaWithoutUsableCaptcha(t *testing.T) {
	for _, tc := range []struct {
		name       string
		subscribed bool
		wantErrors int
	}{
		{name: "no captcha subscription"},
		{name: "subscribed captcha unpublished", subscribed: true, wantErrors: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger.ResetDebounceForTest()
			t.Cleanup(logger.ResetDebounceForTest)
			fixture := newTestRateLimitFixture(t, []ratelimit.BucketRule{perIPTestBucket("per-ip", 100)}, func(cfg *configuration.Config) {
				cfg.RateLimitFailureAction = configuration.FailureActionCaptcha
			})
			if tc.subscribed {
				fixture.bindUnpublishedTestCaptcha()
			}
			fixture.counter.err = errors.New("redis: unreachable")
			log, sink := newTestLogSink(slog.LevelDebug)
			// bouncer.New adds traefikName with log.With; this literal route does not go through New.
			fixture.b.log = log.With("traefikName", fixture.b.name)
			for request := range 3 {
				rw := fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
				if fixture.next.called || rw.Code != http.StatusForbidden || rw.Header().Get("X-Remediation") != "ban:captcha-downgrade" {
					t.Fatalf("request %d: next=%v status %d header %q, want 403 ban:captcha-downgrade", request, fixture.next.called, rw.Code, rw.Header().Get("X-Remediation"))
				}
			}
			logged := sink.String()
			if got := countLogLines(logged, `"level":"ERROR"`, `"msg":"`+msgRateLimitCaptchaUnavailable+`"`, `"reason":"unusable"`); got != tc.wantErrors {
				t.Fatalf("unusable ERROR lines=%d want %d: %s", got, tc.wantErrors, logged)
			}
			if got := countLogLines(logged, `"msg":"`+msgRateLimitCaptchaDowngrade+`"`, `"origin":"`+lapi.OriginPluginRateLimitFailure+`"`); got != 3 {
				t.Fatalf("DEBUG downgrade lines=%d want 3: %s", got, logged)
			}
			if strings.Contains(logged, msgCaptchaUnsubscribed) || strings.Contains(logged, `"level":"WARN"`) {
				t.Fatalf("the failure captcha downgrade must not WARN: %s", logged)
			}
			if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimitFailure, "ipv4", "ban"); got != 3 {
				t.Fatalf("ban drops=%d want 3", got)
			}
		})
	}
}

// TestRateLimit_bindLogsCaptchaUnavailableOncePerBind proves the ERROR for a router without a captcha
// subscription is logged on the bind of a client whose policy answers with a captcha, once per bind and
// not per request, and never for a policy without a captcha answer or on a router subscribed to a captcha.
func TestRateLimit_bindLogsCaptchaUnavailableOncePerBind(t *testing.T) {
	for _, tc := range []struct {
		name          string
		buckets       []ratelimit.BucketRule
		failureAction string
		captcha       bool
		wantErrors    int
	}{
		{name: "captcha bucket", buckets: []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1)}, wantErrors: 1},
		{name: "failure action captcha", buckets: []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, failureAction: configuration.FailureActionCaptcha, wantErrors: 1},
		{name: "ratelimit and log buckets with passthrough", buckets: []ratelimit.BucketRule{perIPTestBucket("per-ip", 1), func() ratelimit.BucketRule {
			bucket := perIPTestBucket("dry-run", 1)
			bucket.Action = ratelimit.ActionLog
			return bucket
		}()}, failureAction: configuration.FailureActionPassthrough},
		{name: "captcha bucket on a router with a captcha", buckets: []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1)}, captcha: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestRateLimitConfig(tc.buckets, func(cfg *configuration.Config) {
				cfg.RateLimitInstanceName = "shared"
				cfg.RateLimitFailureAction = tc.failureAction
			})
			next := &recordedNextRequest{}
			fixture := &testRateLimitFixture{b: newTestRateLimitRoute(t, "edge", cfg, next), counter: &testRateLimitCounter{counts: map[string]int64{}}, next: next}
			if tc.captcha {
				fixture.bindUsableTestCaptcha(t)
			}
			log, sink := newTestLogSink(slog.LevelDebug)
			// bouncer.New adds traefikName with log.With; this literal route does not go through New.
			fixture.b.log = log.With("traefikName", fixture.b.name)
			client := newTestRateLimitClient(t, cfg, fixture.counter)
			fixture.b.ReceiveRateLimit(reclaim.Published{Value: client})
			for range 3 {
				fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
			}
			fixture.b.ReceiveRateLimit(reclaim.Published{Value: client})
			logged := sink.String()
			if got := countLogLines(logged, `"level":"ERROR"`, `"msg":"`+msgRateLimitCaptchaUnavailable+`"`, `"reason":"unsubscribed"`, `"traefikName":"edge"`, `"instanceName":"shared"`); got != tc.wantErrors {
				t.Fatalf("bind ERROR lines=%d want %d: %s", got, tc.wantErrors, logged)
			}
			if got := countLogLines(logged, `"level":"ERROR"`); got != tc.wantErrors {
				t.Fatalf("ERROR lines=%d want %d: %s", got, tc.wantErrors, logged)
			}
			if strings.Contains(logged, msgCaptchaUnsubscribed) {
				t.Fatalf("must not WARN %s: %s", msgCaptchaUnsubscribed, logged)
			}
			// A new client of the same policy is a new bind, and logs again.
			fixture.b.ReceiveRateLimit(reclaim.Published{Value: newTestRateLimitClient(t, cfg, fixture.counter)})
			if got := countLogLines(sink.String(), `"msg":"`+msgRateLimitCaptchaUnavailable+`"`); got != 2*tc.wantErrors {
				t.Fatalf("after a rebind: ERROR lines=%d want %d", got, 2*tc.wantErrors)
			}
		})
	}
}

// TestRateLimit_captchaPageRequestsAreNotCharged proves the challenge-form POST and a custom widget asset
// skip every bucket on a router with a usable captcha, even with captcha and ratelimit buckets both over
// their limits, and are charged like any other request on a router without one.
func TestRateLimit_captchaPageRequestsAreNotCharged(t *testing.T) {
	buckets := []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1), perIPTestBucket("per-ip-hard", 2)}
	for _, usable := range []bool{true, false} {
		fixture := newTestRateLimitFixture(t, buckets, nil)
		if usable {
			captchaClient := fixture.bindUsableTestCaptcha(t)
			if !captchaClient.IsCustomResourceRequest(httptest.NewRequest(http.MethodGet, "http://example.com"+testCaptchaWidgetAsset, nil)) {
				t.Fatalf("%s must be a widget asset of the test captcha", testCaptchaWidgetAsset)
			}
		}
		for range 3 {
			fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
		}
		chargedBefore := fixture.counter.takes.Load()
		for _, req := range []*http.Request{challengeMarkerPost(), httptest.NewRequest(http.MethodGet, "http://example.com"+testCaptchaWidgetAsset, nil)} {
			rw := fixture.serveRequest(req, testRateLimitClientIP)
			answeredByBucket := strings.HasPrefix(rw.Header().Get("X-Remediation"), "ban:ratelimit:") || strings.HasPrefix(rw.Header().Get("X-Remediation"), "captcha:ratelimit:")
			if answeredByBucket == usable {
				t.Fatalf("usable=%v %s %s: header %q, want answered by a bucket only without a usable captcha", usable, req.Method, req.URL.Path, rw.Header().Get("X-Remediation"))
			}
		}
		charged := fixture.counter.takes.Load() - chargedBefore
		if usable && charged != 0 {
			t.Fatalf("usable captcha: captcha page requests charged %d times, want 0", charged)
		}
		if !usable && charged == 0 {
			t.Fatal("no usable captcha: captcha page requests must be charged")
		}
	}
}

// TestRateLimit_stackedCaptchaAndRateLimitBuckets proves the spec's stacked buckets through ServeHTTP:
// an unsolved client gets requests 1-2 through, the challenge on 3-4, and the ratelimit answer on 5; a
// client holding a valid gate gets 1-4 through and the ratelimit answer on 5, and is never counted by
// the captcha bucket.
func TestRateLimit_stackedCaptchaAndRateLimitBuckets(t *testing.T) {
	buckets := []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(2), perIPTestBucket("per-ip-hard", 4)}
	unsolved := newTestRateLimitFixture(t, buckets, nil)
	unsolved.bindUsableTestCaptcha(t)
	for request := 1; request <= 5; request++ {
		rw := unsolved.serve(http.MethodGet, "/", testCaptchaRemoteIP)
		wantHeader := ""
		switch {
		case request == 5:
			wantHeader = "ban:ratelimit:per-ip-hard"
		case request >= 3:
			wantHeader = "captcha:ratelimit:per-ip-soft"
		}
		if got := rw.Header().Get("X-Remediation"); got != wantHeader || unsolved.next.called != (wantHeader == "") {
			t.Fatalf("unsolved request %d: next=%v header %q, want %q", request, unsolved.next.called, got, wantHeader)
		}
	}

	solved := newTestRateLimitFixture(t, buckets, nil)
	gateCookie := solveTestGateCookie(t, solved.bindUsableTestCaptcha(t))
	for request := 1; request <= 5; request++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: "crowdsec_captcha_gate", Value: gateCookie})
		rw := solved.serveRequest(req, testCaptchaRemoteIP)
		wantHeader := ""
		if request == 5 {
			wantHeader = "ban:ratelimit:per-ip-hard"
		}
		if got := rw.Header().Get("X-Remediation"); got != wantHeader || solved.next.called != (wantHeader == "") {
			t.Fatalf("solved request %d: next=%v header %q, want %q", request, solved.next.called, got, wantHeader)
		}
	}
	if keys := solved.countedKeysOf("per-ip-soft"); len(keys) != 0 {
		t.Fatalf("a solved client moved the captcha bucket counter: %v", keys)
	}
}

// solvedChallengeFormPost is the challenge-form POST of the test captcha page: the marker plus an answer
// testSiteverifyCaptchaClient accepts.
func solvedChallengeFormPost() *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/protected", strings.NewReader("crowdsec_captcha_challenge=v1&dummy-captcha-response=ok"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// TestRateLimit_challengeFormPostGoesToTheCaptchaGate proves a challenge-form POST on a router with a usable
// captcha and no AppSec is not charged only when the captcha gate answers it, that is when the policy can
// answer with a captcha and no bypassCaptcha rule matched: a valid answer gets the solved redirect and the
// gate cookie, a missing answer gets the challenge page again with captcha:ratelimit and a captcha drop under
// plugin:ratelimit. With a bypassCaptcha rule, a policy without a captcha answer, or no usable captcha, it is
// charged like any request, so an over-limit client gets the ratelimit answer.
func TestRateLimit_challengeFormPostGoesToTheCaptchaGate(t *testing.T) {
	captchaPolicy := []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(1), perIPTestBucket("per-ip-hard", 2)}
	for _, tc := range []struct {
		name          string
		buckets       []ratelimit.BucketRule
		failureAction string
		captcha       bool
		bypassCaptcha bool
		form          func() *http.Request
		wantStatus    int
		wantHeader    string
		wantNext      bool
		wantGate      bool
		wantCharged   bool
	}{
		{name: "valid answer", buckets: captchaPolicy, captcha: true, form: solvedChallengeFormPost, wantStatus: http.StatusFound, wantHeader: "captcha:solved", wantGate: true},
		{name: "missing answer", buckets: captchaPolicy, captcha: true, form: challengeMarkerPost, wantStatus: http.StatusOK, wantHeader: "captcha:ratelimit"},
		{name: "failure action captcha without captcha buckets", buckets: []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, failureAction: configuration.FailureActionCaptcha, captcha: true, form: solvedChallengeFormPost, wantStatus: http.StatusFound, wantHeader: "captcha:solved", wantGate: true},
		{name: "bypassCaptcha rule", buckets: captchaPolicy, captcha: true, bypassCaptcha: true, form: solvedChallengeFormPost, wantStatus: http.StatusTooManyRequests, wantHeader: "ban:ratelimit:per-ip-hard", wantCharged: true},
		{name: "policy without a captcha answer", buckets: []ratelimit.BucketRule{perIPTestBucket("per-ip", 1)}, failureAction: configuration.FailureActionPassthrough, captcha: true, form: solvedChallengeFormPost, wantStatus: http.StatusTooManyRequests, wantHeader: "ban:ratelimit:per-ip", wantCharged: true},
		{name: "no usable captcha", buckets: captchaPolicy, form: solvedChallengeFormPost, wantStatus: http.StatusTooManyRequests, wantHeader: "ban:ratelimit:per-ip-hard", wantCharged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newTestRateLimitFixture(t, tc.buckets, func(cfg *configuration.Config) {
				cfg.RateLimitFailureAction = tc.failureAction
			})
			if tc.captcha {
				fixture.bindUsableTestCaptcha(t)
			}
			if tc.bypassCaptcha {
				fixture.b.actionRules = mustPathAction(t, "form", "^/protected$", httprule.ActionBypassCaptcha)
			}
			// Put the client over every bucket of the policy first.
			for range 3 {
				fixture.serve(http.MethodGet, "/", testRateLimitClientIP)
			}
			chargedBefore := fixture.counter.takes.Load()
			rw := fixture.serveRequest(tc.form(), testRateLimitClientIP)
			if rw.Code != tc.wantStatus || rw.Header().Get("X-Remediation") != tc.wantHeader || fixture.next.called != tc.wantNext {
				t.Fatalf("status %d header %q next=%v, want %d %q next=%v (body %q)", rw.Code, rw.Header().Get("X-Remediation"), fixture.next.called, tc.wantStatus, tc.wantHeader, tc.wantNext, rw.Body.String())
			}
			if hasGateCookie(rw) != tc.wantGate {
				t.Fatalf("gate cookie=%v want %v", hasGateCookie(rw), tc.wantGate)
			}
			if charged := fixture.counter.takes.Load() - chargedBefore; (charged != 0) != tc.wantCharged {
				t.Fatalf("charged %d times, want charged=%v", charged, tc.wantCharged)
			}
			if tc.wantHeader == "captcha:ratelimit" {
				assertChallengeFormChallengedAgain(t, fixture, rw)
			}
		})
	}
}

// readCountingBody is a test request body that counts the Read calls made on it.
type readCountingBody struct {
	reader io.Reader
	reads  int
}

// Read reads from the wrapped reader and counts the call.
func (body *readCountingBody) Read(p []byte) (int, error) {
	body.reads++
	return body.reader.Read(p)
}

// Close does nothing: the wrapped reader holds no resource.
func (*readCountingBody) Close() error { return nil }

// TestRateLimit_challengeFormBodyReadOnlyWhenTheGateAnswers proves the rate-limit step reads a POST body for
// the challenge marker only after the policy and bypassCaptcha checks say the captcha gate would answer it:
// a policy without a captcha answer or a bypassCaptcha rule charges the marker POST without one Read, and a
// policy with a captcha answer reads it and hands it to the gate uncharged.
func TestRateLimit_challengeFormBodyReadOnlyWhenTheGateAnswers(t *testing.T) {
	captchaPolicy := []ratelimit.BucketRule{perIPSoftTestCaptchaBucket(5), perIPTestBucket("per-ip-hard", 10)}
	for _, tc := range []struct {
		name          string
		buckets       []ratelimit.BucketRule
		bypassCaptcha bool
		wantRead      bool
	}{
		{name: "policy without a captcha answer", buckets: []ratelimit.BucketRule{perIPTestBucket("per-ip", 10)}},
		{name: "bypassCaptcha rule", buckets: captchaPolicy, bypassCaptcha: true},
		{name: "policy with a captcha answer", buckets: captchaPolicy, wantRead: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newTestRateLimitFixture(t, tc.buckets, nil)
			fixture.bindUsableTestCaptcha(t)
			if tc.bypassCaptcha {
				fixture.b.actionRules = mustPathAction(t, "form", "^/protected$", httprule.ActionBypassCaptcha)
			}
			req := challengeMarkerPost()
			body := &readCountingBody{reader: req.Body}
			req.Body = body
			rw := fixture.serveRequest(req, testRateLimitClientIP)
			charged := fixture.counter.takes.Load() != 0
			if (body.reads != 0) != tc.wantRead || charged == tc.wantRead {
				t.Fatalf("body reads %d charged=%v, want read=%v charged=%v (status %d header %q)", body.reads, charged, tc.wantRead, !tc.wantRead, rw.Code, rw.Header().Get("X-Remediation"))
			}
			if !tc.wantRead && !fixture.next.called {
				t.Fatalf("an under-limit marker POST no gate answers must reach next: status %d header %q", rw.Code, rw.Header().Get("X-Remediation"))
			}
		})
	}
}

// assertChallengeFormChallengedAgain checks a challenge-form POST the gate rejected: the challenge page and
// one captcha drop under the rate-limit origin without a bucket.
func assertChallengeFormChallengedAgain(t *testing.T, fixture *testRateLimitFixture, rw *httptest.ResponseRecorder) {
	t.Helper()
	if got := fixture.lapiClient.TestDroppedCount(lapi.OriginPluginRateLimitChallengeForm, "ipv4", "captcha"); got != 1 {
		t.Fatalf("captcha drops under %s=%d want 1", lapi.OriginPluginRateLimitChallengeForm, got)
	}
	if rw.Body.String() != "CAPTCHA_CHALLENGE_PAGE" {
		t.Fatalf("body %q, want the challenge page", rw.Body.String())
	}
}
