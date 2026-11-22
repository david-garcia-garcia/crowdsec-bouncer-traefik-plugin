package ratelimit

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/httprule"
)

// testCounter is an in-memory Counter: every Take counts, then compares with limit.
// failBucket makes every Take on a key of that bucket return an error. retryAfter is the RetryAfter of
// a denied Take (default 15s).
type testCounter struct {
	counts     map[string]int64
	failBucket string
	retryAfter time.Duration
	takes      []string
}

// newTestCounter returns an empty testCounter.
func newTestCounter() *testCounter {
	return &testCounter{counts: map[string]int64{}, retryAfter: 15 * time.Second}
}

// Take counts one hit on key and reports whether the count is within limit.
func (counter *testCounter) Take(_ context.Context, key string, limit Limit) (Status, error) {
	counter.takes = append(counter.takes, key)
	if counter.failBucket != "" && strings.Contains(key, ":"+counter.failBucket+":") {
		return Status{}, errors.New("redis: unreachable")
	}
	counter.counts[key]++
	status := Status{Allowed: counter.counts[key] <= limit.Requests}
	if !status.Allowed {
		status.RetryAfter = counter.retryAfter
	}
	return status, nil
}

// takesOn is how many Takes hit a key of bucket.
func (counter *testCounter) takesOn(bucket string) int {
	total := 0
	for _, key := range counter.takes {
		if strings.Contains(key, ":"+bucket+":") {
			total++
		}
	}
	return total
}

// chargeTest charges one request from clientIP to method target, for a client without a captcha gate.
func chargeTest(set *BucketSet, counter Counter, method, target, clientIP string) Verdict {
	return chargeTestWithGate(set, counter, method, target, clientIP, false)
}

// chargeTestWithGate charges one request from clientIP to method target; gateCleared says the client
// holds the router's valid captcha gate.
func chargeTestWithGate(set *BucketSet, counter Counter, method, target, clientIP string, gateCleared bool) Verdict {
	return set.Charge(context.Background(), counter, "edge", httptest.NewRequest(method, "http://example.com"+target, nil), net.ParseIP(clientIP), gateCleared)
}

// TestCharge_firstRateLimitAnswersAndLaterBucketsAreNotCharged is the spec scenario with login then per-ip.
func TestCharge_firstRateLimitAnswersAndLaterBucketsAreNotCharged(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "login", Requests: 1, Window: "1m", Rule: httprule.Rule{Method: "^POST$", Path: "^/login$"}, Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "per-ip", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	if verdict := chargeTest(set, counter, http.MethodPost, "/login", "198.51.100.1"); verdict.RateLimit.Name != "" || verdict.Err != nil {
		t.Fatalf("first verdict=%+v", verdict)
	}
	verdict := chargeTest(set, counter, http.MethodPost, "/login", "198.51.100.1")
	if verdict.RateLimit.Name != "login" || verdict.RateLimit.RetryAfter < time.Second || verdict.RateLimit.RetryAfter > time.Minute {
		t.Fatalf("second verdict=%+v want the ratelimit answer of login", verdict)
	}
	if got := counter.takesOn("per-ip"); got != 1 {
		t.Fatalf("per-ip charged %d times, want 1", got)
	}
	if verdict := chargeTest(set, counter, http.MethodGet, "/login", "198.51.100.1"); verdict.RateLimit.Name != "" {
		t.Fatalf("GET /login must not match login: %+v", verdict)
	}
}

// TestCharge_logBucketNeverStops proves a log bucket over its limit is reported and the walk goes on.
func TestCharge_logBucketNeverStops(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "dry-run", Requests: 1, Window: "1m", Action: ActionLog, Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "after", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	for request := 1; request <= 3; request++ {
		verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
		if verdict.RateLimit.Name != "" {
			t.Fatalf("request %d answered by %s", request, verdict.RateLimit.Name)
		}
		wantExceeded := request > 1
		if (len(verdict.Exceeded) == 1) != wantExceeded {
			t.Fatalf("request %d Exceeded=%+v", request, verdict.Exceeded)
		}
		if wantExceeded && (verdict.Exceeded[0].Name != "dry-run" || verdict.Exceeded[0].Requests != 1 || verdict.Exceeded[0].Window != time.Minute) {
			t.Fatalf("request %d Exceeded=%+v", request, verdict.Exceeded)
		}
	}
	if got := counter.takesOn("after"); got != 3 {
		t.Fatalf("after charged %d times, want 3", got)
	}
}

// TestCharge_finalStopsEvaluation proves a matching final bucket stops the walk even under its limit,
// and that a bucket skipped for a missing key value does not apply its final.
func TestCharge_finalStopsEvaluation(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "token", Requests: 100, Window: "1m", Final: true, Key: []KeyPart{{From: KeyFromHeader, Name: "Authorization"}}},
		{Name: "static", Requests: 1000, Window: "1m", Final: true, Rule: httprule.Rule{Path: `\.js$`}, Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "catch-all", Requests: 1, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	for range 5 {
		if verdict := chargeTest(set, counter, http.MethodGet, "/app.js", "198.51.100.1"); verdict.RateLimit.Name != "" {
			t.Fatalf("app.js answered by %s", verdict.RateLimit.Name)
		}
	}
	if got := counter.takesOn("catch-all"); got != 0 {
		t.Fatalf("catch-all charged %d times behind final", got)
	}
	if got := counter.takesOn("token"); got != 0 {
		t.Fatalf("token charged %d times without Authorization", got)
	}
	chargeTest(set, counter, http.MethodGet, "/index.html", "198.51.100.2")
	if verdict := chargeTest(set, counter, http.MethodGet, "/index.html", "198.51.100.2"); verdict.RateLimit.Name != "catch-all" {
		t.Fatalf("index.html verdict=%+v want the ratelimit answer of catch-all", verdict)
	}
}

// TestCharge_counterErrorStopsTheWalk proves the first error is returned and later buckets are not charged.
func TestCharge_counterErrorStopsTheWalk(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "first", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "second", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "third", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	counter.failBucket = "second"
	verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
	if verdict.Err == nil || !strings.Contains(verdict.Err.Error(), "bucket second") || verdict.RateLimit.Name != "" {
		t.Fatalf("verdict=%+v want error from bucket second", verdict)
	}
	if counter.takesOn("first") != 1 || counter.takesOn("third") != 0 {
		t.Fatalf("takes=%v", counter.takes)
	}
}

// TestCharge_nilSetOrCounterChargesNothing proves the step is inert without a set or a counter.
func TestCharge_nilSetOrCounterChargesNothing(t *testing.T) {
	var nilSet *BucketSet
	if verdict := chargeTest(nilSet, newTestCounter(), http.MethodGet, "/", "198.51.100.1"); verdict.RateLimit.Name != "" || verdict.Err != nil {
		t.Fatalf("nil set verdict=%+v", verdict)
	}
	set := mustNewTestBucketSet(t, []BucketRule{validTestBucket("b")})
	if verdict := chargeTest(set, nil, http.MethodGet, "/", "198.51.100.1"); verdict.RateLimit.Name != "" || verdict.Err != nil {
		t.Fatalf("nil counter verdict=%+v", verdict)
	}
}

// TestCharge_retryAfterIsTheCounterRetryAfterRoundedUp proves the ratelimit verdict carries the counter's
// RetryAfter rounded up to whole seconds, at least 1s.
func TestCharge_retryAfterIsTheCounterRetryAfterRoundedUp(t *testing.T) {
	for _, tc := range []struct {
		counter time.Duration
		want    time.Duration
	}{
		{0, time.Second},
		{300 * time.Millisecond, time.Second},
		{time.Second, time.Second},
		{14*time.Second + 200*time.Millisecond, 15 * time.Second},
		{15 * time.Second, 15 * time.Second},
	} {
		set := mustNewTestBucketSet(t, []BucketRule{{Name: "b", Requests: 1, Window: "60s"}})
		counter := newTestCounter()
		counter.retryAfter = tc.counter
		chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
		if verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1"); verdict.RateLimit.RetryAfter != tc.want {
			t.Fatalf("counter RetryAfter %s: Charge RetryAfter=%s want %s", tc.counter, verdict.RateLimit.RetryAfter, tc.want)
		}
	}
}

// softCaptchaHardRateLimitBuckets are the spec's stacked buckets on one client address: per-ip-soft
// (captcha, 2 per minute) and per-ip-hard (ratelimit, 4 per minute), in list order softFirst or reversed.
func softCaptchaHardRateLimitBuckets(softFirst bool) []BucketRule {
	soft := BucketRule{Name: "per-ip-soft", Action: ActionCaptcha, Requests: 2, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}}
	hard := BucketRule{Name: "per-ip-hard", Action: ActionRateLimit, Requests: 4, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}}
	if softFirst {
		return []BucketRule{soft, hard}
	}
	return []BucketRule{hard, soft}
}

// TestCharge_stackedRateLimitIsTheHardCeiling proves, in both list orders, that a client that never
// solves gets requests 1-2 through, the captcha bucket on 3-4, and the ratelimit bucket on 5: a captcha
// bucket over its limit does not stop the walk, and ratelimit wins over captcha.
func TestCharge_stackedRateLimitIsTheHardCeiling(t *testing.T) {
	for _, softFirst := range []bool{true, false} {
		set := mustNewTestBucketSet(t, softCaptchaHardRateLimitBuckets(softFirst))
		counter := newTestCounter()
		for request := 1; request <= 5; request++ {
			verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
			wantCaptcha, wantRateLimit := "", ""
			switch {
			case request == 5:
				wantRateLimit = "per-ip-hard"
			case request >= 3:
				wantCaptcha = "per-ip-soft"
			}
			if verdict.Err != nil || verdict.RateLimit.Name != wantRateLimit || (wantRateLimit == "" && verdict.Captcha.Name != wantCaptcha) {
				t.Fatalf("softFirst=%v request %d: verdict=%+v want ratelimit %q captcha %q", softFirst, request, verdict, wantRateLimit, wantCaptcha)
			}
			if wantCaptcha != "" && verdict.Captcha.RetryAfter != 15*time.Second {
				t.Fatalf("softFirst=%v request %d: captcha RetryAfter=%s want the counter's 15s", softFirst, request, verdict.Captcha.RetryAfter)
			}
		}
		if got := counter.takesOn("per-ip-hard"); got != 5 {
			t.Fatalf("softFirst=%v: per-ip-hard charged %d times, want 5 (a kept captcha bucket must not stop the walk)", softFirst, got)
		}
	}
}

// TestCharge_gateClearedSkipsCaptchaBuckets proves, in both list orders, that a client with a cleared
// gate is not counted by captcha buckets and still meets the ratelimit bucket on request 5.
func TestCharge_gateClearedSkipsCaptchaBuckets(t *testing.T) {
	for _, softFirst := range []bool{true, false} {
		set := mustNewTestBucketSet(t, softCaptchaHardRateLimitBuckets(softFirst))
		counter := newTestCounter()
		for request := 1; request <= 5; request++ {
			verdict := chargeTestWithGate(set, counter, http.MethodGet, "/", "198.51.100.1", true)
			wantRateLimit := ""
			if request == 5 {
				wantRateLimit = "per-ip-hard"
			}
			if verdict.Err != nil || verdict.Captcha.Name != "" || verdict.RateLimit.Name != wantRateLimit {
				t.Fatalf("softFirst=%v request %d: verdict=%+v want ratelimit %q and no captcha", softFirst, request, verdict, wantRateLimit)
			}
		}
		if got := counter.takesOn("per-ip-soft"); got != 0 {
			t.Fatalf("softFirst=%v: per-ip-soft charged %d times with a cleared gate, want 0", softFirst, got)
		}
	}
}

// TestCharge_finalOnASkippedCaptchaBucketDoesNotApply proves a final captcha bucket stops the walk for
// an unsolved client and not for a client with a cleared gate, whose later buckets are still charged.
func TestCharge_finalOnASkippedCaptchaBucketDoesNotApply(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "soft", Action: ActionCaptcha, Final: true, Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "catch-all", Requests: 1, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	for range 2 {
		if verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1"); verdict.RateLimit.Name != "" {
			t.Fatalf("unsolved client: verdict=%+v, the final captcha bucket must stop the walk", verdict)
		}
	}
	if got := counter.takesOn("catch-all"); got != 0 {
		t.Fatalf("catch-all charged %d times behind a final captcha bucket", got)
	}
	chargeTestWithGate(set, counter, http.MethodGet, "/", "198.51.100.2", true)
	if verdict := chargeTestWithGate(set, counter, http.MethodGet, "/", "198.51.100.2", true); verdict.RateLimit.Name != "catch-all" {
		t.Fatalf("cleared gate: verdict=%+v want the ratelimit answer of catch-all", verdict)
	}
}

// TestCharge_counterErrorAfterAKeptCaptchaBucket proves a counter error after a captcha bucket over its
// limit stops the walk and returns the error, and that log buckets over their limit are still reported
// beside a kept captcha bucket.
func TestCharge_counterErrorAfterAKeptCaptchaBucket(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "soft", Action: ActionCaptcha, Requests: 1, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "dry-run", Action: ActionLog, Requests: 1, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "hard", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
	verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
	if verdict.Err != nil || verdict.Captcha.Name != "soft" || len(verdict.Exceeded) != 1 || verdict.Exceeded[0].Name != "dry-run" {
		t.Fatalf("second request: verdict=%+v want captcha soft and dry-run logged", verdict)
	}
	counter.failBucket = "hard"
	verdict = chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
	if verdict.Err == nil || !strings.Contains(verdict.Err.Error(), "bucket hard") || verdict.RateLimit.Name != "" {
		t.Fatalf("third request: verdict=%+v want the error of bucket hard", verdict)
	}
}

// testTokenBucketCounter is an in-memory token bucket per key with a frozen clock: every key starts with
// limit.Burst tokens, a Take takes one, and a Take that finds none is denied without taking one, with
// RetryAfter = one token's refill (Window / Requests) minus elapsed (here 300ms).
type testTokenBucketCounter struct {
	tokens map[string]int64
}

// Take takes one token of key, seeding the key with limit.Burst on first use.
func (counter *testTokenBucketCounter) Take(_ context.Context, key string, limit Limit) (Status, error) {
	tokens, seen := counter.tokens[key]
	if !seen {
		tokens = limit.Burst
	}
	if tokens < 1 {
		counter.tokens[key] = tokens
		return Status{RetryAfter: limit.Window/time.Duration(limit.Requests) - 300*time.Millisecond}, nil
	}
	counter.tokens[key] = tokens - 1
	return Status{Allowed: true}, nil
}

// TestCharge_tokenBucketBurstThenRetryAfter proves Charge hands the counter each bucket's burst: burst 3
// admits 3 at once and the fourth is answered with the refill time rounded up (9.7s -> 10s); a denied hit
// takes no token, so the answer repeats with the same Retry-After.
func TestCharge_tokenBucketBurstThenRetryAfter(t *testing.T) {
	set, err := NewBucketSet([]BucketRule{
		{Name: "per-ip", Requests: 1, Window: "10s", Burst: 3, Key: []KeyPart{{From: KeyFromIP}}},
	}, AlgorithmTokenBucket)
	if err != nil {
		t.Fatal(err)
	}
	counter := &testTokenBucketCounter{tokens: map[string]int64{}}
	for attempt := 1; attempt <= 3; attempt++ {
		if verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.80"); verdict.RateLimit.Name != "" {
			t.Fatalf("request %d of burst 3 answered: %+v", attempt, verdict)
		}
	}
	for attempt := 4; attempt <= 5; attempt++ {
		verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.80")
		if verdict.RateLimit.Name != "per-ip" || verdict.RateLimit.RetryAfter != 10*time.Second {
			t.Fatalf("request %d verdict=%+v, want per-ip with Retry-After 10s", attempt, verdict)
		}
	}
}

// TestCharge_tokenBucketDefaultBurstAndActions proves the default burst is requests and that the
// actions keep their meaning under tokenBucket: a captcha bucket is kept, a stacked ratelimit bucket
// answers, a log bucket is recorded.
func TestCharge_tokenBucketDefaultBurstAndActions(t *testing.T) {
	set, err := NewBucketSet([]BucketRule{
		{Name: "dry-run", Action: ActionLog, Requests: 1, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "soft", Action: ActionCaptcha, Requests: 2, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "hard", Action: ActionRateLimit, Requests: 3, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	}, AlgorithmTokenBucket)
	if err != nil {
		t.Fatal(err)
	}
	counter := &testTokenBucketCounter{tokens: map[string]int64{}}
	var verdicts [4]Verdict
	for i := range verdicts {
		verdicts[i] = chargeTest(set, counter, http.MethodGet, "/", "198.51.100.81")
	}
	if len(verdicts[0].Exceeded) != 0 || len(verdicts[1].Exceeded) != 1 || verdicts[1].Exceeded[0].Name != "dry-run" {
		t.Fatalf("log bucket: %+v / %+v", verdicts[0], verdicts[1])
	}
	if verdicts[1].Captcha.Name != "" || verdicts[2].Captcha.Name != "soft" || verdicts[2].RateLimit.Name != "" {
		t.Fatalf("captcha bucket of burst 2: request 3 must keep soft: %+v", verdicts[2])
	}
	if verdicts[3].RateLimit.Name != "hard" || verdicts[3].RateLimit.RetryAfter != 20*time.Second {
		t.Fatalf("ratelimit bucket of burst 3: request 4 must be answered by hard after 19.7s -> 20s: %+v", verdicts[3])
	}
}
