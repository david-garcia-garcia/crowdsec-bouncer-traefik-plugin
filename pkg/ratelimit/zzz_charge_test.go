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
// failBucket makes every Take on a key of that bucket return an error.
type testCounter struct {
	counts     map[string]int64
	failBucket string
	takes      []string
}

// newTestCounter returns an empty testCounter.
func newTestCounter() *testCounter {
	return &testCounter{counts: map[string]int64{}}
}

// Take counts one hit on key and reports whether the count is within limit.
func (counter *testCounter) Take(_ context.Context, key string, limit int64, _ time.Duration) (allowed bool, estimated float64, err error) {
	counter.takes = append(counter.takes, key)
	if counter.failBucket != "" && strings.Contains(key, ":"+counter.failBucket+":") {
		return true, 0, errors.New("redis: unreachable")
	}
	counter.counts[key]++
	return counter.counts[key] <= limit, float64(counter.counts[key]), nil
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

// chargeTest charges one request from clientIP to method target.
func chargeTest(set *BucketSet, counter Counter, method, target, clientIP string) Verdict {
	return set.Charge(context.Background(), counter, "edge", httptest.NewRequest(method, "http://example.com"+target, nil), net.ParseIP(clientIP))
}

// TestCharge_firstDenyAnswersAndLaterBucketsAreNotCharged is the spec scenario with login then per-ip.
func TestCharge_firstDenyAnswersAndLaterBucketsAreNotCharged(t *testing.T) {
	set := mustNewTestBucketSet(t, []BucketRule{
		{Name: "login", Requests: 1, Window: "1m", Rule: httprule.Rule{Method: "^POST$", Path: "^/login$"}, Key: []KeyPart{{From: KeyFromIP}}},
		{Name: "per-ip", Requests: 100, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}},
	})
	counter := newTestCounter()
	if verdict := chargeTest(set, counter, http.MethodPost, "/login", "198.51.100.1"); verdict.DenyBucket != "" || verdict.Err != nil {
		t.Fatalf("first verdict=%+v", verdict)
	}
	verdict := chargeTest(set, counter, http.MethodPost, "/login", "198.51.100.1")
	if verdict.DenyBucket != "login" || verdict.RetryAfter < time.Second || verdict.RetryAfter > time.Minute {
		t.Fatalf("second verdict=%+v want deny by login", verdict)
	}
	if got := counter.takesOn("per-ip"); got != 1 {
		t.Fatalf("per-ip charged %d times, want 1", got)
	}
	if verdict := chargeTest(set, counter, http.MethodGet, "/login", "198.51.100.1"); verdict.DenyBucket != "" {
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
		if verdict.DenyBucket != "" {
			t.Fatalf("request %d denied by %s", request, verdict.DenyBucket)
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
		if verdict := chargeTest(set, counter, http.MethodGet, "/app.js", "198.51.100.1"); verdict.DenyBucket != "" {
			t.Fatalf("app.js denied by %s", verdict.DenyBucket)
		}
	}
	if got := counter.takesOn("catch-all"); got != 0 {
		t.Fatalf("catch-all charged %d times behind final", got)
	}
	if got := counter.takesOn("token"); got != 0 {
		t.Fatalf("token charged %d times without Authorization", got)
	}
	chargeTest(set, counter, http.MethodGet, "/index.html", "198.51.100.2")
	if verdict := chargeTest(set, counter, http.MethodGet, "/index.html", "198.51.100.2"); verdict.DenyBucket != "catch-all" {
		t.Fatalf("index.html verdict=%+v want deny by catch-all", verdict)
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
	if verdict.Err == nil || !strings.Contains(verdict.Err.Error(), "bucket second") || verdict.DenyBucket != "" {
		t.Fatalf("verdict=%+v want error from bucket second", verdict)
	}
	if counter.takesOn("first") != 1 || counter.takesOn("third") != 0 {
		t.Fatalf("takes=%v", counter.takes)
	}
}

// TestCharge_nilSetOrCounterChargesNothing proves the step is inert without a set or a counter.
func TestCharge_nilSetOrCounterChargesNothing(t *testing.T) {
	var nilSet *BucketSet
	if verdict := chargeTest(nilSet, newTestCounter(), http.MethodGet, "/", "198.51.100.1"); verdict.DenyBucket != "" || verdict.Err != nil {
		t.Fatalf("nil set verdict=%+v", verdict)
	}
	set := mustNewTestBucketSet(t, []BucketRule{validTestBucket("b")})
	if verdict := chargeTest(set, nil, http.MethodGet, "/", "198.51.100.1"); verdict.DenyBucket != "" || verdict.Err != nil {
		t.Fatalf("nil counter verdict=%+v", verdict)
	}
}

// TestRetryAfterAt_isTimeToTheWindowBoundary proves second 45 of a 60s window gives 15s, on the unix grid.
func TestRetryAfterAt_isTimeToTheWindowBoundary(t *testing.T) {
	windowStart := time.Unix(1_800_000_000/60*60, 0)
	if got := retryAfterAt(windowStart.Add(45*time.Second), time.Minute); got != 15*time.Second {
		t.Fatalf("second 45: got %s want 15s", got)
	}
	if got := retryAfterAt(windowStart, time.Minute); got != time.Minute {
		t.Fatalf("second 0: got %s want 60s", got)
	}
	if got := retryAfterAt(windowStart.Add(59*time.Second+900*time.Millisecond), time.Minute); got != time.Second {
		t.Fatalf("last second: got %s want 1s", got)
	}
	set := mustNewTestBucketSet(t, []BucketRule{{Name: "b", Requests: 1, Window: "60s"}})
	set.now = func() time.Time { return windowStart.Add(45 * time.Second) }
	counter := newTestCounter()
	chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1")
	if verdict := chargeTest(set, counter, http.MethodGet, "/", "198.51.100.1"); verdict.RetryAfter != 15*time.Second {
		t.Fatalf("Charge RetryAfter=%s want 15s", verdict.RetryAfter)
	}
}
