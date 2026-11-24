package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/admission"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// errTestRedisDown is the counter error switchCounter returns while it is down.
var errTestRedisDown = errors.New("redis: connection refused")

// switchCounter answers allowed, or errTestRedisDown while down is set, and counts the calls that reached it.
type switchCounter struct {
	mu    sync.Mutex
	calls int
	down  bool
}

func (counter *switchCounter) Take(context.Context, string, Limit) (Status, error) {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	counter.calls++
	if counter.down {
		return Status{}, errTestRedisDown
	}
	return Status{Allowed: true}, nil
}

func (counter *switchCounter) set(down bool) {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	counter.down = down
}

func (counter *switchCounter) callCount() int {
	counter.mu.Lock()
	defer counter.mu.Unlock()
	return counter.calls
}

// newGateTestClient is a Client on counter that logs to a DEBUG JSON sink, with an admission gate of
// periodSecs (0 builds none), as newClient builds it for a counter that calls Redis before answering.
func newGateTestClient(t *testing.T, counter Counter, periodSecs int64) (*Client, *lockedLogSink) {
	t.Helper()
	logger.ResetDebounceForTest()
	t.Cleanup(logger.ResetDebounceForTest)
	client, err := NewTestClient(deadRedisTestSettings(0), counter)
	if err != nil {
		t.Fatal(err)
	}
	sink := &lockedLogSink{}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
	gate, err := admission.New(admission.Config{Leg: gateKey, PeriodSecs: periodSecs, MsgStarted: MsgBackoffStarted, MsgEnded: MsgBackoffEnded}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	client.gate = gate
	client.host = "redis.test:6379"
	client.log = log
	return client, sink
}

// gateTestTake takes one hit under a StepBudget deadline and returns the error.
func gateTestTake(client *Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
	defer cancel()
	_, err := client.Take(ctx, "rl:edge:per-ip:k", Limit{Bucket: "per-ip", Burst: 5, Requests: 5, Window: time.Minute})
	return err
}

// countTestLogLines is how many JSON lines of logs carry msg at level.
func countTestLogLines(t *testing.T, logs, level, msg string) int {
	t.Helper()
	total := 0
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if entry["level"] == level && entry["msg"] == msg {
			total++
		}
	}
	return total
}

// TestTake_gateTripsSkipsRedisAndRecovers proves the Redis admission gate: after admission.TripFailures
// failed takes, Take returns ErrGateSkip without calling the counter and logs WARN MsgBackoffStarted once;
// after the cooldown one probe reaches Redis, and its success logs INFO MsgBackoffEnded once.
func TestTake_gateTripsSkipsRedisAndRecovers(t *testing.T) {
	counter := &switchCounter{down: true}
	client, sink := newGateTestClient(t, counter, 10)
	now := time.Now()
	client.GateForTest().Inner().SetNowForTest(func() time.Time { return now })

	for i := range admission.TripFailures {
		if err := gateTestTake(client); !errors.Is(err, errTestRedisDown) {
			t.Fatalf("take %d: error %v, want %v", i+1, err, errTestRedisDown)
		}
	}
	for range 3 {
		if err := gateTestTake(client); !errors.Is(err, ErrGateSkip) {
			t.Fatalf("after the trip: error %v, want %v", err, ErrGateSkip)
		}
	}
	if got := counter.callCount(); got != admission.TripFailures {
		t.Fatalf("counter reached %d times, want %d: a skip must not call Redis", got, admission.TripFailures)
	}
	logs := sink.String()
	if got := countTestLogLines(t, logs, "WARN", MsgBackoffStarted); got != 1 {
		t.Fatalf("%d WARN %q, want 1\n%s", got, MsgBackoffStarted, logs)
	}
	if got := countTestLogLines(t, logs, "ERROR", MsgRedisUnavailable); got != 1 {
		t.Fatalf("%d ERROR %q, want 1 (debounced)\n%s", got, MsgRedisUnavailable, logs)
	}
	if !strings.Contains(logs, `"host":"redis.test:6379"`) || !strings.Contains(logs, `"error":"redis: connection refused"`) {
		t.Fatalf("the ERROR must carry host and error:\n%s", logs)
	}

	counter.set(false)
	now = now.Add(11 * time.Second)
	for range 3 {
		if err := gateTestTake(client); err != nil {
			t.Fatalf("after the cooldown: %v", err)
		}
	}
	logs = sink.String()
	if got := countTestLogLines(t, logs, "INFO", MsgBackoffEnded); got != 1 {
		t.Fatalf("%d INFO %q, want 1\n%s", got, MsgBackoffEnded, logs)
	}
	if got := countTestLogLines(t, logs, "WARN", MsgBackoffStarted); got != 1 {
		t.Fatalf("recovery: %d WARN %q, want still 1\n%s", got, MsgBackoffStarted, logs)
	}
}

// TestTake_canceledRequestDoesNotTripTheGate proves takes whose request was canceled are neither reported
// to the gate nor logged.
func TestTake_canceledRequestDoesNotTripTheGate(t *testing.T) {
	counter := &switchCounter{down: true}
	client, sink := newGateTestClient(t, counter, 10)
	for range 2 * admission.TripFailures {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.Take(ctx, "rl:edge:per-ip:k", Limit{Bucket: "per-ip", Requests: 5, Window: time.Minute}); errors.Is(err, ErrGateSkip) {
			t.Fatal("a canceled request must not trip the gate")
		}
	}
	if client.GateForTest().BackingOff() {
		t.Fatal("the gate must not back off on canceled requests")
	}
	if logs := sink.String(); countTestLogLines(t, logs, "ERROR", MsgRedisUnavailable) != 0 {
		t.Fatalf("a canceled request must not log the outage:\n%s", logs)
	}
}

// TestTake_withoutGateLogsDebouncedErrorAndNeverSkips proves that with rateLimitUnhealthyBackOffPeriodSecs 0
// every take reaches Redis and the outage is one ERROR per debounce window, as for ModSec.
func TestTake_withoutGateLogsDebouncedErrorAndNeverSkips(t *testing.T) {
	counter := &switchCounter{down: true}
	client, sink := newGateTestClient(t, counter, 0)
	if client.GateForTest() != nil {
		t.Fatal("period 0 must build no gate")
	}
	for range 2 * admission.TripFailures {
		if err := gateTestTake(client); !errors.Is(err, errTestRedisDown) {
			t.Fatalf("error %v, want %v", err, errTestRedisDown)
		}
	}
	logs := sink.String()
	if got := countTestLogLines(t, logs, "ERROR", MsgRedisUnavailable); got != 1 {
		t.Fatalf("%d ERROR %q, want 1\n%s", got, MsgRedisUnavailable, logs)
	}
	if strings.Contains(logs, `"level":"WARN"`) {
		t.Fatalf("no gate, no backoff WARN:\n%s", logs)
	}
}

// TestTake_testClientLogsNothing proves a NewTestClient (no gate, no logger) takes without logging.
func TestTake_testClientLogsNothing(t *testing.T) {
	client, err := NewTestClient(deadRedisTestSettings(0), &switchCounter{down: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := gateTestTake(client); !errors.Is(err, errTestRedisDown) {
		t.Fatalf("error %v, want %v", err, errTestRedisDown)
	}
}

// TestCharge_gateSkipStopsTheWalk proves a gate skip is the verdict error, so the subscriber can tell it
// from a counter error.
func TestCharge_gateSkipStopsTheWalk(t *testing.T) {
	counter := &switchCounter{down: true}
	client, _ := newGateTestClient(t, counter, 10)
	for range admission.TripFailures {
		_ = gateTestTake(client)
	}
	verdict := chargeTest(client.Buckets(), client, "GET", "/", "198.51.100.7")
	if !errors.Is(verdict.Err, ErrGateSkip) {
		t.Fatalf("verdict error %v, want %v", verdict.Err, ErrGateSkip)
	}
}

// TestOpen_gateOnlyWhereASuccessProvesRedis proves Open builds the gate for the token bucket and the exact
// sliding window with a period above 0, and none for the buffered sliding window or a period of 0; and that
// the period is part of the ownership key.
func TestOpen_gateOnlyWhereASuccessProvesRedis(t *testing.T) {
	cases := []struct {
		name      string
		algorithm string
		syncRate  time.Duration
		period    int64
		wantGate  bool
	}{
		{"exact", AlgorithmSlidingWindow, 0, 10, true},
		{"token bucket", AlgorithmTokenBucket, 200 * time.Millisecond, 10, true},
		{"buffered", "", 200 * time.Millisecond, 10, false},
		{"exact period 0", AlgorithmSlidingWindow, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reclaim.ResetForTestWith(0)
			t.Cleanup(func() { reclaim.ResetForTest() })
			settings := deadRedisTestSettings(tc.syncRate)
			settings.Algorithm = tc.algorithm
			settings.BackOffPeriodSecs = tc.period
			client, err := Open(context.Background(), "edge", settings, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if got := client.GateForTest() != nil; got != tc.wantGate {
				t.Fatalf("gate=%v, want %v", got, tc.wantGate)
			}
		})
	}
	short := deadRedisTestSettings(0)
	long := deadRedisTestSettings(0)
	long.BackOffPeriodSecs = 30
	if OwnershipKey("edge", short) == OwnershipKey("edge", long) {
		t.Fatal("a changed backoff period must open another Client")
	}
}

// TestOpen_deadRedisTripsTheGateAtInfo proves, on a real Client in exact mode against a dead address, that
// the outage logs one debounced ERROR and one WARN MsgBackoffStarted with the owner's attributes at the
// default INFO level, and that the take after the trip does not dial.
func TestOpen_deadRedisTripsTheGateAtInfo(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	logger.ResetDebounceForTest()
	t.Cleanup(logger.ResetDebounceForTest)
	sink := &lockedLogSink{}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings := deadRedisTestSettings(0)
	settings.BackOffPeriodSecs = 10
	client, err := Open(context.Background(), "edge", settings, log)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i := range admission.TripFailures {
		if err := gateTestTake(client); err == nil || errors.Is(err, ErrGateSkip) {
			t.Fatalf("take %d: error %v, want a Redis error", i+1, err)
		}
	}
	started := time.Now()
	if err := gateTestTake(client); !errors.Is(err, ErrGateSkip) {
		t.Fatalf("after the trip: error %v, want %v", err, ErrGateSkip)
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("a skipped take took %s: it must not dial", elapsed)
	}
	logs := sink.String()
	if got := countTestLogLines(t, logs, "WARN", MsgBackoffStarted); got != 1 {
		t.Fatalf("%d WARN %q, want 1\n%s", got, MsgBackoffStarted, logs)
	}
	if got := countTestLogLines(t, logs, "ERROR", MsgRedisUnavailable); got != 1 {
		t.Fatalf("%d ERROR %q, want 1\n%s", got, MsgRedisUnavailable, logs)
	}
	for _, attr := range []string{`"traefikName":"edge"`, `"instanceName":"shared"`, `"host":"127.0.0.1:1"`, `"leg":"ratelimit"`} {
		if !strings.Contains(logs, attr) {
			t.Fatalf("the outage lines must carry %s:\n%s", attr, logs)
		}
	}
}

// TestOpen_warnsWhenTheFailureActionCannotApply proves the owner logs one WARN at creation when its
// failure or backoff action blocks (ban, captcha) on the buffered sliding window, and none otherwise.
func TestOpen_warnsWhenTheFailureActionCannotApply(t *testing.T) {
	cases := []struct {
		name          string
		algorithm     string
		syncRate      time.Duration
		failureAction string
		backOffAction string
		want          int
	}{
		{"buffered ban", "", 200 * time.Millisecond, "ban", "passthrough", 1},
		{"buffered captcha", AlgorithmSlidingWindow, 200 * time.Millisecond, "captcha", "passthrough", 1},
		{"buffered backoff ban", "", 200 * time.Millisecond, "passthrough", "ban", 1},
		{"buffered passthrough", "", 200 * time.Millisecond, "passthrough", "passthrough", 0},
		{"exact ban", AlgorithmSlidingWindow, 0, "ban", "ban", 0},
		{"token bucket ban", AlgorithmTokenBucket, 200 * time.Millisecond, "ban", "ban", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reclaim.ResetForTestWith(0)
			t.Cleanup(func() { reclaim.ResetForTest() })
			sink := &lockedLogSink{}
			log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
			settings := deadRedisTestSettings(tc.syncRate)
			settings.Algorithm = tc.algorithm
			settings.Policy.FailureAction = tc.failureAction
			settings.Policy.BackOffAction = tc.backOffAction
			client, err := Open(context.Background(), "edge", settings, log)
			if err != nil {
				t.Fatalf("the configuration must be accepted: %v", err)
			}
			defer client.Close()
			// Reusing the Client does not warn again.
			if _, err := Open(context.Background(), "edge", settings, log); err != nil {
				t.Fatal(err)
			}
			logs := sink.String()
			if got := countTestLogLines(t, logs, "WARN", msgFailureActionBuffered); got != tc.want {
				t.Fatalf("%d WARN %q, want %d\n%s", got, msgFailureActionBuffered, tc.want, logs)
			}
			if tc.want == 1 && (!strings.Contains(logs, `"failureAction":"`+tc.failureAction+`"`) ||
				!strings.Contains(logs, `"backOffAction":"`+tc.backOffAction+`"`) ||
				!strings.Contains(logs, "rateLimitSyncRate: 0 or rateLimitAlgorithm: tokenBucket")) {
				t.Fatalf("the WARN must name both actions and the fix:\n%s", logs)
			}
		})
	}
}
