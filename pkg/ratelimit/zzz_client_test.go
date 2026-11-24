package ratelimit

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/logger"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// deadRedisTestSettings is one per-ip bucket and the default policy on a port where nothing listens;
// Open must not dial it.
func deadRedisTestSettings(syncRate time.Duration) Settings {
	return Settings{
		Buckets:      []BucketRule{{Name: "per-ip", Requests: 5, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}}},
		InstanceName: "shared",
		Policy:       Policy{FailureAction: "passthrough", ResponseHeaders: true, StatusCode: 429},
		Redis:        RedisSettings{Host: "127.0.0.1:1", SyncRate: syncRate},
	}
}

// redisOnlyTestSettings is deadRedisTestSettings in exact mode pointed at redis instead.
func redisOnlyTestSettings(redis RedisSettings) Settings {
	settings := deadRedisTestSettings(0)
	settings.Redis = redis
	return settings
}

// TestOpen_sharesOneClientPerMiddlewareAndSettings proves equal keys reuse the Client, a changed
// Redis setting, algorithm, bucket row, policy setting, or middleware name opens another, and a changed
// instance name keeps it.
func TestOpen_sharesOneClientPerMiddlewareAndSettings(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	ctx := context.Background()
	first, err := Open(ctx, "edge", deadRedisTestSettings(200*time.Millisecond), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	again, err := Open(ctx, "edge", deadRedisTestSettings(200*time.Millisecond), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("equal middleware name and settings must share one Client")
	}
	renamed := deadRedisTestSettings(200 * time.Millisecond)
	renamed.InstanceName = "renamed"
	if kept, renameErr := Open(ctx, "edge", renamed, slog.Default()); renameErr != nil || kept != first {
		t.Fatalf("a changed instance name must keep the Client (err %v)", renameErr)
	}
	changes := map[string]func(*Settings, *string){
		"syncRate":        func(settings *Settings, _ *string) { settings.Redis.SyncRate = 0 },
		"algorithm":       func(settings *Settings, _ *string) { settings.Algorithm = AlgorithmTokenBucket },
		"host":            func(settings *Settings, _ *string) { settings.Redis.Host = "127.0.0.1:2" },
		"password":        func(settings *Settings, _ *string) { settings.Redis.Password = "secret" },
		"database":        func(settings *Settings, _ *string) { settings.Redis.Database = "1" },
		"middleware":      func(_ *Settings, name *string) { *name = "edge-b" },
		"bucket requests": func(settings *Settings, _ *string) { settings.Buckets[0].Requests = 6 },
		"bucket path":     func(settings *Settings, _ *string) { settings.Buckets[0].Path = "^/login" },
		"failureAction":   func(settings *Settings, _ *string) { settings.Policy.FailureAction = "ban" },
		"statusCode":      func(settings *Settings, _ *string) { settings.Policy.StatusCode = 503 },
		"responseHeaders": func(settings *Settings, _ *string) { settings.Policy.ResponseHeaders = false },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			settings := deadRedisTestSettings(200 * time.Millisecond)
			middlewareName := "edge"
			change(&settings, &middlewareName)
			other, err := Open(ctx, middlewareName, settings, slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if other == first {
				t.Fatalf("changed %s must open a new Client", name)
			}
		})
	}
}

// TestOpen_carriesBucketsAndPolicy proves the Client keeps the compiled buckets and the policy it was
// opened with, that its started line names the instance, and that a nil Client has no incarnation.
func TestOpen_carriesBucketsAndPolicy(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sink := &lockedLogSink{}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings := deadRedisTestSettings(0)
	settings.Policy = Policy{FailureAction: "ban", ResponseHeaders: false, StatusCode: 503}
	client, err := Open(context.Background(), "edge", settings, log)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.Buckets() == nil || client.Policy() != settings.Policy {
		t.Fatalf("buckets=%v policy=%+v, want compiled buckets and %+v", client.Buckets(), client.Policy(), settings.Policy)
	}
	if client.Incarnation() == "" {
		t.Fatal("an opened Client must have an incarnation")
	}
	started := sink.String()
	for _, attr := range []string{`"msg":"` + msgInstanceStarted + `"`, `"leg":"ratelimit"`, `"instanceName":"shared"`, `"incarnation":"` + client.Incarnation() + `"`, `"algorithm":"slidingWindow"`} {
		if !strings.Contains(started, attr) {
			t.Fatalf("started line lacks %s: %s", attr, started)
		}
	}
	if got := (*Client)(nil).Incarnation(); got != "" {
		t.Fatalf("nil Client incarnation %q, want empty", got)
	}
}

// TestOwnershipKey_algorithmAndBurst proves an empty algorithm keys as slidingWindow, and that under
// tokenBucket a burst edit is a new key.
func TestOwnershipKey_algorithmAndBurst(t *testing.T) {
	empty := deadRedisTestSettings(0)
	sliding := deadRedisTestSettings(0)
	sliding.Algorithm = AlgorithmSlidingWindow
	if OwnershipKey("edge", empty) != OwnershipKey("edge", sliding) {
		t.Fatal("an empty algorithm must key as slidingWindow")
	}
	tokenBucket := deadRedisTestSettings(0)
	tokenBucket.Algorithm = AlgorithmTokenBucket
	burst := deadRedisTestSettings(0)
	burst.Algorithm = AlgorithmTokenBucket
	burst.Buckets[0].Burst = 9
	if OwnershipKey("edge", tokenBucket) == OwnershipKey("edge", sliding) || OwnershipKey("edge", burst) == OwnershipKey("edge", tokenBucket) {
		t.Fatal("the algorithm and a burst edit must each change the key")
	}
}

// TestOpen_tokenBucketClient proves a tokenBucket owner builds no sliding-window limiter, logs its
// algorithm, answers a Redis outage with an error even with a buffered sync rate (no local count),
// sleeps and wakes without a limiter, and closes twice.
func TestOpen_tokenBucketClient(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	sink := &lockedLogSink{}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelInfo}))
	settings := deadRedisTestSettings(200 * time.Millisecond)
	settings.Algorithm = AlgorithmTokenBucket
	settings.Buckets[0].Burst = 8
	client, err := Open(context.Background(), "edge", settings, log)
	if err != nil {
		t.Fatalf("Open against a dead address must succeed: %v", err)
	}
	if client.limiter != nil {
		t.Fatal("a tokenBucket Client must not build the sliding-window limiter")
	}
	counter, isTokenBucket := client.counter.(*tokenBucketCounter)
	if !isTokenBucket || counter.buckets["per-ip"] == nil {
		t.Fatalf("counter=%T, want one token bucket for per-ip", client.counter)
	}
	if started := sink.String(); !strings.Contains(started, `"algorithm":"tokenBucket"`) {
		t.Fatalf("started line lacks the algorithm: %s", started)
	}
	assertTakeFailsWithinBudget(t, client)
	if _, missingErr := client.Take(context.Background(), "rl:edge:other:x", Limit{Bucket: "other", Burst: 1, Requests: 1, Window: time.Second}); missingErr == nil {
		t.Fatal("a Take for a bucket the owner does not have must fail")
	}
	client.Sleep()
	client.Wake()
	client.Close()
	client.Close()
}

// TestTokenBucketTTL_coversAFullRefill proves the TTL is the full refill rounded up to whole seconds, at
// least 1s, and that the rate is requests per window.
func TestTokenBucketTTL_coversAFullRefill(t *testing.T) {
	tests := []struct {
		limit Limit
		want  time.Duration
	}{
		{limit: Limit{Burst: 5, Requests: 5, Window: time.Minute}, want: time.Minute},
		{limit: Limit{Burst: 3, Requests: 1, Window: 5 * time.Second}, want: 15 * time.Second},
		{limit: Limit{Burst: 10, Requests: 7, Window: time.Minute}, want: 86 * time.Second},
		{limit: Limit{Burst: 1, Requests: 100, Window: time.Second}, want: time.Second},
	}
	for _, tt := range tests {
		if got := tokenBucketTTL(tt.limit); got != tt.want {
			t.Fatalf("tokenBucketTTL(%+v)=%s want %s", tt.limit, got, tt.want)
		}
	}
	if got := tokenBucketRate(Limit{Requests: 6, Window: time.Minute}); got != 0.1 {
		t.Fatalf("rate=%v want 0.1 per second", got)
	}
}

// TestOpen_invalidBucketsFail proves Open compiles the bucket rows and fails on an invalid one.
func TestOpen_invalidBucketsFail(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	settings := deadRedisTestSettings(0)
	settings.Buckets[0].Window = "500ms"
	if _, err := Open(context.Background(), "edge", settings, slog.Default()); err == nil || !strings.Contains(err.Error(), "bucket 0") {
		t.Fatalf("Open with an invalid bucket: error = %v, want one naming bucket 0", err)
	}
}

// TestOpen_deadRedisFailsAtTakeWithinTheBudget proves Open does not dial and that an exact-mode Take
// against a dead address errors within the step budget.
func TestOpen_deadRedisFailsAtTakeWithinTheBudget(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	client, err := Open(context.Background(), "edge", deadRedisTestSettings(0), slog.Default())
	if err != nil {
		t.Fatalf("Open against a dead address must succeed: %v", err)
	}
	defer client.Close()
	assertTakeFailsWithinBudget(t, client)
}

// TestOpen_deadRedisBufferedKeepsTheLocalLimit proves a buffered Take against a dead address answers
// within the step budget with no error and keeps this replica's limit (windowcounter v1.0.9+).
func TestOpen_deadRedisBufferedKeepsTheLocalLimit(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	client, err := Open(context.Background(), "edge", deadRedisTestSettings(200*time.Millisecond), slog.Default())
	if err != nil {
		t.Fatalf("Open against a dead address must succeed: %v", err)
	}
	defer client.Close()
	key := "rl:edge:b:" + t.Name()
	for hit := 1; hit <= 3; hit++ {
		ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
		started := time.Now()
		status, takeErr := client.Take(ctx, key, Limit{Bucket: "per-ip", Burst: 2, Requests: 2, Window: time.Minute})
		cancel()
		if takeErr != nil {
			t.Fatalf("hit %d: buffered Take must not fail on a Redis outage: %v", hit, takeErr)
		}
		if elapsed := time.Since(started); elapsed > StepBudget+100*time.Millisecond {
			t.Fatalf("hit %d: Take took %s, budget %s", hit, elapsed, StepBudget)
		}
		if want := hit <= 2; status.Allowed != want {
			t.Fatalf("hit %d: allowed=%v, want %v (local limit 2)", hit, status.Allowed, want)
		}
	}
}

// TestClient_silentRedisAndClose proves a Redis that accepts but never answers costs at most the budget,
// and that Close closes the Redis client: a Take after Close does not dial again.
func TestClient_silentRedisAndClose(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var accepted atomic.Int64
	silentConns := make(chan net.Conn, 64)
	t.Cleanup(func() {
		for {
			select {
			case conn := <-silentConns:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted.Add(1)
			silentConns <- conn
		}
	}()
	client, err := Open(context.Background(), "edge", redisOnlyTestSettings(RedisSettings{Host: listener.Addr().String()}), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	assertTakeFailsWithinBudget(t, client)
	if accepted.Load() == 0 {
		t.Fatal("Take must dial the silent Redis")
	}
	client.Close()
	client.Close()
	dialsBeforeClose := accepted.Load()
	assertTakeFailsWithinBudget(t, client)
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() != dialsBeforeClose {
		t.Fatal("Take after Close must not dial: Close must close the Redis client")
	}
}

// assertTakeFailsWithinBudget takes one hit under a StepBudget deadline and expects an error in time.
func assertTakeFailsWithinBudget(t *testing.T, client *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
	defer cancel()
	started := time.Now()
	_, err := client.Take(ctx, "rl:edge:per-ip:"+t.Name(), Limit{Bucket: "per-ip", Burst: 5, Requests: 5, Window: time.Minute})
	if err == nil {
		t.Fatal("Take must fail")
	}
	if elapsed := time.Since(started); elapsed > StepBudget+100*time.Millisecond {
		t.Fatalf("Take took %s, budget %s", elapsed, StepBudget)
	}
}

// TestClient_wrongPasswordLogsLibraryLinesAtDebug proves a Redis that rejects AUTH costs DEBUG lines from
// the library: the simpleredis WARN and ERROR lines of each failed dial are capped at DEBUG, and the only
// line above DEBUG is the Client's debounced ERROR MsgRedisUnavailable, however many takes fail.
func TestClient_wrongPasswordLogsLibraryLinesAtDebug(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	logger.ResetDebounceForTest()
	t.Cleanup(logger.ResetDebounceForTest)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 512)
				for {
					if _, readErr := conn.Read(buf); readErr != nil {
						return
					}
					if _, writeErr := conn.Write([]byte("-WRONGPASS invalid username-password pair\r\n")); writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	sink := &lockedLogSink{}
	log := slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
	client, err := Open(context.Background(), "edge", redisOnlyTestSettings(RedisSettings{Host: listener.Addr().String(), Password: "wrong"}), log)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertTakeFailsWithinBudget(t, client)
	assertTakeFailsWithinBudget(t, client)
	logs := sink.String()
	if strings.Contains(logs, `"level":"WARN"`) || strings.Count(logs, `"level":"ERROR"`) != 1 ||
		countTestLogLines(t, logs, "ERROR", MsgRedisUnavailable) != 1 {
		t.Fatalf("a failed dial must log no library WARN or ERROR, only one ERROR %q:\n%s", MsgRedisUnavailable, logs)
	}
	if !strings.Contains(logs, `"msg":"dial: redis:noauth"`) {
		t.Fatalf("the library NOAUTH line must still be written at DEBUG:\n%s", logs)
	}
}

// lockedLogSink is a log writer safe for the library goroutines that log while the test reads.
type lockedLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (sink *lockedLogSink) Write(p []byte) (int, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buf.Write(p)
}

func (sink *lockedLogSink) String() string {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.buf.String()
}
