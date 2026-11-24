//go:build realredis

package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
	"github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis"
)

const (
	// realRedisWindow is the window every case counts in. Long enough that a case never crosses it.
	realRedisWindow = time.Minute
	// realRedisLimit is the requests per window every case allows.
	realRedisLimit = 5
)

// realRedisTestLimit is the sliding-window Limit every Take of the sliding-window cases charges.
func realRedisTestLimit() Limit {
	return Limit{Bucket: "b", Burst: realRedisLimit, Requests: realRedisLimit, Window: realRedisWindow}
}

// newRealRedisSlidingWindowClient builds a sliding-window Client on addr with syncRate, outside the reclaim table.
func newRealRedisSlidingWindowClient(addr string, syncRate time.Duration) (*Client, error) {
	return newClient(RedisSettings{Host: addr, SyncRate: syncRate}, AlgorithmSlidingWindow, 0, nil, slog.Default())
}

// TestMain waits for Dragonfly (or Redis) at REALREDIS_ADDR before the suite.
func TestMain(m *testing.M) {
	if err := waitRealRedis(realRedisAddr(), 20*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "realredis: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// realRedisAddr is host:port. CI publishes Dragonfly on 127.0.0.1:6379.
func realRedisAddr() string {
	addr := strings.TrimSpace(os.Getenv("REALREDIS_ADDR"))
	if addr == "" {
		return "127.0.0.1:6379"
	}
	return addr
}

// waitRealRedis retries one exact-mode Take until it succeeds or budget expires.
func waitRealRedis(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		client, err := newRealRedisSlidingWindowClient(addr, 0)
		if err != nil {
			return err
		}
		_, last := client.Take(context.Background(), "rl:wait", Limit{Bucket: "wait", Burst: 1_000_000, Requests: 1_000_000, Window: realRedisWindow})
		client.Close()
		if last == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no Redis at %s: %w", addr, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// newRealRedisTestClient opens a Client on the real server with syncRate, closed at test end.
func newRealRedisTestClient(t *testing.T, syncRate time.Duration) *Client {
	t.Helper()
	client, err := newRealRedisSlidingWindowClient(realRedisAddr(), syncRate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

// realRedisTestKey is a counter key no other case or earlier run uses (counters outlive a run by two windows).
func realRedisTestKey(t *testing.T) string {
	t.Helper()
	waitAwayFromWindowEnd(realRedisWindow)
	return fmt.Sprintf("rl:%s:%d", strings.ReplaceAll(t.Name(), "/", "-"), time.Now().UnixNano())
}

// waitAwayFromWindowEnd waits out the last 5 seconds of the current window, so the hits of one case
// fall in one window.
func waitAwayFromWindowEnd(window time.Duration) {
	windowSec := int64(window / time.Second)
	now := time.Now()
	windowEnd := time.Unix((now.Unix()/windowSec+1)*windowSec, 0)
	if remaining := windowEnd.Sub(now); remaining < 5*time.Second {
		time.Sleep(remaining + 100*time.Millisecond)
	}
}

// takeRealRedisTest takes one hit against realRedisLimit and fails the test on an error.
func takeRealRedisTest(t *testing.T, client *Client, key string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
	defer cancel()
	status, err := client.Take(ctx, key, realRedisTestLimit())
	if err != nil {
		t.Fatal(err)
	}
	return status.Allowed
}

// TestRealRedis_exactModeDeniesTheHitAfterTheLimit proves sync rate 0 denies request requests+1.
func TestRealRedis_exactModeDeniesTheHitAfterTheLimit(t *testing.T) {
	client := newRealRedisTestClient(t, 0)
	key := realRedisTestKey(t)
	for hit := 1; hit <= realRedisLimit; hit++ {
		if !takeRealRedisTest(t, client, key) {
			t.Fatalf("hit %d of 5 denied", hit)
		}
	}
	if takeRealRedisTest(t, client, key) {
		t.Fatal("hit 6 of 5 allowed")
	}
}

// TestRealRedis_bufferedModeDeniesAfterAFlush proves a second process sees the first one's hits once
// they are flushed: client A spends the limit, flushes, and client B's first hit is denied.
func TestRealRedis_bufferedModeDeniesAfterAFlush(t *testing.T) {
	first := newRealRedisTestClient(t, 200*time.Millisecond)
	second := newRealRedisTestClient(t, 200*time.Millisecond)
	key := realRedisTestKey(t)
	for hit := 1; hit <= realRedisLimit; hit++ {
		if !takeRealRedisTest(t, first, key) {
			t.Fatalf("first: hit %d of 5 denied", hit)
		}
	}
	time.Sleep(600 * time.Millisecond)
	if takeRealRedisTest(t, second, key) {
		t.Fatal("second: hit 6 of 5 allowed after the first client flushed")
	}
}

// TestRealRedis_twoClientsShareACounter proves two processes in exact mode count into one key.
func TestRealRedis_twoClientsShareACounter(t *testing.T) {
	first := newRealRedisTestClient(t, 0)
	second := newRealRedisTestClient(t, 0)
	key := realRedisTestKey(t)
	denied := 0
	for range 3 {
		for _, client := range []*Client{first, second} {
			if !takeRealRedisTest(t, client, key) {
				denied++
			}
		}
	}
	if denied == 0 {
		t.Fatal("6 hits over two clients on a limit of 5 must deny at least one")
	}
}

// TestRealRedis_deadAddressReturnsAnError proves an unreachable server is an error, not a verdict, in exact mode.
func TestRealRedis_deadAddressReturnsAnError(t *testing.T) {
	client, err := newRealRedisSlidingWindowClient("127.0.0.1:1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
	defer cancel()
	if _, err := client.Take(ctx, realRedisTestKey(t), realRedisTestLimit()); err == nil {
		t.Fatal("dead address must return an error")
	}
}

// TestRealRedis_bucketEditKeepsTheCount proves an owner's bucket edit opens a new Client that keeps
// counting the same Redis key: bucket login allows 3, then 5 per window, and a client that already
// sent 3 gets 2 more before the edited bucket answers.
func TestRealRedis_bucketEditKeepsTheCount(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	waitAwayFromWindowEnd(realRedisWindow)
	middlewareName := fmt.Sprintf("edit-%d", time.Now().UnixNano())
	settingsFor := func(requests int) Settings {
		return Settings{
			Buckets: []BucketRule{{Name: "login", Requests: requests, Window: "1m", Key: []KeyPart{{From: KeyFromIP}}}},
			Policy:  Policy{FailureAction: "passthrough", ResponseHeaders: true, StatusCode: 429},
			Redis:   RedisSettings{Host: realRedisAddr()},
		}
	}
	charge := func(client *Client) Verdict {
		ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
		defer cancel()
		return client.Buckets().Charge(ctx, client, middlewareName, httptest.NewRequest(http.MethodGet, "http://example.com/login", nil), net.ParseIP("198.51.100.9"), false)
	}
	before, err := Open(context.Background(), middlewareName, settingsFor(3), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	for hit := 1; hit <= 3; hit++ {
		if verdict := charge(before); verdict.Err != nil || verdict.RateLimit.Name != "" {
			t.Fatalf("hit %d before the edit: %+v, want allowed", hit, verdict)
		}
	}
	after, err := Open(context.Background(), middlewareName, settingsFor(5), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatal("a bucket edit must open a new Client")
	}
	for hit := 4; hit <= 6; hit++ {
		verdict := charge(after)
		if verdict.Err != nil {
			t.Fatalf("hit %d after the edit: %v", hit, verdict.Err)
		}
		if wantLimited := hit == 6; (verdict.RateLimit.Name == "login") != wantLimited {
			t.Fatalf("hit %d after the edit: ratelimit bucket %q, want limited=%v (count kept from before the edit)", hit, verdict.RateLimit.Name, wantLimited)
		}
	}
}

// realRedisKeyProbeScript returns the type and TTL of KEYS[1] and whether KEYS[2] exists.
const realRedisKeyProbeScript = `local kind = redis.call('type', KEYS[1])
return {kind['ok'], tostring(redis.call('ttl', KEYS[1])), tostring(redis.call('exists', KEYS[2]))}`

// TestRealRedis_tokenBucketBurstRetryAfterAndRefill proves a tokenBucket owner on Dragonfly: burst 3 at
// requests 1 per 2s admits 3 at once, answers the fourth with Retry-After 2s, takes no token for the
// answered hits, admits one more after the refill, and keeps its state in one hash under <key>:tb with a
// TTL of one full refill (6s), never under the sliding window's <key>:<window start>.
func TestRealRedis_tokenBucketBurstRetryAfterAndRefill(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	middlewareName := fmt.Sprintf("tb-%d", time.Now().UnixNano())
	clientIP := "198.51.100.10"
	client, err := Open(context.Background(), middlewareName, Settings{
		Algorithm: AlgorithmTokenBucket,
		Buckets:   []BucketRule{{Name: "tb", Requests: 1, Window: "2s", Burst: 3, Key: []KeyPart{{From: KeyFromIP}}}},
		Policy:    Policy{FailureAction: "ban", ResponseHeaders: true, StatusCode: 429},
		Redis:     RedisSettings{Host: realRedisAddr(), SyncRate: 200 * time.Millisecond},
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	charge := func() Verdict {
		ctx, cancel := context.WithTimeout(context.Background(), StepBudget)
		defer cancel()
		return client.Buckets().Charge(ctx, client, middlewareName, httptest.NewRequest(http.MethodGet, "http://example.com/", nil), net.ParseIP(clientIP), false)
	}
	// Burst: three at once, then the refill answers.
	for hit := 1; hit <= 3; hit++ {
		if verdict := charge(); verdict.Err != nil || verdict.RateLimit.Name != "" {
			t.Fatalf("hit %d of burst 3: %+v", hit, verdict)
		}
	}
	for hit := 4; hit <= 5; hit++ {
		verdict := charge()
		if verdict.Err != nil || verdict.RateLimit.Name != "tb" || verdict.RateLimit.RetryAfter != 2*time.Second {
			t.Fatalf("hit %d: %+v, want tb with Retry-After 2s", hit, verdict)
		}
	}
	// Key layout: one hash under :tb with a TTL of one full refill, and no sliding-window key.
	key := redisCounterKey(middlewareName, "tb", []string{clientIP})
	windowStart := time.Now().Unix() / 2 * 2
	probe, err := client.redis.Eval(context.Background(), realRedisKeyProbeScript, simpleredis.ScriptSHA1Hex(realRedisKeyProbeScript),
		[]string{key + ":tb", fmt.Sprintf("%s:%d", key, windowStart)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(probe) != 3 || string(probe[0]) != "hash" || string(probe[2]) != "0" {
		t.Fatalf("probe=%q, want a hash under :tb and no sliding-window key", probe)
	}
	if ttl := string(probe[1]); ttl != "6" && ttl != "5" {
		t.Fatalf("ttl=%s, want one full refill (6s)", ttl)
	}
	// Refill: the answered hits took no token, so one token is back after 2s.
	time.Sleep(2100 * time.Millisecond)
	if verdict := charge(); verdict.Err != nil || verdict.RateLimit.Name != "" {
		t.Fatalf("after the refill: %+v, want allowed", verdict)
	}
	if verdict := charge(); verdict.RateLimit.Name != "tb" {
		t.Fatalf("second hit after one refill: %+v, want tb", verdict)
	}
}
