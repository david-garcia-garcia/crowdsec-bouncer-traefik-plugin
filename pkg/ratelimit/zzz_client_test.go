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

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/reclaim"
)

// deadRedisTestSettings points at a port where nothing listens; Open must not dial it.
func deadRedisTestSettings(syncRate time.Duration) RedisSettings {
	return RedisSettings{Host: "127.0.0.1:1", SyncRate: syncRate}
}

// TestOpen_sharesOneClientPerMiddlewareAndSettings proves equal keys reuse the Client and a changed
// sync rate, host, password, database, or middleware name opens another.
func TestOpen_sharesOneClientPerMiddlewareAndSettings(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	ctx := context.Background()
	base := deadRedisTestSettings(200 * time.Millisecond)
	first, err := Open(ctx, "edge", base, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	again, err := Open(ctx, "edge", base, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("equal middleware name and settings must share one Client")
	}
	changes := map[string]func(*RedisSettings, *string){
		"syncRate":   func(settings *RedisSettings, _ *string) { settings.SyncRate = 0 },
		"host":       func(settings *RedisSettings, _ *string) { settings.Host = "127.0.0.1:2" },
		"password":   func(settings *RedisSettings, _ *string) { settings.Password = "secret" },
		"database":   func(settings *RedisSettings, _ *string) { settings.Database = "1" },
		"middleware": func(_ *RedisSettings, name *string) { *name = "edge-b" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			settings := base
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

// TestOpen_deadRedisFailsAtTakeWithinTheBudget proves Open does not dial and that a Take against a dead
// address errors within the step budget, in exact and buffered mode.
func TestOpen_deadRedisFailsAtTakeWithinTheBudget(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
	for _, syncRate := range []time.Duration{0, 200 * time.Millisecond} {
		t.Run(syncRate.String(), func(t *testing.T) {
			client, err := Open(context.Background(), "edge", deadRedisTestSettings(syncRate), slog.Default())
			if err != nil {
				t.Fatalf("Open against a dead address must succeed: %v", err)
			}
			defer client.Close()
			assertTakeFailsWithinBudget(t, client)
		})
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
	client, err := Open(context.Background(), "edge", RedisSettings{Host: listener.Addr().String()}, slog.Default())
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
	_, _, err := client.Take(ctx, "rl:edge:b:"+t.Name(), 5, time.Minute)
	if err == nil {
		t.Fatal("Take must fail")
	}
	if elapsed := time.Since(started); elapsed > StepBudget+100*time.Millisecond {
		t.Fatalf("Take took %s, budget %s", elapsed, StepBudget)
	}
}

// TestClient_wrongPasswordLogsAtDebugOnly proves a Redis that rejects AUTH costs DEBUG lines only:
// the simpleredis WARN and ERROR lines of each failed dial are capped at DEBUG.
func TestClient_wrongPasswordLogsAtDebugOnly(t *testing.T) {
	reclaim.ResetForTestWith(0)
	t.Cleanup(func() { reclaim.ResetForTest() })
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
	client, err := Open(context.Background(), "edge", RedisSettings{Host: listener.Addr().String(), Password: "wrong"}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertTakeFailsWithinBudget(t, client)
	logs := sink.String()
	if strings.Contains(logs, `"level":"WARN"`) || strings.Contains(logs, `"level":"ERROR"`) {
		t.Fatalf("a failed dial must not log WARN or ERROR:\n%s", logs)
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
