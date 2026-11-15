package logger

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDebounced_sameMessageOnce proves attributes do not open a second window.
func TestDebounced_sameMessageOnce(t *testing.T) {
	ResetDebounceForTest()
	var sink bytes.Buffer
	log := slog.New(slog.NewTextHandler(&sink, &slog.HandlerOptions{Level: slog.LevelDebug}))

	Debounced(log, slog.LevelWarn, time.Minute, "remediation status", "statusCode", 401)
	Debounced(log, slog.LevelWarn, time.Minute, "remediation status", "statusCode", 502)
	Debounced(log, slog.LevelError, time.Minute, "other message")

	if got := strings.Count(sink.String(), "remediation status"); got != 1 {
		t.Fatalf("same message count %d, log %s", got, sink.String())
	}
	if !strings.Contains(sink.String(), "401") {
		t.Fatalf("first attributes missing: %s", sink.String())
	}
	if strings.Contains(sink.String(), "502") {
		t.Fatalf("second attributes should be suppressed: %s", sink.String())
	}
	if !strings.Contains(sink.String(), "other message") {
		t.Fatalf("different message missing: %s", sink.String())
	}
}

// Test_allowDebounced_window proves the same text stays silent for the interval that call passes.
func Test_allowDebounced_window(t *testing.T) {
	ResetDebounceForTest()
	now := time.Now()
	interval := 30 * time.Second
	if !allowDebounced("alpha", interval, now) {
		t.Fatal("first alpha should log")
	}
	if allowDebounced("alpha", interval, now.Add(time.Second)) {
		t.Fatal("alpha inside the window should be suppressed")
	}
	if !allowDebounced("beta", interval, now) {
		t.Fatal("beta is a different message and should log")
	}
	if !allowDebounced("alpha", interval, now.Add(interval)) {
		t.Fatal("alpha after the window should log")
	}
}

// Test_allowDebounced_oneWinnerInsideWindow proves one burst of the same message logs once.
func Test_allowDebounced_oneWinnerInsideWindow(t *testing.T) {
	ResetDebounceForTest()
	now := time.Now()
	var wins atomic.Int32
	var done sync.WaitGroup
	done.Add(32)
	for range 32 {
		go func() {
			defer done.Done()
			if allowDebounced("race", time.Minute, now) {
				wins.Add(1)
			}
		}()
	}
	done.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("wins %d", got)
	}
}
