package lapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

// Test_lapiHasNoSelectStatement fails if non-test code in pkg/lapi uses a select statement.
// yaegi v0.16.1 shares one select case slice per statement across every goroutine that runs it,
// so the loops of different Clients would wait on each other's channels.
func Test_lapiHasNoSelectStatement(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var found []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, parseErr := parser.ParseFile(fset, file, nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if _, ok := node.(*ast.SelectStmt); ok {
				found = append(found, fset.Position(node.Pos()).String())
			}
			return true
		})
	}
	if len(found) > 0 {
		t.Fatalf("pkg/lapi must not use select (yaegi shares its cases across Clients): %v", found)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitPollRuns waits until counter reaches want or fails after timeout.
func waitPollRuns(t *testing.T, counter *int64, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for atomic.LoadInt64(counter) < want {
		if time.Now().After(deadline) {
			t.Fatalf("poll timer ran %d times, want at least %d", atomic.LoadInt64(counter), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// Test_pollTimer_rearmsAfterWork fails if the timer runs work only once.
func Test_pollTimer_rearmsAfterWork(t *testing.T) {
	var runs int64
	poll := startPollTimerEvery("test", time.Millisecond, discardLogger(), func() { atomic.AddInt64(&runs, 1) })
	t.Cleanup(poll.stop)
	waitPollRuns(t, &runs, 3, 5*time.Second)
}

// Test_pollTimer_stopEndsOnlyThatTimer fails if stopping one timer stops or stalls another.
func Test_pollTimer_stopEndsOnlyThatTimer(t *testing.T) {
	var stoppedRuns, liveRuns int64
	stopped := startPollTimerEvery("stopped", time.Millisecond, discardLogger(), func() { atomic.AddInt64(&stoppedRuns, 1) })
	live := startPollTimerEvery("live", time.Millisecond, discardLogger(), func() { atomic.AddInt64(&liveRuns, 1) })
	t.Cleanup(live.stop)
	waitPollRuns(t, &stoppedRuns, 2, 5*time.Second)
	stopped.stop()
	// A fire that passed the stopped check before stop may still finish once.
	time.Sleep(20 * time.Millisecond)
	frozen := atomic.LoadInt64(&stoppedRuns)
	liveBefore := atomic.LoadInt64(&liveRuns)
	waitPollRuns(t, &liveRuns, liveBefore+5, 5*time.Second)
	if got := atomic.LoadInt64(&stoppedRuns); got != frozen {
		t.Fatalf("stopped timer kept running: %d after stop, then %d", frozen, got)
	}
}

// Test_pollTimer_stopDuringWorkDoesNotRearm fails if a fire in progress re-arms after stop.
func Test_pollTimer_stopDuringWorkDoesNotRearm(t *testing.T) {
	var runs int64
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	poll := startPollTimerEvery("test", time.Millisecond, discardLogger(), func() {
		if atomic.AddInt64(&runs, 1) == 1 {
			entered <- struct{}{}
			<-release
		}
	})
	<-entered
	poll.stop()
	close(release)
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt64(&runs); got != 1 {
		t.Fatalf("timer stopped during work ran %d times, want 1", got)
	}
}

// Test_pollTimer_stopIsNilSafeAndIdempotent fails if stop panics on nil or on a second call.
func Test_pollTimer_stopIsNilSafeAndIdempotent(t *testing.T) {
	var nilTimer *pollTimer
	nilTimer.stop()
	poll := startPollTimerEvery("test", time.Hour, discardLogger(), func() {})
	poll.stop()
	poll.stop()
	if !poll.isStopped() {
		t.Fatal("stop must mark the timer stopped")
	}
}

// Test_clientSleepWakeClose_restartsAndStopsPollTimers fails if Sleep/Close leave a poll timer
// running or Wake does not start new ones.
func Test_clientSleepWakeClose_restartsAndStopsPollTimers(t *testing.T) {
	client, _ := NewTestClient(discardLogger())
	client.updateInterval = 3600
	// Set before any lifecycle call: Sleep reads it on its async drain. The test Client has no
	// MetricsReporter, so that drain POSTs nothing.
	client.metricsInterval = 3600
	client.streamTimer = startPollTimer("stream", client.updateInterval, client.log, func() {})
	client.metricsTimer = startPollTimer("metrics", client.metricsInterval, client.log, func() {})
	stream, metrics := client.streamTimer, client.metricsTimer

	client.Sleep()
	if client.streamTimer != nil || client.metricsTimer != nil {
		t.Fatal("Sleep must clear both poll timers")
	}
	if !stream.isStopped() || !metrics.isStopped() {
		t.Fatal("Sleep must stop both poll timers")
	}

	client.decisionStore.TryBeginStreamPoll() // Wake's first poll skips instead of calling LAPI.
	client.Wake()
	if client.streamTimer == nil || client.metricsTimer == nil {
		t.Fatal("Wake must start both poll timers")
	}
	stream, metrics = client.streamTimer, client.metricsTimer

	client.Close()
	if !stream.isStopped() || !metrics.isStopped() {
		t.Fatal("Close must stop both poll timers")
	}
}

// TestYaegi_pollTimer_manyLoopsStopIndependently runs many production poll timers under yaegi
// v0.16.1, the interpreter Traefik uses, stops half, and fails if a stopped loop keeps running
// or a live loop stalls. On master the select-based loops shared one case slice per statement.
func TestYaegi_pollTimer_manyLoopsStopIndependently(t *testing.T) {
	yaegitest.Run(t, yaegitest.GoPath(t), pollTimerManyLoopsYaegiSource())
}

// pollTimerManyLoopsYaegiSource is a package main that drives many production poll timers.
func pollTimerManyLoopsYaegiSource() string {
	return fmt.Sprintf(`package main

import (
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	lapi %q
)

const loops = 16

func main() {
	runtime.GOMAXPROCS(2)
	var counts [loops]int64
	stops := make([]func(), loops)
	for i := 0; i < loops; i++ {
		counter := &counts[i]
		stops[i] = lapi.StartPollTimerForTest(time.Millisecond, func() { atomic.AddInt64(counter, 1) })
	}
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	for i := 0; i < loops; i++ {
		waitAtLeast(&counts[i], 5)
	}
	for i := 0; i < loops; i += 2 {
		stops[i]()
	}
	// A fire that passed the stopped check before stop may still finish once.
	time.Sleep(20 * time.Millisecond)
	var frozen [loops]int64
	for i := 0; i < loops; i++ {
		frozen[i] = atomic.LoadInt64(&counts[i])
	}
	for i := 1; i < loops; i += 2 {
		waitAtLeast(&counts[i], frozen[i]+20)
	}
	for i := 0; i < loops; i += 2 {
		if got := atomic.LoadInt64(&counts[i]); got != frozen[i] {
			fmt.Fprintf(os.Stderr, "stopped loop %%d kept running: %%d then %%d\n", i, frozen[i], got)
			os.Exit(1)
		}
	}
}

func waitAtLeast(counter *int64, want int64) {
	deadline := time.Now().Add(10 * time.Second)
	for atomic.LoadInt64(counter) < want {
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "loop stalled at %%d, want at least %%d\n", atomic.LoadInt64(counter), want)
			os.Exit(1)
		}
		time.Sleep(time.Millisecond)
	}
}
`, yaegitest.ModulePath+"/pkg/lapi")
}
