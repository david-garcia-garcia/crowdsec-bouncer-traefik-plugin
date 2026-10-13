package lapi

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/yaegitest"
)

const tickerOwnChannelSends = 20000

// Test_startTicker_keepsEachTickerOnItsOwnChannel fails if two ticker loops
// share one select statement and yaegi v0.16.1 mixes their tick channels.
// Native go test staying green is not that proof.
func Test_startTicker_keepsEachTickerOnItsOwnChannel(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(previousProcs) })

	var streamRuns, metricsRuns int64
	var runs sync.WaitGroup
	runs.Add(2 * tickerOwnChannelSends)
	streamTicks := make(chan time.Time)
	metricsTicks := make(chan time.Time)
	streamStop := make(chan bool, 1)
	metricsStop := make(chan bool, 1)
	// Drive each production loop on its own channel.
	go runStreamTicker(streamTicks, streamStop, func() {
		atomic.AddInt64(&streamRuns, 1)
		runs.Done()
	})
	go runMetricsTicker(metricsTicks, metricsStop, func() {
		atomic.AddInt64(&metricsRuns, 1)
		runs.Done()
	})
	go sendTickerOwnChannelTicks(streamTicks, tickerOwnChannelSends)
	go sendTickerOwnChannelTicks(metricsTicks, tickerOwnChannelSends)

	// Wait for every send to be received, then stop both loops.
	finished := make(chan struct{})
	go func() {
		runs.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatalf("timed out stream=%d metrics=%d want=%d each",
			atomic.LoadInt64(&streamRuns), atomic.LoadInt64(&metricsRuns), tickerOwnChannelSends)
	}
	stopTicker(streamStop)
	stopTicker(metricsStop)
	if streamRuns != tickerOwnChannelSends || metricsRuns != tickerOwnChannelSends {
		t.Fatalf("each loop must receive only its own ticks: stream=%d metrics=%d want=%d",
			streamRuns, metricsRuns, tickerOwnChannelSends)
	}
}

// Test_startTicker_stopEndsBothLoops fails if stopTicker leaves a loop blocked.
func Test_startTicker_stopEndsBothLoops(t *testing.T) {
	streamTicks := make(chan time.Time)
	metricsTicks := make(chan time.Time)
	streamStop := make(chan bool, 1)
	metricsStop := make(chan bool, 1)
	var stopped sync.WaitGroup
	stopped.Add(2)
	go func() {
		defer stopped.Done()
		runStreamTicker(streamTicks, streamStop, func() {})
	}()
	go func() {
		defer stopped.Done()
		runMetricsTicker(metricsTicks, metricsStop, func() {})
	}()
	stopTicker(streamStop)
	stopTicker(metricsStop)
	finished := make(chan struct{})
	go func() {
		stopped.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stopTicker must end both ticker goroutines")
	}
}

// sendTickerOwnChannelTicks pushes count values so each loop can receive its own channel.
func sendTickerOwnChannelTicks(ticks chan time.Time, count int) {
	for range count {
		ticks <- time.Time{}
	}
}

// TestYaegi_startTicker_keepsEachTickerOnItsOwnChannel runs the same two-loop
// drive under yaegi v0.16.1. yaegi test cannot load package lapi; this snippet
// starts the production loops through the interpreter Traefik uses.
func TestYaegi_startTicker_keepsEachTickerOnItsOwnChannel(t *testing.T) {
	yaegitest.Run(t, yaegitest.GoPath(t), tickerOwnChannelYaegiSource())
}

// tickerOwnChannelYaegiSource is a package main that starts two production ticker loops.
func tickerOwnChannelYaegiSource() string {
	return fmt.Sprintf(`package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	lapi %q
)

func main() {
	runtime.GOMAXPROCS(2)
	const count = 20000
	var streamRuns, metricsRuns int64
	var runs sync.WaitGroup
	runs.Add(2 * count)
	streamTicks := make(chan time.Time)
	metricsTicks := make(chan time.Time)
	streamStop := make(chan bool, 1)
	metricsStop := make(chan bool, 1)
	go lapi.RunStreamTickerForTest(streamTicks, streamStop, func() {
		atomic.AddInt64(&streamRuns, 1)
		runs.Done()
	})
	go lapi.RunMetricsTickerForTest(metricsTicks, metricsStop, func() {
		atomic.AddInt64(&metricsRuns, 1)
		runs.Done()
	})
	go sendTicks(streamTicks, count)
	go sendTicks(metricsTicks, count)
	runs.Wait()
	if streamRuns != int64(count) || metricsRuns != int64(count) {
		fmt.Fprintf(os.Stderr, "each loop must receive only its own ticks: stream=%%d metrics=%%d want=%%d\n", streamRuns, metricsRuns, count)
		os.Exit(1)
	}
}

func sendTicks(ticks chan time.Time, count int) {
	for i := 0; i < count; i++ {
		ticks <- time.Time{}
	}
}
`, yaegitest.ModulePath+"/pkg/lapi")
}
