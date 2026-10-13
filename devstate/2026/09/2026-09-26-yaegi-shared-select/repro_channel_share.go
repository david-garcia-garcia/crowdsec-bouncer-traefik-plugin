//go:build ignore

// Reproduction cited by explore.md: yaegi v0.16.1 shared select case list.
// Shape matches upstream ticker_test.go (PR 399) but uses the current fork's
// select loop (ticker channel + stop), not range. Native go run stays isolated.
// Under yaegi, GOMAXPROCS>1, 20000 sends: crossed counts (PR 399 example 19997/20003).
package main

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

func runTickerSelect(ticks <-chan time.Time, work func()) {
	for {
		select {
		case <-ticks:
			work()
		}
	}
}

func runTickerSelectA(ticks <-chan time.Time, work func()) {
	for {
		select {
		case <-ticks:
			work()
		}
	}
}

func runTickerSelectB(ticks <-chan time.Time, work func()) {
	for {
		select {
		case <-ticks:
			work()
		}
	}
}

func runTickerRange(ticks <-chan time.Time, work func()) {
	for range ticks {
		work()
	}
}

func sendTicks(ticks chan time.Time, count int) {
	for i := 0; i < count; i++ {
		ticks <- time.Time{}
	}
}

func drive(label string, count int, loopA, loopB func(<-chan time.Time, func())) {
	var streamRuns, metricsRuns int64
	var runs sync.WaitGroup
	runs.Add(2 * count)
	streamTicks := make(chan time.Time)
	metricsTicks := make(chan time.Time)
	go loopA(streamTicks, func() {
		atomic.AddInt64(&streamRuns, 1)
		runs.Done()
	})
	go loopB(metricsTicks, func() {
		atomic.AddInt64(&metricsRuns, 1)
		runs.Done()
	})
	go sendTicks(streamTicks, count)
	go sendTicks(metricsTicks, count)
	runs.Wait()
	fmt.Printf("%s stream=%d metrics=%d want=%d each isolated=%v\n",
		label, streamRuns, metricsRuns, count, streamRuns == int64(count) && metricsRuns == int64(count))
}

func main() {
	runtime.GOMAXPROCS(2)
	fmt.Printf("GOMAXPROCS=%d NumCPU=%d\n", runtime.GOMAXPROCS(0), runtime.NumCPU())
	const count = 20000
	drive("shared-select", count, runTickerSelect, runTickerSelect)
	drive("split-select", count, runTickerSelectA, runTickerSelectB)
	drive("range", count, runTickerRange, runTickerRange)
}
