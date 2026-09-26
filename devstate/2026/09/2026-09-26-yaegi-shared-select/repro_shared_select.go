//go:build ignore

// Throwaway reproduction for explore 2026-09-26-yaegi-shared-select.
// Mirrors pkg/lapi startTicker: one select on ticker.C and a stop chan, two goroutines.
// Expected under yaegi v0.16.1: shared select — both loops wait on the first caller's cases.
// Native go run should keep each ticker on its own channel.
package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

func startTickerShared(interval time.Duration, work func()) chan bool {
	ticker := time.NewTicker(interval)
	stop := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-ticker.C:
				work()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return stop
}

func startTickerStream(interval time.Duration, work func()) chan bool {
	ticker := time.NewTicker(interval)
	stop := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-ticker.C:
				work()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return stop
}

func startTickerMetrics(interval time.Duration, work func()) chan bool {
	ticker := time.NewTicker(interval)
	stop := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-ticker.C:
				work()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return stop
}

func startTickerRange(interval time.Duration, work func()) *time.Ticker {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			work()
		}
	}()
	return ticker
}

func stopTicker(stop chan bool) {
	if stop == nil {
		return
	}
	select {
	case stop <- true:
	default:
	}
}

func runShared(runFor time.Duration) (int64, int64) {
	var fast, slow int64
	stopFast := startTickerShared(20*time.Millisecond, func() { atomic.AddInt64(&fast, 1) })
	stopSlow := startTickerShared(200*time.Millisecond, func() { atomic.AddInt64(&slow, 1) })
	time.Sleep(runFor)
	stopTicker(stopFast)
	stopTicker(stopSlow)
	time.Sleep(50 * time.Millisecond)
	return atomic.LoadInt64(&fast), atomic.LoadInt64(&slow)
}

func runSplit(runFor time.Duration) (int64, int64) {
	var fast, slow int64
	stopFast := startTickerStream(20*time.Millisecond, func() { atomic.AddInt64(&fast, 1) })
	stopSlow := startTickerMetrics(200*time.Millisecond, func() { atomic.AddInt64(&slow, 1) })
	time.Sleep(runFor)
	stopTicker(stopFast)
	stopTicker(stopSlow)
	time.Sleep(50 * time.Millisecond)
	return atomic.LoadInt64(&fast), atomic.LoadInt64(&slow)
}

func runRange(runFor time.Duration) (int64, int64) {
	var fast, slow int64
	tFast := startTickerRange(20*time.Millisecond, func() { atomic.AddInt64(&fast, 1) })
	tSlow := startTickerRange(200*time.Millisecond, func() { atomic.AddInt64(&slow, 1) })
	time.Sleep(runFor)
	tFast.Stop()
	tSlow.Stop()
	return atomic.LoadInt64(&fast), atomic.LoadInt64(&slow)
}

func runStop(kind string) {
	var n int64
	var stop chan bool
	if kind == "shared" {
		stop = startTickerShared(20*time.Millisecond, func() { atomic.AddInt64(&n, 1) })
	} else {
		stop = startTickerStream(20*time.Millisecond, func() { atomic.AddInt64(&n, 1) })
	}
	time.Sleep(80 * time.Millisecond)
	before := atomic.LoadInt64(&n)
	stopTicker(stop)
	time.Sleep(120 * time.Millisecond)
	after := atomic.LoadInt64(&n)
	fmt.Printf("stop kind=%s before=%d after=%d grew=%d\n", kind, before, after, after-before)
}

func main() {
	runFor := 800 * time.Millisecond
	fast, slow := runShared(runFor)
	fmt.Printf("shared fast=%d slow=%d (expect fast~40 slow~4 if isolated)\n", fast, slow)
	fast, slow = runSplit(runFor)
	fmt.Printf("split  fast=%d slow=%d (expect fast~40 slow~4 if isolated)\n", fast, slow)
	fast, slow = runRange(runFor)
	fmt.Printf("range  fast=%d slow=%d (expect fast~40 slow~4 if isolated)\n", fast, slow)
	runStop("shared")
	runStop("split")
	os.Exit(0)
}
