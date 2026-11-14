package lapi

import (
	"log/slog"
	"sync"
	"time"
)

// pollTimer runs one Client loop (stream or usage-metrics) on a stdlib timer until stop.
// It has no select on purpose: yaegi v0.16.1 shares one select case slice per statement
// across every goroutine that runs it, so the loops of different Clients could take each
// other's ticks and stops. time.AfterFunc is the stdlib timer (same reason as reclaim grace).
type pollTimer struct {
	mu      sync.Mutex
	timer   *time.Timer
	stopped bool
	name    string
	log     *slog.Logger
}

// startPollTimer runs work every intervalSeconds, measured from the end of the previous work.
func startPollTimer(name string, intervalSeconds int64, log *slog.Logger, work func()) *pollTimer {
	return startPollTimerEvery(name, time.Duration(intervalSeconds)*time.Second, log, work)
}

// startPollTimerEvery is startPollTimer with a Duration, so tests can use sub-second intervals.
func startPollTimerEvery(name string, interval time.Duration, log *slog.Logger, work func()) *pollTimer {
	poll := &pollTimer{name: name, log: log}
	log.Debug("ticker:started", "name", name, "interval", int64(interval/time.Second))
	// Hold mu so a first fire cannot read timer before it is assigned.
	poll.mu.Lock()
	defer poll.mu.Unlock()
	poll.timer = time.AfterFunc(interval, func() {
		poll.fire(interval, work)
	})
	return poll
}

// fire runs work on the timer goroutine, then re-arms one interval later unless stopped.
func (p *pollTimer) fire(interval time.Duration, work func()) {
	if p.isStopped() {
		return
	}
	work()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.stopped {
		p.timer.Reset(interval)
	}
}

// isStopped reports under mu whether stop has ended this loop.
func (p *pollTimer) isStopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopped
}

// stop ends the loop. It does not wait for a work call already running. Nil-safe and idempotent.
func (p *pollTimer) stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	p.timer.Stop()
	p.mu.Unlock()
	p.log.Debug("ticker:stopped", "name", p.name)
}
