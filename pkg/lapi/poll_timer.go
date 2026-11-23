package lapi

import (
	"log/slog"
	"sync"
	"time"
)

// pollTimer runs one Client loop (the stream poll or the usage-metrics push): it calls work,
// waits one interval after work returns, and repeats until stop. The stream poll reports
// whether it succeeded; after a failure the wait is the shorter failedPollRetry.
//
// Why it exists: Traefik runs this plugin under yaegi v0.16.1, which builds one case list per
// select statement and shares it across every goroutine that runs that statement. Each LAPI
// middleware owns its own Client, so with several middlewares, or with an old Client in
// reclaim grace beside a new one, the loops of different Clients would run the same select
// and could take each other's ticks or stop signals. A Client could then stop polling for
// good while still reporting healthy, with no error logged. So pollTimer has no select:
// time.AfterFunc runs fire on the stdlib timer goroutine, fire re-arms the timer after work,
// and stop sets a flag and stops the timer. Reclaim grace uses AfterFunc for the same reason.
// Test_lapiHasNoSelectStatement keeps select out of pkg/lapi.
//
// Why it differs from upstream: upstream fixed the same yaegi problem in
// maxlerebourg/crowdsec-bouncer-traefik-plugin PR 399 with `for range ticker.C { go work() }`.
// That is enough there because upstream's tickers are process-wide and never stopped. Here
// every Client is stopped on Sleep and Close, and Ticker.Stop does not close C, so a goroutine
// ranging over it would block forever and keep the Client, decision store included, alive
// after every reload. Upstream also runs each tick's work concurrently; here the next poll is
// scheduled only after work returns, so one Client never overlaps its own polls.
//
// A plain `for { time.Sleep(interval); if stopped { return }; work() }` loop would also avoid
// select, but its goroutine would outlive stop by up to one interval, still holding the Client.
type pollTimer struct {
	mu       sync.Mutex
	timer    *time.Timer
	stopped  bool
	name     string
	log      *slog.Logger
	interval time.Duration // wait after a work call that succeeded
	retry    time.Duration // wait after a work call that failed
}

// failedPollRetry caps the wait after a poll that did not succeed. The next try is this long
// after the failed one returns, or one interval if that is shorter, so a 7200 s alone-mode
// interval does not leave the stream unhealthy for 2 hours after CAPI is back. A 60 s stream
// interval is unchanged.
const failedPollRetry = 60 * time.Second

// startPollTimer runs work every intervalSeconds, measured from the end of the previous work.
func startPollTimer(name string, intervalSeconds int64, log *slog.Logger, work func()) *pollTimer {
	return startPollTimerEvery(name, time.Duration(intervalSeconds)*time.Second, log, work)
}

// startPollTimerEvery is startPollTimer with a Duration, so tests can use sub-second intervals.
func startPollTimerEvery(name string, interval time.Duration, log *slog.Logger, work func()) *pollTimer {
	return startPollLoop(name, interval, interval, interval, log, func() bool {
		work()
		return true
	})
}

// startRetryPollTimer runs work now, then every intervalSeconds after a run that reports success,
// and failedPollRetry (or one interval if shorter) after a run that reports failure.
func startRetryPollTimer(name string, intervalSeconds int64, log *slog.Logger, work func() bool) *pollTimer {
	interval := time.Duration(intervalSeconds) * time.Second
	return startPollLoop(name, 0, interval, failedPollDelay(interval), log, work)
}

// failedPollDelay is the wait after a failed poll: failedPollRetry, or interval if shorter.
func failedPollDelay(interval time.Duration) time.Duration {
	if interval < failedPollRetry {
		return interval
	}
	return failedPollRetry
}

// startPollLoop runs work first after first, then re-arms interval after a successful work and
// retry after a failed one.
func startPollLoop(name string, first, interval, retry time.Duration, log *slog.Logger, work func() bool) *pollTimer {
	poll := &pollTimer{name: name, log: log, interval: interval, retry: retry}
	log.Debug("ticker:started", "name", name, "interval", int64(interval/time.Second))
	// Hold mu so a first fire cannot read timer before it is assigned.
	poll.mu.Lock()
	defer poll.mu.Unlock()
	poll.timer = time.AfterFunc(first, func() {
		poll.fire(work)
	})
	return poll
}

// fire runs work on the timer goroutine, then re-arms one interval later, or one retry later
// when work failed, unless stopped.
func (p *pollTimer) fire(work func() bool) {
	if p.isStopped() {
		return
	}
	next := p.interval
	if !work() {
		next = p.retry
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.stopped {
		p.timer.Reset(next)
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
