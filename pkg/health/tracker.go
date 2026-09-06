// Package health tracks CrowdSec backend health and manages backoff state.
package health

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Tracker counts failures in a tumbling window, trips unhealthy after
// threshold, and auto-recovers after backoffTimeout.
type Tracker struct {
	mu               sync.RWMutex
	isShutdown       atomic.Bool // lockless fast path for IsUnhealthy()
	shutdownUntil    time.Time
	failureCount     int
	lastFailureReset time.Time
	backoffTimeout   time.Duration
	failureWindow    time.Duration
	failureThreshold int
	logger           *slog.Logger
}

// New creates a Tracker. When failureThreshold < 0 or backoffTimeout is 0,
// the tracker never trips (opt-out). When failureWindow is 0, the counter
// never resets except on auto-recover. When failureWindow is greater than 0,
// the first tumbling window starts now.
func New(backoffTimeout, failureWindow time.Duration, failureThreshold int, logger *slog.Logger) *Tracker {
	ht := &Tracker{
		backoffTimeout:   backoffTimeout,
		failureWindow:    failureWindow,
		failureThreshold: failureThreshold,
		logger:           logger,
	}
	if failureWindow > 0 {
		ht.lastFailureReset = time.Now()
	}
	return ht
}

// NewFromSeconds builds a Tracker from operator second knobs.
func NewFromSeconds(timeoutSeconds, windowSeconds, threshold int64, logger *slog.Logger) *Tracker {
	return New(time.Duration(timeoutSeconds)*time.Second, time.Duration(windowSeconds)*time.Second, int(threshold), logger)
}

func (ht *Tracker) log() *slog.Logger {
	if ht.logger != nil {
		return ht.logger
	}
	return slog.Default()
}

// RecordFailure records a failure and returns true if the tracker just tripped to unhealthy.
// When failureThreshold < 0 or backoffTimeout is 0, always returns false (never trip).
func (ht *Tracker) RecordFailure() bool {
	if ht.failureThreshold < 0 || ht.backoffTimeout <= 0 {
		return false
	}

	ht.mu.Lock()
	defer ht.mu.Unlock()

	now := time.Now()

	// Reset failure count if the tumbling window has elapsed.
	if ht.failureWindow > 0 && now.Sub(ht.lastFailureReset) > ht.failureWindow {
		ht.failureCount = 0
		ht.lastFailureReset = now
	}

	ht.failureCount++

	// Trip if threshold reached.
	if ht.failureCount >= ht.failureThreshold {
		ht.isShutdown.Store(true)
		ht.shutdownUntil = now.Add(ht.backoffTimeout)
		ht.log().Warn("marking backend as unhealthy", "backoff", ht.backoffTimeout, "failures", ht.failureCount)
		return true
	}
	return false
}

// IsUnhealthy reports whether the backend is in backoff.
// Uses a lockless fast-path when not shutdown; auto-recovers when shutdownUntil has passed.
func (ht *Tracker) IsUnhealthy() bool {
	if !ht.isShutdown.Load() {
		return false
	}

	ht.mu.Lock()
	defer ht.mu.Unlock()
	if ht.isShutdown.Load() && time.Now().After(ht.shutdownUntil) {
		ht.isShutdown.Store(false)
		ht.failureCount = 0
		ht.log().Info("backend unhealthy backoff expired")
		return false
	}
	return ht.isShutdown.Load()
}
