package logger

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// debounceSlot holds the last time one message text was logged.
type debounceSlot struct {
	last atomic.Pointer[time.Time]
}

// debounceSlots is process-wide so every logger shares one window per message text.
//
//nolint:gochecknoglobals // one window per message is the job of Debounced
var debounceSlots sync.Map

// Debounced logs msg at level at most once per interval.
// The key is msg. Attributes are not part of the key, so varying details belong there.
func Debounced(log *slog.Logger, level slog.Level, interval time.Duration, msg string, args ...any) {
	if !allowDebounced(msg, interval, time.Now()) {
		return
	}
	log.Log(context.Background(), level, msg, args...)
}

// allowDebounced is the leading edge of Debounced: the first copy of msg inside interval is logged.
// A repeat inside the window loads the stored time and returns. It does not take a lock.
func allowDebounced(msg string, interval time.Duration, now time.Time) bool {
	if actual, ok := debounceSlots.Load(msg); ok {
		return claimDebounceSlot(actual.(*debounceSlot), interval, now)
	}
	fresh := &debounceSlot{}
	stamp := now
	fresh.last.Store(&stamp)
	actual, loaded := debounceSlots.LoadOrStore(msg, fresh)
	if !loaded {
		return true
	}
	return claimDebounceSlot(actual.(*debounceSlot), interval, now)
}

// claimDebounceSlot logs when interval has elapsed since slot was last claimed.
func claimDebounceSlot(slot *debounceSlot, interval time.Duration, now time.Time) bool {
	last := slot.last.Load()
	if last != nil && now.Sub(*last) < interval {
		return false
	}
	stamp := now
	return slot.last.CompareAndSwap(last, &stamp)
}

// ResetDebounceForTest clears the process-wide windows. Test-only.
func ResetDebounceForTest() {
	debounceSlots.Range(func(key, _ any) bool {
		debounceSlots.Delete(key)
		return true
	})
}
