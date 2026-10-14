package logger

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// debounceSlot holds the last time one message text was logged.
// last stores a time.Time. atomic.Pointer[T] is not used: Yaegi v0.16 cannot select that field.
type debounceSlot struct {
	last atomic.Value
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
		if slot, ok := actual.(*debounceSlot); ok {
			return claimDebounceSlot(slot, interval, now)
		}
	}
	fresh := &debounceSlot{}
	fresh.last.Store(now)
	actual, loaded := debounceSlots.LoadOrStore(msg, fresh)
	if !loaded {
		return true
	}
	slot, ok := actual.(*debounceSlot)
	if !ok {
		return true
	}
	return claimDebounceSlot(slot, interval, now)
}

// claimDebounceSlot logs when interval has elapsed since slot was last claimed.
func claimDebounceSlot(slot *debounceSlot, interval time.Duration, now time.Time) bool {
	loaded := slot.last.Load()
	last, ok := loaded.(time.Time)
	if ok && now.Sub(last) < interval {
		return false
	}
	if !ok {
		slot.last.Store(now)
		return true
	}
	return slot.last.CompareAndSwap(last, now)
}

// ResetDebounceForTest clears the process-wide windows. Test-only.
func ResetDebounceForTest() {
	debounceSlots.Range(func(key, _ any) bool {
		debounceSlots.Delete(key)
		return true
	})
}
