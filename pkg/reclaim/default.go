package reclaim

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

var (
	defaultMu    sync.Mutex
	defaultTable *Table
)

// Default returns the process-wide table, creating it on first use.
func Default() *Table {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable == nil {
		defaultTable = NewTable(DefaultGrace)
	}
	return defaultTable
}

// Open is Default().Open: create-once for key on the process table and bind ctx.
// logger is required. If the value has Close(), the table calls it when the incarnation ends.
// If the value has Sleep/Wake, last holder Sleeps and a reclaim Wakes.
func Open(ctx context.Context, key string, logger *slog.Logger, create func() (any, error)) (any, error) {
	return Default().Open(ctx, key, logger, create)
}

// Peek is Default().Peek: inspect a key without binding a constructor context.
func Peek(key string) (value any, holders int, sleeping bool, ok bool) {
	return Default().Peek(key)
}

// ReplaceSleeping is Default().ReplaceSleeping: discard a sleeper inside the table, then Open.
func ReplaceSleeping(ctx context.Context, key string, logger *slog.Logger, create func() (any, error)) (any, error) {
	return Default().ReplaceSleeping(ctx, key, logger, create)
}

// Reset tears down the process table (cancels every lifetime) and installs a fresh one. Tests only.
func Reset() {
	ResetWith(DefaultGrace)
}

// ResetWith replaces the process table after canceling the current one. Tests only.
func ResetWith(grace time.Duration) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable != nil {
		defaultTable.Reset()
	}
	defaultTable = NewTable(grace)
}
