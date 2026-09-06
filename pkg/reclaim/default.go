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

// OpenWithGrace is Default().OpenWithGrace.
func OpenWithGrace(ctx context.Context, key string, logger *slog.Logger, grace time.Duration, create func() (any, error)) (any, error) {
	return Default().OpenWithGrace(ctx, key, logger, grace, create)
}

// Peek is Default().Peek: inspect a key without binding a constructor context.
func Peek(key string) View {
	return Default().Peek(key)
}

// PeekLivePrefix is Default().PeekLivePrefix: a live slot under prefix, no bind.
func PeekLivePrefix(prefix string) View {
	return Default().PeekLivePrefix(prefix)
}

// ResetForTest tears down the process table (cancels every lifetime) and installs a fresh one.
func ResetForTest() {
	ResetForTestWith(DefaultGrace)
}

// ResetForTestWith replaces the process table after canceling the current one.
func ResetForTestWith(grace time.Duration) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable != nil {
		defaultTable.ResetForTest()
	}
	defaultTable = NewTable(grace)
}
