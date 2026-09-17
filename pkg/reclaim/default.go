package reclaim

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ProcessGrace is this plugin’s process-table wait after the last holder (LAPI and AppSec).
const ProcessGrace = 30 * time.Second

var (
	defaultMu    sync.Mutex
	defaultTable *Table
)

// Default returns the process-wide table, creating it on first use with ProcessGrace.
func Default() *Table {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable == nil {
		defaultTable = New(Config{Grace: ProcessGrace})
	}
	return defaultTable
}

// Open is Default().Open: create-once for key on the process table and bind ctx.
func Open(ctx context.Context, key string, logger *slog.Logger, create func() (any, error), hooks Hooks) (any, error) {
	return Default().Open(ctx, key, logger, create, hooks)
}

// OpenWithHooks is Default().OpenWithHooks.
func OpenWithHooks(ctx context.Context, key string, logger *slog.Logger, create func() (any, Hooks, error)) (any, error) {
	return Default().OpenWithHooks(ctx, key, logger, create)
}

// Peek is Default().Peek: inspect a key without binding a constructor context.
func Peek(key string) View {
	return Default().Peek(key)
}

// PeekLivePrefix is Default().PeekLivePrefix: a live slot under prefix, no bind.
func PeekLivePrefix(prefix string) View {
	return Default().PeekLivePrefix(prefix)
}

// ResetForTest tears down the process table and installs a fresh one with ProcessGrace.
func ResetForTest() {
	ResetForTestWith(ProcessGrace)
}

// ResetForTestWith replaces the process table after Reset of the current one.
func ResetForTestWith(grace time.Duration) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable != nil {
		defaultTable.Reset()
	}
	defaultTable = New(Config{Grace: grace})
}
