package reclaim

import (
	"context"
	"log/slog"
	"sync"
	"time"

	utilreclaim "github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim"
)

// ProcessGrace is this plugin’s process-table wait after the last holder (LAPI and AppSec).
const ProcessGrace = 30 * time.Second

// Table is the utilities reclaim table. Callers import this shim, not utilities reclaim.
type Table = utilreclaim.Table

// Config is the utilities table config (Grace is freeze-at-New).
type Config = utilreclaim.Config

// Hooks are Sleep/Wake/Close funcs. Yaegi v0.16 panics asserting a foreign concrete type.
type Hooks = utilreclaim.Hooks

// State is whether a Peek'd slot is usable now (Awake) or kept for grace (Asleep).
type State = utilreclaim.State

const (
	// Awake means the value is bound to at least one live context.
	Awake = utilreclaim.Awake
	// Asleep means the last holder is gone and grace has not ended.
	Asleep = utilreclaim.Asleep
)

var (
	defaultMu    sync.Mutex
	defaultTable *Table
)

// New constructs a table with the utilities AfterFunc grace (Yaegi _select hang).
func New(cfg Config) *Table {
	return utilreclaim.New(cfg)
}

// Default returns the process-wide table, creating it on first use with ProcessGrace.
func Default() *Table {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable == nil {
		defaultTable = New(Config{Grace: ProcessGrace})
	}
	return defaultTable
}

// OpenWithHooks is Default().OpenWithHooks.
func OpenWithHooks(ctx context.Context, key string, logger *slog.Logger, create func() (any, Hooks, error)) (any, error) {
	return Default().OpenWithHooks(ctx, key, logger, create)
}

// Peek is Default().Peek: look without bind, Wake, or stopping grace.
func Peek(key string) (any, State, bool) {
	return Default().Peek(key)
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
