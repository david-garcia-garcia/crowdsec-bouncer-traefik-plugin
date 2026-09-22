package reclaim

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
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

// Default returns the process-wide table, creating it on first use with ProcessGrace
// unless EnsureProcessGrace already installed one.
func Default() *Table {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable == nil {
		defaultTable = New(Config{Grace: ProcessGrace})
	}
	return defaultTable
}

// EnsureProcessGrace installs the process table on first New. Later calls no-op.
// Negative grace becomes ProcessGrace. Zero disposes as soon as the last holder ends.
func EnsureProcessGrace(grace time.Duration) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultTable != nil {
		return
	}
	if grace < 0 {
		grace = ProcessGrace
	}
	defaultTable = New(Config{Grace: grace})
}

// OpenWithHooks is Default().OpenWithHooks.
func OpenWithHooks(ctx context.Context, key string, logger *slog.Logger, create func() (any, Hooks, error)) (any, error) {
	return Default().OpenWithHooks(ctx, key, logger, create)
}

// Peek is Default().Peek: look without bind, Wake, or stopping grace.
func Peek(key string) (any, State, bool) {
	return Default().Peek(key)
}

// Watcher is a weak reference: Watch copies the alias without binding a holder.
type Watcher = utilreclaim.Watcher

// SetAlias publishes the mapped ownership key under a public name.
func SetAlias(key, alias, publisher string, empty any) error {
	return Default().SetAlias(key, alias, publisher, empty)
}

// Watch copies the alias into dest without binding a holder.
func Watch(alias string, dest Watcher, empty any) {
	Default().Watch(alias, dest, empty)
}

// Unwatch removes dest from the alias.
func Unwatch(alias string, dest *atomic.Value) {
	Default().Unwatch(alias, dest)
}

// ClearAlias drops the alias when this publisher still holds it.
func ClearAlias(alias, publisher string) {
	Default().ClearAlias(alias, publisher)
}

// ClearPublisher drops every alias this publisher still holds in prefix.
func ClearPublisher(publisher, prefix string) {
	Default().ClearPublisher(publisher, prefix)
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
