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

// Box is the only type stored in a watcher atomic.Value (Yaegi-safe).
type Box = utilreclaim.Box

// Unbox returns the value Watch stored, or nil when dest is empty.
func Unbox(dest *atomic.Value) any {
	if dest == nil {
		return nil
	}
	stored := dest.Load()
	if boxed, ok := stored.(*Box); ok {
		return boxed.Value
	}
	return stored
}

// SetAlias publishes the mapped ownership key under a public name in group.
func SetAlias(key, alias, publisher, group string) error {
	return Default().SetAlias(key, alias, publisher, group)
}

// Watch copies the alias into dest without binding a holder.
func Watch(alias string, dest *atomic.Value, empty any) {
	Default().Watch(alias, dest, empty)
}

// Unwatch removes dest from the alias.
func Unwatch(alias string, dest *atomic.Value) {
	Default().Unwatch(alias, dest)
}

// ClearPublisher drops every alias this publisher still holds in group.
func ClearPublisher(publisher, group string) {
	Default().ClearPublisher(publisher, group)
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
