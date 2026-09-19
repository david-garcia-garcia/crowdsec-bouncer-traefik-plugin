// Package intern maps unique strings to stable uint16 ids with lock-free reverse lookup.
package intern

import (
	"sync"
	"sync/atomic"
)

const maxID = 65535

// Table is an append-only string intern. Index 0 is unused. Empty name is id 0.
type Table struct {
	mu sync.Mutex
	// names is []string with index 0 unused. atomic.Value not atomic.Pointer[T]
	// (interpreters without generic atomics still Load the snapshot).
	names atomic.Value
}

// New returns an empty table ready to intern names.
func New() *Table {
	table := &Table{}
	table.names.Store([]string{""})
	return table
}

// snapshot is the lock-free name slice. Index 0 is unused.
func (t *Table) snapshot() []string {
	if t == nil {
		return nil
	}
	names, _ := t.names.Load().([]string)
	return names
}

// lookup finds an already interned name on the snapshot.
func (t *Table) lookup(name string) (uint16, bool) {
	for id, existing := range t.snapshot() {
		if id == 0 || existing != name {
			continue
		}
		return uint16(id), true //nolint:gosec // G115 intern snapshot index is capped at 65535
	}
	return 0, false
}

// Intern returns the id for name. Empty name is 0. Overflow does not wrap.
func (t *Table) Intern(name string) (uint16, bool) {
	if t == nil {
		return 0, false
	}
	if name == "" {
		return 0, true
	}
	// Unlocked hit on the current snapshot.
	if id, ok := t.lookup(name); ok {
		return id, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok := t.lookup(name); ok {
		return id, true
	}
	names := t.snapshot()
	if names == nil {
		names = []string{""}
	}
	if len(names) > maxID {
		return 0, false
	}
	// Copy-on-write append; readers keep the previous snapshot.
	next := make([]string, len(names)+1)
	copy(next, names)
	next[len(names)] = name
	id := uint16(len(names)) //nolint:gosec // G115 overflow returns before append past 65535
	t.names.Store(next)
	return id, true
}

// Name is the interned string for id. Lock-free. Unknown id is empty.
func (t *Table) Name(id uint16) string {
	if id == 0 {
		return ""
	}
	names := t.snapshot()
	if int(id) >= len(names) {
		return ""
	}
	return names[id]
}

// ReplaceNamesForTest installs names as the current snapshot. Tests only.
func (t *Table) ReplaceNamesForTest(names []string) {
	if t == nil {
		return
	}
	t.names.Store(names)
}
