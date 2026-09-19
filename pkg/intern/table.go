// Package intern maps unique strings to uint16 ids. ID is string→id; Name is id→string.
package intern

import (
	"strconv"
	"sync"
	"sync/atomic"
)

const maxID = 65535

// snapshot is one copy-on-write pair of inverse maps. Readers Load it; writers Store a clone.
type snapshot struct {
	byID   map[uint16]string
	byName map[string]uint16
}

// Table is an append-only string intern. ID and Name are inverse. Empty name is id 0.
type Table struct {
	mu sync.Mutex
	// snap holds *snapshot. Yaegi v0.16 panics boxing a map (or a struct of maps) into interface{}.
	snap atomic.Value
}

// New returns an empty table.
func New() *Table {
	table := &Table{}
	table.snap.Store(&snapshot{
		byID:   map[uint16]string{},
		byName: map[string]uint16{},
	})
	return table
}

// current is the lock-free inverse maps.
func (t *Table) current() snapshot {
	if t == nil {
		return snapshot{}
	}
	stored, _ := t.snap.Load().(*snapshot)
	if stored == nil {
		return snapshot{}
	}
	return *stored
}

// lookup is string→id on the current snapshot.
func (t *Table) lookup(name string) (uint16, bool) {
	id, ok := t.current().byName[name]
	return id, ok
}

// ID is string→id: the uint16 for name, appending if new. Empty name is 0. Overflow does not wrap.
func (t *Table) ID(name string) (uint16, bool) {
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
	prev := t.current()
	if len(prev.byName) >= maxID {
		return 0, false
	}
	id := uint16(len(prev.byName) + 1) //nolint:gosec // G115 overflow returns before append past 65535
	// Copy-on-write both maps; readers keep the previous snapshot.
	next := cloneSnapshot(prev)
	next.byID[id] = name
	next.byName[name] = id
	t.snap.Store(&next)
	return id, true
}

// Name is id→string: the interned name for id. Lock-free. Unknown id is empty.
func (t *Table) Name(id uint16) string {
	if id == 0 {
		return ""
	}
	return t.current().byID[id]
}

// cloneSnapshot copies both maps so a writer can append without mutating readers.
func cloneSnapshot(prev snapshot) snapshot {
	byID := make(map[uint16]string, len(prev.byID)+1)
	byName := make(map[string]uint16, len(prev.byName)+1)
	for id, name := range prev.byID {
		byID[id] = name
	}
	for name, id := range prev.byName {
		byName[name] = id
	}
	return snapshot{byID: byID, byName: byName}
}

// FillUntilMaxForTest stores unique names for ids 1..65535. Tests only.
func (t *Table) FillUntilMaxForTest() {
	if t == nil {
		return
	}
	byID := make(map[uint16]string, maxID)
	byName := make(map[string]uint16, maxID)
	for n := 1; n <= maxID; n++ {
		name := strconv.Itoa(n)
		id := uint16(n) //nolint:gosec // G115 loop is capped at maxID
		byID[id] = name
		byName[name] = id
	}
	t.snap.Store(&snapshot{byID: byID, byName: byName})
}
