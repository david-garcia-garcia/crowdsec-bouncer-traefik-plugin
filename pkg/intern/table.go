// Package intern maps unique strings to uint16 ids. ID is string→id; Name is id→string.
package intern

import (
	"strconv"
	"sync"
)

const maxID = 65535

// Table is an append-only string intern. ID and Name are inverse. Empty name is id 0.
// Maps stay behind the mutex: Yaegi v0.16 panics boxing a map into interface{}.
type Table struct {
	mu     sync.RWMutex
	byID   map[uint16]string
	byName map[string]uint16
}

// New returns an empty table.
func New() *Table {
	return &Table{
		byID:   map[uint16]string{},
		byName: map[string]uint16{},
	}
}

// ID is string→id: the uint16 for name, appending if new. Empty name is 0. Overflow does not wrap.
func (t *Table) ID(name string) (uint16, bool) {
	if t == nil {
		return 0, false
	}
	if name == "" {
		return 0, true
	}
	t.mu.RLock()
	id, ok := t.byName[name]
	t.mu.RUnlock()
	if ok {
		return id, true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if id, ok = t.byName[name]; ok {
		return id, true
	}
	if len(t.byName) >= maxID {
		return 0, false
	}
	id = uint16(len(t.byName) + 1) //nolint:gosec // G115 overflow returns before append past 65535
	t.byID[id] = name
	t.byName[name] = id
	return id, true
}

// Name is id→string: the interned name for id. Unknown id is empty.
func (t *Table) Name(id uint16) string {
	if t == nil || id == 0 {
		return ""
	}
	t.mu.RLock()
	name := t.byID[id]
	t.mu.RUnlock()
	return name
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
	t.mu.Lock()
	t.byID = byID
	t.byName = byName
	t.mu.Unlock()
}
