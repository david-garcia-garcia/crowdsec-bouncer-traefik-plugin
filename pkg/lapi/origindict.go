package lapi

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

// maxInternedOrigins is the last uint16 id (1..65535). Id 0 is unused / empty origin.
const maxInternedOrigins = 65535

// originDictionary is one DecisionStore's append-only MetricsOrigin intern table.
type originDictionary struct {
	mu           sync.Mutex
	byName       map[string]uint16
	names        atomic.Value // []string published after each intern; index is id-1
	overflowOnce sync.Once
	log          *slog.Logger
}

// newOriginDictionary is an empty session-scoped table. Not a package var.
func newOriginDictionary(log *slog.Logger) originDictionary {
	dict := originDictionary{byName: make(map[string]uint16), log: log}
	dict.names.Store([]string{})
	return dict
}

// InternOrigin maps a first-seen name to the next uint16 id. Empty origin is skipped.
// Overflow does not intern or wrap; it logs once per table.
func (d *originDictionary) InternOrigin(name string) (uint16, bool) {
	if name == "" {
		return 0, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if id, ok := d.byName[name]; ok {
		return id, true
	}
	if len(d.byName) >= maxInternedOrigins {
		d.logOverflow()
		return 0, false
	}
	id := uint16(len(d.byName) + 1)
	d.byName[name] = id
	previous, _ := d.names.Load().([]string)
	published := make([]string, len(previous)+1)
	copy(published, previous)
	published[id-1] = name
	d.names.Store(published)
	return id, true
}

// OriginName is the interned string for id, or empty. Lock-free after the write publishes.
func (d *originDictionary) OriginName(id uint16) string {
	if id == 0 {
		return ""
	}
	names, _ := d.names.Load().([]string)
	if int(id) > len(names) {
		return ""
	}
	return names[id-1]
}

// logOverflow records that this store will not intern further new names.
func (d *originDictionary) logOverflow() {
	d.overflowOnce.Do(func() {
		if d.log == nil {
			return
		}
		d.log.Warn("decisionstore: origin dictionary full; new origins stay on the string path")
	})
}
