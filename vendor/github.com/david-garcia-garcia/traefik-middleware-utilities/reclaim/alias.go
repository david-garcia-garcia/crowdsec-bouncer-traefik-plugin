// Ad-hoc vendor override: holders (Open) are strong refs; watchers (Watch) are
// weak refs on a public alias. Propose these APIs upstream after they prove out.
package reclaim

import (
	"fmt"
	"reflect"
	"sync/atomic"
)

// Watcher is a weak reference to a mapped value. Watch copies current into Value
// and does not increment holders, stop grace, or Wake.
type Watcher struct {
	Value *atomic.Value
}

// Box is the only type stored in a watcher atomic.Value. Yaegi panics if that
// Value's first Store type later changes (typed-nil *T vs *T, or LAPI vs AppSec).
type Box struct {
	Value any
}

// aliasEntry is one public name: the incarnation it currently points at (or none)
// and the watchers that late-bind that name. alias and group are opaque to the table.
type aliasEntry struct {
	incarnation *slot
	publisher   string
	group       string
	empty       any
	watchers    []*atomic.Value
}

// SetAlias publishes the mapped key under a public name. Holders stay on key;
// watchers attach to alias. A second publisher on the same alias is rejected.
// The same publisher may replace its own alias in the same group (rename).
func (t *Table) SetAlias(key, alias, publisher, group string) error {
	if t == nil || alias == "" || key == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	incarnation := t.items[key]
	if incarnation == nil || (incarnation.state != slotAwake && incarnation.state != slotAsleep) {
		return fmt.Errorf("reclaim alias %q has no mapped key %q", alias, key)
	}
	if existing := t.aliases[alias]; existing != nil && existing.publisher != "" && existing.publisher != publisher {
		return fmt.Errorf("reclaim alias %q is held by %q; release it before %q can publish", alias, existing.publisher, publisher)
	}
	current := t.aliases[alias]
	for _, other := range t.aliases {
		if other == current || other.publisher != publisher || other.group != group {
			continue
		}
		t.clearAliasLocked(other)
	}
	entry := t.aliases[alias]
	if entry == nil {
		entry = &aliasEntry{}
		t.aliases[alias] = entry
	}
	if entry.incarnation != incarnation {
		t.detachAliasLocked(entry)
		incarnation.aliases = append(incarnation.aliases, entry)
		entry.incarnation = incarnation
	}
	entry.publisher = publisher
	entry.group = group
	t.storeWatchersLocked(entry, incarnation.value)
	return nil
}

// Watch appends dest to the alias and copies current (typed empty when unset).
// It never waits for SetAlias and never binds a holder. First non-nil empty sticks.
func (t *Table) Watch(alias string, dest *atomic.Value, empty any) {
	if t == nil || alias == "" || dest == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.aliases[alias]
	if entry == nil {
		entry = &aliasEntry{empty: empty}
		t.aliases[alias] = entry
	}
	if entry.empty == nil && empty != nil {
		entry.empty = empty
	}
	entry.watchers = append(entry.watchers, dest)
	current := entry.empty
	if entry.incarnation != nil && !isNilValue(entry.incarnation.value) {
		current = entry.incarnation.value
	}
	t.storeOneLocked(entry, dest, current)
}

// Unwatch removes dest from the alias. It does not Close the mapped value.
func (t *Table) Unwatch(alias string, dest *atomic.Value) {
	if t == nil || alias == "" || dest == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.aliases[alias]
	if entry == nil {
		return
	}
	kept := entry.watchers[:0]
	for _, watcher := range entry.watchers {
		if watcher != dest {
			kept = append(kept, watcher)
		}
	}
	entry.watchers = kept
}

// ClearPublisher drops every alias this publisher still holds in group.
// Watchers stay registered for a later SetAlias.
func (t *Table) ClearPublisher(publisher, group string) {
	if t == nil || publisher == "" || group == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, entry := range t.aliases {
		if entry.publisher != publisher || entry.group != group {
			continue
		}
		t.clearAliasLocked(entry)
	}
}

func (t *Table) unbindIncarnationLocked(incarnation *slot) {
	if incarnation == nil {
		return
	}
	bound := incarnation.aliases
	incarnation.aliases = nil
	for _, entry := range bound {
		entry.incarnation = nil
		entry.publisher = ""
		entry.group = ""
		t.storeWatchersLocked(entry, entry.empty)
	}
}

func (t *Table) clearAliasLocked(entry *aliasEntry) {
	t.detachAliasLocked(entry)
	entry.publisher = ""
	entry.group = ""
	t.storeWatchersLocked(entry, entry.empty)
}

func (t *Table) detachAliasLocked(entry *aliasEntry) {
	incarnation := entry.incarnation
	if incarnation == nil {
		return
	}
	kept := incarnation.aliases[:0]
	for _, other := range incarnation.aliases {
		if other != entry {
			kept = append(kept, other)
		}
	}
	incarnation.aliases = kept
	entry.incarnation = nil
}

func (t *Table) storeWatchersLocked(entry *aliasEntry, current any) {
	for _, watcher := range entry.watchers {
		t.storeOneLocked(entry, watcher, current)
	}
}

func (t *Table) storeOneLocked(entry *aliasEntry, dest *atomic.Value, current any) {
	toStore := current
	if isNilValue(current) {
		toStore = entry.empty
	}
	prev := dest.Load()
	if boxed, ok := prev.(*Box); ok {
		boxed.Value = toStore
		return
	}
	dest.Store(&Box{Value: toStore})
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}

func sameValue(left, right any) bool {
	if isNilValue(left) && isNilValue(right) {
		return true
	}
	if isNilValue(left) || isNilValue(right) {
		return false
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Kind() == reflect.Ptr && rightValue.Kind() == reflect.Ptr {
		return leftValue.Pointer() == rightValue.Pointer()
	}
	return left == right
}
