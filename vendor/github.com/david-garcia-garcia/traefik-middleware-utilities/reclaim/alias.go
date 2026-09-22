// Ad-hoc vendor override: holders (Open) are strong refs; watchers (Watch) are
// weak refs on a public alias. Propose these APIs upstream after they prove out.
package reclaim

import (
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
)

// Watcher is a weak reference to a mapped value. Watch copies current into Value
// and does not increment holders, stop grace, or Wake.
type Watcher struct {
	Value  *atomic.Value
	Notify func(current any, bound bool)
}

// aliasEntry is one public name: the incarnation it currently points at (or none)
// and the watchers that late-bind that name.
type aliasEntry struct {
	incarnation *slot
	publisher   string
	empty       any
	watchers    []Watcher
}

// SetAlias publishes the mapped key under a public name. Holders stay on key;
// watchers attach to alias. A second publisher on the same alias is rejected.
// The same publisher may replace its own alias (rename) or its own value.
func (t *Table) SetAlias(key, alias, publisher string, empty any) error {
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
	prefix := aliasFamily(alias)
	for otherAlias, other := range t.aliases {
		if otherAlias == alias || other.publisher != publisher || !strings.HasPrefix(otherAlias, prefix) {
			continue
		}
		t.clearAliasLocked(otherAlias, other)
	}
	entry := t.aliases[alias]
	if entry == nil {
		entry = &aliasEntry{}
		t.aliases[alias] = entry
	}
	if entry.empty == nil && empty != nil {
		entry.empty = empty
	}
	entry.incarnation = incarnation
	entry.publisher = publisher
	t.storeWatchersLocked(entry, incarnation.value, true)
	return nil
}

// Watch appends dest to the alias and copies current (typed empty when unset).
// It never waits for SetAlias and never binds a holder.
func (t *Table) Watch(alias string, dest Watcher, empty any) {
	if t == nil || alias == "" || dest.Value == nil {
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
	bound := false
	if entry.incarnation != nil && !isNilValue(entry.incarnation.value) {
		current = entry.incarnation.value
		bound = true
	}
	t.storeOneLocked(entry, dest, current, bound)
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
		if watcher.Value != dest {
			kept = append(kept, watcher)
		}
	}
	entry.watchers = kept
}

// ClearAlias drops the alias when this publisher still holds it.
func (t *Table) ClearAlias(alias, publisher string) {
	if t == nil || alias == "" || publisher == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.aliases[alias]
	if entry == nil || entry.publisher != publisher {
		return
	}
	t.clearAliasLocked(alias, entry)
}

// ClearPublisher drops every alias this publisher still holds in family prefix
// (for example "alias:lapi:"). Watchers stay registered for a later SetAlias.
func (t *Table) ClearPublisher(publisher, prefix string) {
	if t == nil || publisher == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for alias, entry := range t.aliases {
		if entry.publisher != publisher {
			continue
		}
		if prefix != "" && !strings.HasPrefix(alias, prefix) {
			continue
		}
		t.clearAliasLocked(alias, entry)
	}
}

func (t *Table) unbindIncarnationLocked(incarnation *slot) {
	if t.aliases == nil || incarnation == nil {
		return
	}
	for alias, entry := range t.aliases {
		if entry.incarnation != incarnation {
			continue
		}
		t.clearAliasLocked(alias, entry)
	}
}

func (t *Table) clearAliasLocked(alias string, entry *aliasEntry) {
	entry.incarnation = nil
	entry.publisher = ""
	t.storeWatchersLocked(entry, entry.empty, false)
	_ = alias
}

func (t *Table) storeWatchersLocked(entry *aliasEntry, current any, bound bool) {
	for _, watcher := range entry.watchers {
		t.storeOneLocked(entry, watcher, current, bound)
	}
}

func (t *Table) storeOneLocked(entry *aliasEntry, watcher Watcher, current any, bound bool) {
	toStore := current
	if isNilValue(current) {
		if entry.empty == nil {
			if watcher.Notify != nil {
				watcher.Notify(current, false)
			}
			return
		}
		toStore = entry.empty
		bound = false
	}
	prev := watcher.Value.Load()
	if prev == nil || !sameValue(prev, toStore) {
		watcher.Value.Store(toStore)
	} else if bound {
		return
	}
	if watcher.Notify != nil {
		watcher.Notify(toStore, bound)
	}
}

func aliasFamily(alias string) string {
	parts := strings.SplitN(alias, ":", 3)
	if len(parts) < 3 {
		return alias
	}
	return parts[0] + ":" + parts[1] + ":"
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
