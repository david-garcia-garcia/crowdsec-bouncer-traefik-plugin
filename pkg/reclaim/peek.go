package reclaim

// View is a slot inspected without binding a constructor context.
// One struct: Yaegi v0.16 corrupts a 4-value (any, int, bool, bool) return.
type View struct {
	Key      string
	Value    any
	Holders  int
	Sleeping bool
	OK       bool
}

// Peek returns the stored value for key without adding a holder and without create.
// Holders is the live constructor-context count. Sleeping is true when the slot is asleep.
// OK is false when the key is absent or only a closer placeholder remains.
func (t *Table) Peek(key string) View {
	if t == nil {
		return View{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	incarnation, found := t.items[key]
	if !found || incarnation.state == slotGone {
		return View{}
	}
	if incarnation.value == nil && incarnation.holders == 0 && incarnation.state == slotBusy {
		return View{}
	}
	return View{
		Key:      key,
		Value:    incarnation.value,
		Holders:  incarnation.holders,
		Sleeping: incarnation.state == slotAsleep,
		OK:       true,
	}
}

// PeekLivePrefix returns one live slot whose key starts with prefix, without binding.
// Sleeping slots are ignored so a grace leftover cannot steal a new snapshot’s Open.
// Several live matches: the lexicographically smallest key. Empty prefix: miss.
// Key-only range: Yaegi v0.16 panics ranging map[string]*slot values.
func (t *Table) PeekLivePrefix(prefix string) View {
	if t == nil || prefix == "" {
		return View{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	chosenKey := ""
	for key := range t.items {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			continue
		}
		incarnation := t.items[key]
		if incarnation.state != slotAwake || incarnation.holders == 0 {
			continue
		}
		if chosenKey == "" || key < chosenKey {
			chosenKey = key
		}
	}
	if chosenKey == "" {
		return View{}
	}
	incarnation := t.items[chosenKey]
	return View{
		Key:      chosenKey,
		Value:    incarnation.value,
		Holders:  incarnation.holders,
		Sleeping: false,
		OK:       true,
	}
}
