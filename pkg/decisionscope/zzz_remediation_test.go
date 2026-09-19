package decisionscope

import "testing"

type testOriginIntern struct {
	memory bool
	names  map[string]uint16
	next   uint16
}

func (origins *testOriginIntern) PacksMemory() bool {
	return origins.memory
}

func (origins *testOriginIntern) Intern(name string) (uint16, bool) {
	if origins.names == nil {
		origins.names = map[string]uint16{}
	}
	if originID, ok := origins.names[name]; ok {
		return originID, true
	}
	origins.next++
	origins.names[name] = origins.next
	return origins.next, true
}

func TestRemediationKindStripsOrigin(t *testing.T) {
	stored := RemediationWithOrigin("t", "crowdsec")
	if RemediationKind(stored) != "t" {
		t.Fatalf("kind %q", RemediationKind(stored))
	}
	if RemediationOrigin(stored) != "crowdsec" {
		t.Fatalf("origin %q", RemediationOrigin(stored))
	}
	if RemediationKind("t") != "t" {
		t.Fatal("bare letter")
	}
	if RemediationOrigin("t") != "" {
		t.Fatal("bare origin")
	}
}

func TestPackUnpackMemoryWord(t *testing.T) {
	origins := &testOriginIntern{memory: true}
	word, ok := Pack(BannedValue, "crowdsec", origins).(uint32)
	if !ok {
		t.Fatal("want packed word")
	}
	kind, leftover, originID := Unpack(word)
	if kind != BannedValue || leftover != "" || originID != 1 {
		t.Fatalf("kind %q leftover %q id %d", kind, leftover, originID)
	}
}

func TestPackLeftoverWhenNotMemory(t *testing.T) {
	origins := &testOriginIntern{memory: false}
	got, ok := Pack(BannedValue, "crowdsec", origins).(string)
	if !ok || got != RemediationWithOrigin(BannedValue, "crowdsec") {
		t.Fatalf("got %#v", got)
	}
}

func TestUnpackLeftoverString(t *testing.T) {
	kind, origin, originID := Unpack(RemediationWithOrigin(BannedValue, "crowdsec"))
	if kind != BannedValue || origin != "crowdsec" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
}
