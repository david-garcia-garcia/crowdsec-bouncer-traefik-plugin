package decisionstore

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

type testOriginIntern struct {
	names map[string]uint16
	next  uint16
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

func TestPackUnpackMemoryWord(t *testing.T) {
	origins := &testOriginIntern{}
	word := Pack(decisionscope.BannedValue, "crowdsec", origins)
	kind, origin, originID := Unpack(word)
	if kind != decisionscope.BannedValue || origin != "" || originID != 1 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
}

func TestPackOverflowUsesGenericOrigin(t *testing.T) {
	table := intern.New()
	table.FillUntilMaxForTest()
	word := Pack(decisionscope.BannedValue, "overflow-origin", originIntern{table: table})
	kind, origin, originID := Unpack(word)
	if kind != decisionscope.BannedValue || origin != "" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
}

func TestUnpackKindOriginString(t *testing.T) {
	kind, origin, originID := Unpack(kindOriginString(decisionscope.BannedValue, "crowdsec"))
	if kind != decisionscope.BannedValue || origin != "crowdsec" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
}
