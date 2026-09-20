package decisionstore

import (
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

func TestPackUnpackMemoryWord(t *testing.T) {
	table := intern.New()
	originID, ok := table.ID("crowdsec")
	if !ok {
		t.Fatal("intern crowdsec")
	}
	word := packWord(decisionscope.BannedValue, originID)
	kind, origin, unpackedID := Unpack(word)
	if kind != decisionscope.BannedValue || origin != "" || unpackedID != originID {
		t.Fatalf("kind %q origin %q id %d", kind, origin, unpackedID)
	}
}

func TestPackOverflowUsesGenericOrigin(t *testing.T) {
	table := intern.New()
	table.FillUntilMaxForTest()
	_, ok := table.ID("overflow-origin")
	if ok {
		t.Fatal("overflow must fail")
	}
	word := packWord(decisionscope.BannedValue, 0)
	kind, origin, originID := Unpack(word)
	if kind != decisionscope.BannedValue || origin != "" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
}

func TestUnpackKindOriginString(t *testing.T) {
	kind, origin, originID := Unpack(KindOriginString(decisionscope.BannedValue, "crowdsec"))
	if kind != decisionscope.BannedValue || origin != "crowdsec" || originID != 0 {
		t.Fatalf("kind %q origin %q id %d", kind, origin, originID)
	}
}
