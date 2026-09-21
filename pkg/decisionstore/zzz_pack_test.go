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
	word := packWord(decisionscope.BannedValue, originID, "ipv4")
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
	word := packWord(decisionscope.BannedValue, 0, "ipv4")
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

func TestPackFamilyCodes(t *testing.T) {
	ipv4 := packWord(decisionscope.BannedValue, 1, "ipv4")
	if packedFamily(ipv4) != "ipv4" || packedOriginID(ipv4) != 1 {
		t.Fatalf("ipv4 word family %q id %d", packedFamily(ipv4), packedOriginID(ipv4))
	}
	ipv6 := packWord(decisionscope.BannedValue, 1, "ipv6")
	if packedFamily(ipv6) != "ipv6" {
		t.Fatalf("ipv6 word family %q", packedFamily(ipv6))
	}
	header := packWord(decisionscope.BannedValue, 1, "")
	if packedFamily(header) != "" {
		t.Fatalf("header word family %q", packedFamily(header))
	}
	kind, _, originID := Unpack(ipv4)
	if kind != decisionscope.BannedValue || originID != 1 {
		t.Fatalf("unpack after family pack kind %q id %d", kind, originID)
	}
}
