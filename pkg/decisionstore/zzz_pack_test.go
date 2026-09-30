package decisionstore

import (
	"testing"
	"unsafe"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

func TestPackUnpackMemoryWord(t *testing.T) {
	table := intern.New()
	originID, ok := table.ID("crowdsec")
	if !ok {
		t.Fatal("intern crowdsec")
	}
	word := packWord(decisionscope.BannedValue, originID, "ipv4", 7)
	kind, origin, unpackedID := Unpack(word)
	if kind != decisionscope.BannedValue || origin != "" || unpackedID != originID {
		t.Fatalf("kind %q origin %q id %d", kind, origin, unpackedID)
	}
	if packedScenarioID(word) != 7 {
		t.Fatalf("scenario id %d", packedScenarioID(word))
	}
}

func TestPackOverflowUsesGenericOrigin(t *testing.T) {
	table := intern.New()
	table.FillUntilMaxForTest()
	_, ok := table.ID("overflow-origin")
	if ok {
		t.Fatal("overflow must fail")
	}
	word := packWord(decisionscope.BannedValue, 0, "ipv4", 0)
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
	ipv4 := packWord(decisionscope.BannedValue, 1, "ipv4", 0)
	if packedFamily(ipv4) != "ipv4" || packedOriginID(ipv4) != 1 {
		t.Fatalf("ipv4 word family %q id %d", packedFamily(ipv4), packedOriginID(ipv4))
	}
	ipv6 := packWord(decisionscope.BannedValue, 1, "ipv6", 0)
	if packedFamily(ipv6) != "ipv6" {
		t.Fatalf("ipv6 word family %q", packedFamily(ipv6))
	}
	header := packWord(decisionscope.BannedValue, 1, "", 0)
	if packedFamily(header) != "" {
		t.Fatalf("header word family %q", packedFamily(header))
	}
	kind, _, originID := Unpack(ipv4)
	if kind != decisionscope.BannedValue || originID != 1 {
		t.Fatalf("unpack after family pack kind %q id %d", kind, originID)
	}
}

func TestPackKindEnumUnpacksASCII(t *testing.T) {
	cases := []struct {
		kind string
		code uint32
	}{
		{decisionscope.BannedValue, packedKindBan},
		{decisionscope.CaptchaValue, packedKindCaptcha},
		{decisionscope.NoBannedValue, packedKindNoBan},
	}
	for _, packCase := range cases {
		word := packWord(packCase.kind, 1, "ipv4", 0)
		if word&packedKindMask != packCase.code {
			t.Fatalf("kind %q packed %d, want %d", packCase.kind, word&packedKindMask, packCase.code)
		}
		kind, _, _ := Unpack(word)
		if kind != packCase.kind {
			t.Fatalf("unpack kind %q, want %q", kind, packCase.kind)
		}
	}
}

func TestPackSaturatesOriginPast12Bits(t *testing.T) {
	word := packWord(decisionscope.BannedValue, packedOriginMask+1, "ipv4", 9)
	if packedOriginID(word) != 0 {
		t.Fatalf("saturated origin id %d", packedOriginID(word))
	}
	if packedFamily(word) != "ipv4" || packedScenarioID(word) != 9 {
		t.Fatalf("family %q scenario %d", packedFamily(word), packedScenarioID(word))
	}
	kind, _, _ := Unpack(word)
	if kind != decisionscope.BannedValue {
		t.Fatalf("kind %q", kind)
	}
}

func TestLiveSlotStaysEightBytes(t *testing.T) {
	if got := unsafe.Sizeof(LiveSlot{}); got != 8 {
		t.Fatalf("LiveSlot %d bytes, want 8", got)
	}
}
