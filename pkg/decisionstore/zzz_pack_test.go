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
	kind, unpackedID, family, scenarioID := unpackWord(word)
	if kind != decisionscope.BannedValue || unpackedID != originID || family != "ipv4" || scenarioID != 7 {
		t.Fatalf("kind %q id %d family %q scenario %d", kind, unpackedID, family, scenarioID)
	}
	if PackedScenarioIDForTest(word) != 7 {
		t.Fatalf("scenario id %d", PackedScenarioIDForTest(word))
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
	kind, originID, family, scenarioID := unpackWord(word)
	if kind != decisionscope.BannedValue || originID != 0 || family != "ipv4" || scenarioID != 0 {
		t.Fatalf("kind %q id %d family %q scenario %d", kind, originID, family, scenarioID)
	}
}

func TestUnpackKindOriginString(t *testing.T) {
	hit := unpackFromString(KindOriginString(decisionscope.BannedValue, "crowdsec"))
	if hit.kind != decisionscope.BannedValue || hit.origin != "crowdsec" || hit.scenario != "" {
		t.Fatalf("hit %+v", hit)
	}
}

func TestPackFamilyCodes(t *testing.T) {
	ipv4 := packWord(decisionscope.BannedValue, 1, "ipv4", 0)
	_, originID, family, _ := unpackWord(ipv4)
	if family != "ipv4" || originID != 1 {
		t.Fatalf("ipv4 word family %q id %d", family, originID)
	}
	_, _, family, _ = unpackWord(packWord(decisionscope.BannedValue, 1, "ipv6", 0))
	if family != "ipv6" {
		t.Fatalf("ipv6 word family %q", family)
	}
	_, _, family, _ = unpackWord(packWord(decisionscope.BannedValue, 1, "", 0))
	if family != "" {
		t.Fatalf("header word family %q", family)
	}
	kind, _, _, _ := unpackWord(ipv4)
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
		kind, _, _, _ := unpackWord(word)
		if kind != packCase.kind {
			t.Fatalf("unpack kind %q, want %q", kind, packCase.kind)
		}
	}
}

func TestPackSaturatesOriginPast12Bits(t *testing.T) {
	word := packWord(decisionscope.BannedValue, packedOriginMask+1, "ipv4", 9)
	kind, originID, family, scenarioID := unpackWord(word)
	if originID != 0 {
		t.Fatalf("saturated origin id %d", originID)
	}
	if kind != decisionscope.BannedValue || family != "ipv4" || scenarioID != 9 {
		t.Fatalf("kind %q family %q scenario %d", kind, family, scenarioID)
	}
}

func TestLiveSlotStaysEightBytes(t *testing.T) {
	if got := unsafe.Sizeof(LiveSlot{}); got != 8 {
		t.Fatalf("LiveSlot %d bytes, want 8", got)
	}
}
