package decisionstore

import (
	"net"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/intern"
)

func TestLookupHitsHeaderScope(t *testing.T) {
	payloads := map[string]any{HeaderScopeKey(decisionscope.ScopeCountry, "FR"): decisionscope.BannedValue}
	got, _, _ := lookupHits(func(key string) any { return payloads[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), map[string]string{decisionscope.ScopeCountry: "FR"}, nil)
	if got != decisionscope.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestLookupHitsMiss(t *testing.T) {
	kind, origin, originID := lookupHits(func(string) any { return nil }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if kind != "" || origin != "" || originID != 0 {
		t.Fatalf("miss kind %q origin %q id %d", kind, origin, originID)
	}
}

func TestLookupHitsBanWinsAcrossScopes(t *testing.T) {
	payloads := map[string]any{HeaderScopeKey(decisionscope.ScopeCountry, "FR"): decisionscope.BannedValue}
	got, _, _ := lookupHits(func(key string) any { return payloads[key] }, "10.1.2.3", net.ParseIP("10.1.2.3"), map[string]string{decisionscope.ScopeCountry: "FR"}, MembershipFromIndex("10.0.0.0/8="+decisionscope.CaptchaValue))
	if got != decisionscope.BannedValue {
		t.Fatalf("range captcha + country ban got %q, want ban", got)
	}
}

func TestLookupHitsNilMembershipDoesNotReadBlob(t *testing.T) {
	got, _, _ := lookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, nil)
	if got != "" {
		t.Fatalf("nil membership must miss, got %q", got)
	}
}

func TestLookupHitsMembershipNotSlot(t *testing.T) {
	banOnly := MembershipFromIndex("10.0.0.0/8=" + decisionscope.BannedValue)
	got, _, _ := lookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, banOnly)
	if got != decisionscope.BannedValue {
		t.Fatalf("membership must win, got %q", got)
	}
	miss, origin, originID := lookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex(""))
	if miss != "" || origin != "" || originID != 0 {
		t.Fatalf("empty membership must miss, got %q origin %q id %d", miss, origin, originID)
	}
}

func TestLookupHitsPackedWord(t *testing.T) {
	table := intern.New()
	payload := Pack(decisionscope.BannedValue, "crowdsec", originIntern{table: table})
	originID, ok := table.ID("crowdsec")
	if !ok {
		t.Fatal("intern crowdsec")
	}
	payloads := map[string]any{"203.0.113.10": payload}
	got, origin, gotID := lookupHits(func(key string) any { return payloads[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if got != decisionscope.BannedValue || origin != "" || gotID != originID {
		t.Fatalf("got %q origin %q id %d, want id %d", got, origin, gotID, originID)
	}
}

func TestLookupHitsOriginSuffix(t *testing.T) {
	payloads := map[string]any{"203.0.113.10": kindOriginString(decisionscope.BannedValue, "crowdsec")}
	got, origin, _ := lookupHits(func(key string) any { return payloads[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if got != decisionscope.BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q", got, origin)
	}
}

func TestLookupHitsRangeOnlyOrigin(t *testing.T) {
	stored := kindOriginString(decisionscope.BannedValue, "crowdsec")
	got, origin, _ := lookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex("10.0.0.0/8="+stored))
	if got != decisionscope.BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q", got, origin)
	}
}

func TestLookupHitsRangeLetterOnlyStillBans(t *testing.T) {
	got, origin, _ := lookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex("10.0.0.0/8="+decisionscope.BannedValue))
	if got != decisionscope.BannedValue || origin != "" {
		t.Fatalf("letter-only got %q origin %q", got, origin)
	}
}

func TestLookupKeysIPThenHeaderSkipsEmpty(t *testing.T) {
	got := lookupKeys("203.0.113.10", map[string]string{
		decisionscope.ScopeCountry: "FR",
		decisionscope.ScopeAS:      "",
	})
	wantHeader := HeaderScopeKey(decisionscope.ScopeCountry, "FR")
	if len(got) != 2 || got[0] != "203.0.113.10" || got[1] != wantHeader {
		t.Fatalf("got %#v", got)
	}
}
