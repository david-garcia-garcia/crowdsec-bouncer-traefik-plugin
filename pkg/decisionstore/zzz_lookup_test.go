package decisionstore

import (
	"net"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

func TestLookupHitsHeaderScope(t *testing.T) {
	hits := map[string]lookupHit{HeaderScopeKey(decisionscope.ScopeCountry, "FR"): {kind: decisionscope.BannedValue}}
	kind, _ := lookupHits(func(key string) lookupHit { return hits[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), map[string]string{decisionscope.ScopeCountry: "FR"}, nil)
	if kind != decisionscope.BannedValue {
		t.Fatalf("kind %q, want ban", kind)
	}
}

func TestLookupHitsMiss(t *testing.T) {
	kind, origin := lookupHits(func(string) lookupHit { return lookupHit{} }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if kind != "" || origin != "" {
		t.Fatalf("miss kind %q origin %q", kind, origin)
	}
}

func TestLookupHitsBanWinsAcrossScopes(t *testing.T) {
	hits := map[string]lookupHit{HeaderScopeKey(decisionscope.ScopeCountry, "FR"): {kind: decisionscope.BannedValue}}
	kind, _ := lookupHits(func(key string) lookupHit { return hits[key] }, "10.1.2.3", net.ParseIP("10.1.2.3"), map[string]string{decisionscope.ScopeCountry: "FR"}, MembershipFromIndex("10.0.0.0/8="+decisionscope.CaptchaValue))
	if kind != decisionscope.BannedValue {
		t.Fatalf("range captcha + country ban kind %q, want ban", kind)
	}
}

func TestLookupHitsMembershipNotSlot(t *testing.T) {
	banOnly := MembershipFromIndex("10.0.0.0/8=" + decisionscope.BannedValue)
	kind, _ := lookupHits(func(string) lookupHit { return lookupHit{} }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, banOnly)
	if kind != decisionscope.BannedValue {
		t.Fatalf("membership must win, kind %q", kind)
	}
	miss, origin := lookupHits(func(string) lookupHit { return lookupHit{} }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex(""))
	if miss != "" || origin != "" {
		t.Fatalf("empty membership must miss, got %q origin %q", miss, origin)
	}
}

func TestLookupHitsOriginSuffix(t *testing.T) {
	hit := unpackFromString(KindOriginString(decisionscope.BannedValue, "crowdsec"))
	hits := map[string]lookupHit{"203.0.113.10": hit}
	kind, origin := lookupHits(func(key string) lookupHit { return hits[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if kind != decisionscope.BannedValue || origin != "crowdsec" {
		t.Fatalf("kind %q origin %q", kind, origin)
	}
}

func TestLookupHitsRangeOnlyOrigin(t *testing.T) {
	stored := KindOriginString(decisionscope.BannedValue, "crowdsec")
	kind, origin := lookupHits(func(string) lookupHit { return lookupHit{} }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex("10.0.0.0/8="+stored))
	if kind != decisionscope.BannedValue || origin != "crowdsec" {
		t.Fatalf("kind %q origin %q", kind, origin)
	}
}

func TestLookupHitsRangeLetterOnlyStillBans(t *testing.T) {
	kind, origin := lookupHits(func(string) lookupHit { return lookupHit{} }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex("10.0.0.0/8="+decisionscope.BannedValue))
	if kind != decisionscope.BannedValue || origin != "" {
		t.Fatalf("letter-only kind %q origin %q", kind, origin)
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
