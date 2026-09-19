package decisionscope

import (
	"net"
	"testing"
)

func applyRange(index, cidr, remediation string) string {
	return ApplyRangeIndex(index, map[string]string{cidr: remediation}, nil)
}

func removeRange(index, cidr string) string {
	return ApplyRangeIndex(index, nil, []string{cidr})
}

func remediationFromIndex(index, remoteIP string) string {
	return MembershipFromIndex(index).Remediation(net.ParseIP(remoteIP))
}

func TestAddRangeBanWins(t *testing.T) {
	index := applyRange("", "10.0.0.0/8", CaptchaValue)
	index = applyRange(index, "10.1.0.0/16", BannedValue)
	if got := remediationFromIndex(index, "10.1.2.3"); got != BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := remediationFromIndex(index, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	index := applyRange("", "192.168.0.0/16", BannedValue)
	index = removeRange(index, "192.168.0.0/16")
	if got := remediationFromIndex(index, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}

func TestRemoveRangeSameNetworkDifferentSpelling(t *testing.T) {
	index := applyRange("", "10.1.2.0/8", BannedValue)
	index = removeRange(index, "10.0.0.0/8")
	if got := remediationFromIndex(index, "10.1.2.3"); got != "" {
		t.Fatalf("same-network remove still matched: %q", got)
	}
}

func TestRemoveRangeUnparseableIdenticalText(t *testing.T) {
	index := ApplyRangeIndex("", map[string]string{"not-a-cidr": BannedValue}, nil)
	index = removeRange(index, "not-a-cidr")
	if index != "" {
		t.Fatalf("identical unparseable remove left %q", index)
	}
}

func TestRemoveRangeParseableVsUnparseableKeepsLine(t *testing.T) {
	index := applyRange("", "10.0.0.0/8", BannedValue)
	index = removeRange(index, "not-a-cidr")
	if got := remediationFromIndex(index, "10.1.2.3"); got != BannedValue {
		t.Fatalf("unparseable remove dropped parseable line: %q", got)
	}
}

func TestAddRangeSameNetworkPersistsIncomingSpelling(t *testing.T) {
	index := applyRange("", "10.1.2.0/8", CaptchaValue)
	index = applyRange(index, "10.0.0.0/8", BannedValue)
	want := "10.0.0.0/8=" + BannedValue
	if index != want {
		t.Fatalf("same-network upsert persisted %q, want %q", index, want)
	}
}

func TestAddRangeUpdatesRemediation(t *testing.T) {
	index := applyRange("", "10.0.0.0/8", CaptchaValue)
	index = applyRange(index, "10.0.0.0/8", BannedValue)
	if got := remediationFromIndex(index, "10.1.2.3"); got != BannedValue {
		t.Fatalf("upsert got %q, want ban", got)
	}
}

func TestLookupHitsHeaderScope(t *testing.T) {
	payloads := map[string]any{HeaderScopeKey(ScopeCountry, "FR"): BannedValue}
	got, _, _ := LookupHits(func(key string) any { return payloads[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), map[string]string{ScopeCountry: "FR"}, nil)
	if got != BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestLookupHitsMiss(t *testing.T) {
	kind, origin, originID := LookupHits(func(string) any { return nil }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if kind != "" || origin != "" || originID != 0 {
		t.Fatalf("miss kind %q origin %q id %d", kind, origin, originID)
	}
}

func TestLookupHitsBanWinsAcrossScopes(t *testing.T) {
	payloads := map[string]any{HeaderScopeKey(ScopeCountry, "FR"): BannedValue}
	got, _, _ := LookupHits(func(key string) any { return payloads[key] }, "10.1.2.3", net.ParseIP("10.1.2.3"), map[string]string{ScopeCountry: "FR"}, MembershipFromIndex("10.0.0.0/8="+CaptchaValue))
	if got != BannedValue {
		t.Fatalf("range captcha + country ban got %q, want ban", got)
	}
}

func TestApplyRangeIndexOneWrite(t *testing.T) {
	index := ApplyRangeIndex("", map[string]string{
		"10.0.0.0/8":  CaptchaValue,
		"10.1.0.0/16": BannedValue,
	}, nil)
	if got := remediationFromIndex(index, "10.1.2.3"); got != BannedValue {
		t.Fatalf("batch upsert got %q, want ban", got)
	}
	index = ApplyRangeIndex(index, nil, []string{"10.1.0.0/16"})
	if got := remediationFromIndex(index, "10.1.2.3"); got != CaptchaValue {
		t.Fatalf("after removal got %q, want captcha from remaining /8", got)
	}
}

func TestLookupHitsNilMembershipDoesNotReadBlob(t *testing.T) {
	got, _, _ := LookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, nil)
	if got != "" {
		t.Fatalf("nil membership must miss, got %q", got)
	}
}

func TestLookupHitsMembershipNotSlot(t *testing.T) {
	banOnly := MembershipFromIndex("10.0.0.0/8=" + BannedValue)
	got, _, _ := LookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, banOnly)
	if got != BannedValue {
		t.Fatalf("membership must win, got %q", got)
	}
	miss, origin, originID := LookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex(""))
	if miss != "" || origin != "" || originID != 0 {
		t.Fatalf("empty membership must miss, got %q origin %q id %d", miss, origin, originID)
	}
}

func TestLookupHitsPackedWord(t *testing.T) {
	payloads := map[string]any{"203.0.113.10": packWord(BannedValue, 3)}
	got, origin, originID := LookupHits(func(key string) any { return payloads[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if got != BannedValue || origin != "" || originID != 3 {
		t.Fatalf("got %q origin %q id %d", got, origin, originID)
	}
}

func TestLookupHitsOriginSuffix(t *testing.T) {
	payloads := map[string]any{"203.0.113.10": RemediationWithOrigin(BannedValue, "crowdsec")}
	got, origin, _ := LookupHits(func(key string) any { return payloads[key] }, "203.0.113.10", net.ParseIP("203.0.113.10"), nil, nil)
	if got != BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q", got, origin)
	}
}

func TestApplyRangeIndexRoundTripOriginSuffix(t *testing.T) {
	stored := RemediationWithOrigin(BannedValue, "crowdsec")
	index := ApplyRangeIndex("", map[string]string{"10.0.0.0/8": stored}, nil)
	if index != "10.0.0.0/8="+stored {
		t.Fatalf("blob %q", index)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("10.1.2.3")); got != stored {
		t.Fatalf("round-trip got %q", got)
	}
}

func TestLookupHitsRangeOnlyOrigin(t *testing.T) {
	stored := RemediationWithOrigin(BannedValue, "crowdsec")
	got, origin, _ := LookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex("10.0.0.0/8="+stored))
	if got != BannedValue || origin != "crowdsec" {
		t.Fatalf("got %q origin %q", got, origin)
	}
}

func TestAddRangeBareIPIsHostPrefix(t *testing.T) {
	index := applyRange("", "192.0.2.1", BannedValue)
	if index != "192.0.2.1/32="+BannedValue {
		t.Fatalf("blob %q", index)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.1")); got != BannedValue {
		t.Fatalf("bare host got %q", got)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.2")); got != "" {
		t.Fatalf("neighbor got %q", got)
	}
	index = removeRange(index, "192.0.2.1")
	if got := remediationFromIndex(index, "192.0.2.1"); got != "" {
		t.Fatalf("removed bare host still matched: %q", got)
	}
	ipv6 := applyRange("", "2001:db8::1", BannedValue)
	if ipv6 != "2001:db8::1/128="+BannedValue {
		t.Fatalf("ipv6 blob %q", ipv6)
	}
	if got := MembershipFromIndex(ipv6).Remediation(net.ParseIP("2001:db8::1")); got != BannedValue {
		t.Fatalf("ipv6 bare host got %q", got)
	}
}

func TestMembershipFromIndexLeftoverBareIPDoesNotRemediate(t *testing.T) {
	index := "192.0.2.1=" + BannedValue
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.1")); got != "" {
		t.Fatalf("leftover bare line remediates: %q", got)
	}
}

func TestLookupHitsRangeLetterOnlyStillBans(t *testing.T) {
	got, origin, _ := LookupHits(func(string) any { return nil }, "10.1.2.3", net.ParseIP("10.1.2.3"), nil, MembershipFromIndex("10.0.0.0/8="+BannedValue))
	if got != BannedValue || origin != "" {
		t.Fatalf("letter-only got %q origin %q", got, origin)
	}
}
