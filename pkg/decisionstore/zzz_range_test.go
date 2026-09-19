package decisionstore

import (
	"net"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

func applyRange(index, cidr, kind string) string {
	return ApplyRangeIndex(index, map[string]Decision{cidr: {Kind: kind}}, nil)
}

func removeRange(index, cidr string) string {
	return ApplyRangeIndex(index, nil, []string{cidr})
}

func remediationFromIndex(index, remoteIP string) string {
	return MembershipFromIndex(index).Remediation(net.ParseIP(remoteIP))
}

func TestAddRangeBanWins(t *testing.T) {
	index := applyRange("", "10.0.0.0/8", decisionscope.CaptchaValue)
	index = applyRange(index, "10.1.0.0/16", decisionscope.BannedValue)
	if got := remediationFromIndex(index, "10.1.2.3"); got != decisionscope.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
	if got := remediationFromIndex(index, "11.0.0.1"); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestRemoveRange(t *testing.T) {
	index := applyRange("", "192.168.0.0/16", decisionscope.BannedValue)
	index = removeRange(index, "192.168.0.0/16")
	if got := remediationFromIndex(index, "192.168.1.1"); got != "" {
		t.Fatalf("removed range still matched: %q", got)
	}
}

func TestRemoveRangeSameNetworkDifferentSpelling(t *testing.T) {
	index := applyRange("", "10.1.2.0/8", decisionscope.BannedValue)
	index = removeRange(index, "10.0.0.0/8")
	if got := remediationFromIndex(index, "10.1.2.3"); got != "" {
		t.Fatalf("same-network remove still matched: %q", got)
	}
}

func TestRemoveRangeUnparseableIdenticalText(t *testing.T) {
	index := ApplyRangeIndex("", map[string]Decision{"not-a-cidr": {Kind: decisionscope.BannedValue}}, nil)
	index = removeRange(index, "not-a-cidr")
	if index != "" {
		t.Fatalf("identical unparseable remove left %q", index)
	}
}

func TestRemoveRangeParseableVsUnparseableKeepsLine(t *testing.T) {
	index := applyRange("", "10.0.0.0/8", decisionscope.BannedValue)
	index = removeRange(index, "not-a-cidr")
	if got := remediationFromIndex(index, "10.1.2.3"); got != decisionscope.BannedValue {
		t.Fatalf("unparseable remove dropped parseable line: %q", got)
	}
}

func TestAddRangeSameNetworkPersistsIncomingSpelling(t *testing.T) {
	index := applyRange("", "10.1.2.0/8", decisionscope.CaptchaValue)
	index = applyRange(index, "10.0.0.0/8", decisionscope.BannedValue)
	want := "10.0.0.0/8=" + decisionscope.BannedValue
	if index != want {
		t.Fatalf("same-network upsert persisted %q, want %q", index, want)
	}
}

func TestAddRangeUpdatesRemediation(t *testing.T) {
	index := applyRange("", "10.0.0.0/8", decisionscope.CaptchaValue)
	index = applyRange(index, "10.0.0.0/8", decisionscope.BannedValue)
	if got := remediationFromIndex(index, "10.1.2.3"); got != decisionscope.BannedValue {
		t.Fatalf("upsert got %q, want ban", got)
	}
}

func TestApplyRangeIndexOneWrite(t *testing.T) {
	index := ApplyRangeIndex("", map[string]Decision{
		"10.0.0.0/8":  {Kind: decisionscope.CaptchaValue},
		"10.1.0.0/16": {Kind: decisionscope.BannedValue},
	}, nil)
	if got := remediationFromIndex(index, "10.1.2.3"); got != decisionscope.BannedValue {
		t.Fatalf("batch upsert got %q, want ban", got)
	}
	index = ApplyRangeIndex(index, nil, []string{"10.1.0.0/16"})
	if got := remediationFromIndex(index, "10.1.2.3"); got != decisionscope.CaptchaValue {
		t.Fatalf("after removal got %q, want captcha from remaining /8", got)
	}
}

func TestApplyRangeIndexRoundTripOriginSuffix(t *testing.T) {
	stored := kindOriginString(decisionscope.BannedValue, "crowdsec")
	index := ApplyRangeIndex("", map[string]Decision{"10.0.0.0/8": {Kind: decisionscope.BannedValue, Origin: "crowdsec"}}, nil)
	if index != "10.0.0.0/8="+stored {
		t.Fatalf("blob %q", index)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("10.1.2.3")); got != stored {
		t.Fatalf("round-trip got %q", got)
	}
}

func TestAddRangeBareIPIsHostPrefix(t *testing.T) {
	index := applyRange("", "192.0.2.1", decisionscope.BannedValue)
	if index != "192.0.2.1/32="+decisionscope.BannedValue {
		t.Fatalf("blob %q", index)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.1")); got != decisionscope.BannedValue {
		t.Fatalf("bare host got %q", got)
	}
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.2")); got != "" {
		t.Fatalf("neighbor got %q", got)
	}
	index = removeRange(index, "192.0.2.1")
	if got := remediationFromIndex(index, "192.0.2.1"); got != "" {
		t.Fatalf("removed bare host still matched: %q", got)
	}
	ipv6 := applyRange("", "2001:db8::1", decisionscope.BannedValue)
	if ipv6 != "2001:db8::1/128="+decisionscope.BannedValue {
		t.Fatalf("ipv6 blob %q", ipv6)
	}
	if got := MembershipFromIndex(ipv6).Remediation(net.ParseIP("2001:db8::1")); got != decisionscope.BannedValue {
		t.Fatalf("ipv6 bare host got %q", got)
	}
}

func TestMembershipFromIndexLeftoverBareIPDoesNotRemediate(t *testing.T) {
	index := "192.0.2.1=" + decisionscope.BannedValue
	if got := MembershipFromIndex(index).Remediation(net.ParseIP("192.0.2.1")); got != "" {
		t.Fatalf("leftover bare line remediates: %q", got)
	}
}
