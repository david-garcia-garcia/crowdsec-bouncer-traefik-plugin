package decisionstore

import (
	"net"
	"testing"

	"github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/decisionscope"
)

func ipOf(addr string) net.IP {
	return net.ParseIP(addr)
}

func TestMembershipFromIndexBanWinsOverLongerCaptcha(t *testing.T) {
	index := "10.0.0.0/8=" + decisionscope.BannedValue + "\n10.1.0.0/16=" + decisionscope.CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != decisionscope.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexLongerBanWinsOverCaptcha(t *testing.T) {
	index := "10.0.0.0/8=" + decisionscope.CaptchaValue + "\n10.1.0.0/16=" + decisionscope.BannedValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != decisionscope.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexCaptchaOnly(t *testing.T) {
	index := "10.0.0.0/8=" + decisionscope.CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != decisionscope.CaptchaValue {
		t.Fatalf("got %q, want captcha", got)
	}
}

func TestMembershipFromIndexMiss(t *testing.T) {
	index := "10.0.0.0/8=" + decisionscope.BannedValue
	if got := MembershipFromIndex(index).Remediation(ipOf("203.0.113.10")); got != "" {
		t.Fatalf("outside range got %q", got)
	}
}

func TestMembershipFromIndexEmpty(t *testing.T) {
	if got := MembershipFromIndex("").Remediation(ipOf("10.1.2.3")); got != "" {
		t.Fatalf("empty index got %q", got)
	}
	if got := (*RangeMembership)(nil).Remediation(ipOf("10.1.2.3")); got != "" {
		t.Fatalf("nil membership got %q", got)
	}
}

func TestMembershipFromIndexSkipsInvalidCIDR(t *testing.T) {
	index := "not-a-cidr=" + decisionscope.BannedValue + "\n10.0.0.0/8=" + decisionscope.CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != decisionscope.CaptchaValue {
		t.Fatalf("invalid line should be skipped, got %q", got)
	}
}

func TestMembershipFromIndexIPv6(t *testing.T) {
	index := "2001:db8::/32=" + decisionscope.BannedValue
	if got := MembershipFromIndex(index).Remediation(ipOf("2001:db8::1")); got != decisionscope.BannedValue {
		t.Fatalf("ipv6 got %q, want ban", got)
	}
	if got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3")); got != "" {
		t.Fatalf("v4 against v6 range got %q", got)
	}
}

func TestMembershipFromIndexReturnsOriginSuffix(t *testing.T) {
	stored := kindOriginString(decisionscope.BannedValue, "crowdsec")
	got := MembershipFromIndex("10.0.0.0/8=" + stored).Remediation(ipOf("10.1.2.3"))
	if got != stored {
		t.Fatalf("got %q, want suffixed ban", got)
	}
}

func TestMembershipFromIndexLetterOnlyStillBans(t *testing.T) {
	got := MembershipFromIndex("10.0.0.0/8=" + decisionscope.BannedValue).Remediation(ipOf("10.1.2.3"))
	if got != decisionscope.BannedValue {
		t.Fatalf("letter-only got %q, want ban", got)
	}
}

func TestMembershipFromIndexOverlappingBansLongestPrefixOrigin(t *testing.T) {
	wide := kindOriginString(decisionscope.BannedValue, "crowdsec")
	narrow := kindOriginString(decisionscope.BannedValue, "cscli")
	index := "10.0.0.0/8=" + wide + "\n10.1.0.0/16=" + narrow
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != narrow {
		t.Fatalf("got %q, want longest-prefix suffix", got)
	}
}

func TestHunt_MembershipIPv4MappedCIDRDoesNotPanic(t *testing.T) {
	got := MembershipFromIndex("::ffff:0:0/96=" + decisionscope.BannedValue).Remediation(ipOf("192.0.2.1"))
	if got != decisionscope.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexMappedLastInsertWins(t *testing.T) {
	first := kindOriginString(decisionscope.BannedValue, "crowdsec")
	last := kindOriginString(decisionscope.BannedValue, "cscli")
	index := "0.0.0.0/0=" + first + "\n::ffff:0:0/96=" + last
	got := MembershipFromIndex(index).Remediation(ipOf("192.0.2.1"))
	if got != last {
		t.Fatalf("got %q, want last remapped insert", got)
	}
}
