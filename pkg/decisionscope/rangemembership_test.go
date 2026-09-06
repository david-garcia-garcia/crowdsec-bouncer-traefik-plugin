package decisionscope

import (
	"net"
	"testing"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
)

func ipOf(addr string) net.IP {
	return net.ParseIP(addr)
}

func TestMembershipFromIndexBanWinsOverLongerCaptcha(t *testing.T) {
	index := "10.0.0.0/8=" + BannedValue + "\n10.1.0.0/16=" + CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexLongerBanWinsOverCaptcha(t *testing.T) {
	index := "10.0.0.0/8=" + CaptchaValue + "\n10.1.0.0/16=" + BannedValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexCaptchaOnly(t *testing.T) {
	index := "10.0.0.0/8=" + CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != CaptchaValue {
		t.Fatalf("got %q, want captcha", got)
	}
}

func TestMembershipFromIndexMiss(t *testing.T) {
	index := "10.0.0.0/8=" + BannedValue
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
	index := "not-a-cidr=" + BannedValue + "\n10.0.0.0/8=" + CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != CaptchaValue {
		t.Fatalf("invalid line should be skipped, got %q", got)
	}
}

func TestMembershipFromIndexIPv6(t *testing.T) {
	index := "2001:db8::/32=" + BannedValue
	if got := MembershipFromIndex(index).Remediation(ipOf("2001:db8::1")); got != BannedValue {
		t.Fatalf("ipv6 got %q, want ban", got)
	}
	if got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3")); got != "" {
		t.Fatalf("v4 against v6 range got %q", got)
	}
}

func TestMembershipFromIndexReturnsOriginSuffix(t *testing.T) {
	stored := cache.RemediationWithOrigin(BannedValue, "crowdsec")
	got := MembershipFromIndex("10.0.0.0/8=" + stored).Remediation(ipOf("10.1.2.3"))
	if got != stored {
		t.Fatalf("got %q, want suffixed ban", got)
	}
}

func TestMembershipFromIndexLetterOnlyStillBans(t *testing.T) {
	got := MembershipFromIndex("10.0.0.0/8=" + BannedValue).Remediation(ipOf("10.1.2.3"))
	if got != BannedValue {
		t.Fatalf("letter-only got %q, want ban", got)
	}
}

func TestMembershipFromIndexOverlappingBansLongestPrefixOrigin(t *testing.T) {
	wide := cache.RemediationWithOrigin(BannedValue, "crowdsec")
	narrow := cache.RemediationWithOrigin(BannedValue, "cscli")
	index := "10.0.0.0/8=" + wide + "\n10.1.0.0/16=" + narrow
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != narrow {
		t.Fatalf("got %q, want longest-prefix suffix", got)
	}
}
