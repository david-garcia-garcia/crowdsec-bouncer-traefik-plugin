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
	index := "10.0.0.0/8=" + cache.BannedValue + "\n10.1.0.0/16=" + cache.CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexLongerBanWinsOverCaptcha(t *testing.T) {
	index := "10.0.0.0/8=" + cache.CaptchaValue + "\n10.1.0.0/16=" + cache.BannedValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != cache.BannedValue {
		t.Fatalf("got %q, want ban", got)
	}
}

func TestMembershipFromIndexCaptchaOnly(t *testing.T) {
	index := "10.0.0.0/8=" + cache.CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != cache.CaptchaValue {
		t.Fatalf("got %q, want captcha", got)
	}
}

func TestMembershipFromIndexMiss(t *testing.T) {
	index := "10.0.0.0/8=" + cache.BannedValue
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
	index := "not-a-cidr=" + cache.BannedValue + "\n10.0.0.0/8=" + cache.CaptchaValue
	got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3"))
	if got != cache.CaptchaValue {
		t.Fatalf("invalid line should be skipped, got %q", got)
	}
}

func TestMembershipFromIndexIPv6(t *testing.T) {
	index := "2001:db8::/32=" + cache.BannedValue
	if got := MembershipFromIndex(index).Remediation(ipOf("2001:db8::1")); got != cache.BannedValue {
		t.Fatalf("ipv6 got %q, want ban", got)
	}
	if got := MembershipFromIndex(index).Remediation(ipOf("10.1.2.3")); got != "" {
		t.Fatalf("v4 against v6 range got %q", got)
	}
}
