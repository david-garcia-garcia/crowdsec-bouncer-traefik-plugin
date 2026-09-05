package decisionscope

import (
	"net"
	"strings"

	cache "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/iplookup"
)

// RangeMembership is in-process ban-then-captcha CIDR membership rebuilt from range-index.
type RangeMembership struct {
	ban     *iplookup.Helper // CIDRs whose remediation is ban
	captcha *iplookup.Helper // CIDRs whose remediation is captcha
}

// MembershipFromIndex builds RangeMembership from a cidr=remediation blob. Invalid CIDR lines are skipped.
func MembershipFromIndex(index string) *RangeMembership {
	ban := iplookup.NewEmptyHelper()
	captcha := iplookup.NewEmptyHelper()
	if index == "" {
		return &RangeMembership{ban: ban, captcha: captcha}
	}
	for _, line := range strings.Split(index, "\n") {
		network, remediation := parseIndexLine(line)
		if network == "" || !IsActiveRemediation(remediation) {
			continue
		}
		helper := captcha
		if remediation == cache.BannedValue {
			helper = ban
		}
		if err := helper.AddCIDR(network); err != nil {
			continue
		}
	}
	return &RangeMembership{ban: ban, captcha: captcha}
}

// Remediation returns ban if the IP is in the ban set, else captcha if in the captcha set, else empty.
func (membership *RangeMembership) Remediation(remoteIP string) string {
	if membership == nil {
		return ""
	}
	parsed := net.ParseIP(remoteIP)
	if parsed == nil {
		return ""
	}
	if membership.ban != nil {
		found, _, err := membership.ban.IsContained(parsed)
		if err == nil && found {
			return cache.BannedValue
		}
	}
	if membership.captcha != nil {
		found, _, err := membership.captcha.IsContained(parsed)
		if err == nil && found {
			return cache.CaptchaValue
		}
	}
	return ""
}
