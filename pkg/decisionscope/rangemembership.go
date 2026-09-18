package decisionscope

import (
	"net"
	"strings"

	"github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache"
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
		if cache.RemediationKind(remediation) == BannedValue {
			helper = ban
		}
		// Store the blob line on the endpoint so a later hit is O(prefix).
		if err := helper.AddCIDRRemediation(network, remediation); err != nil {
			continue
		}
	}
	return &RangeMembership{ban: ban, captcha: captcha}
}

// Remediation returns the stored string of the winning CIDR (ban over captcha), or empty.
func (membership *RangeMembership) Remediation(ipAddr net.IP) string {
	if membership == nil || ipAddr == nil {
		return ""
	}
	if membership.ban != nil {
		stored, found, err := membership.ban.ContainedRemediation(ipAddr)
		if err == nil && found {
			return stored
		}
	}
	if membership.captcha != nil {
		stored, found, err := membership.captcha.ContainedRemediation(ipAddr)
		if err == nil && found {
			return stored
		}
	}
	return ""
}
